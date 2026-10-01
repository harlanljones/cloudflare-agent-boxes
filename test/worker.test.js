import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';

const execution = {
  code: 'print("hello")',
  language: 'python',
  tier: 'standard',
};

function response(body, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function setup({ triage = { safe: true, tier: 'nano', threatScore: 0, reason: '' }, paymentStatus = 200 } = {}) {
  const calls = { payment: [], container: [], telemetry: [], ai: [] };
  const env = {
    AUTH_KV: {
      async get(key) {
        assert.equal(key, 'tenant:valid-key');
        return { id: 'tenant-1', active: true, quotaRemaining: 2, activeRuns: 0, maxConcurrentRuns: 1 };
      },
    },
    PAYMENT_GATEWAY: {
      async fetch(url, init) {
        const body = JSON.parse(init.body);
        calls.payment.push({ url, body });
        if (url.endsWith('/authorize')) {
          return paymentStatus === 200
            ? response({ approved: true, authorizationId: 'auth-1', tenantId: 'tenant-1' })
            : response({}, paymentStatus);
        }
        return response({ approved: true });
      },
    },
    AI: {
      async run(model, input) {
        calls.ai.push({ model, input });
        return triage;
      },
    },
    CONTAINER_RUNNER: {
      async fetch(url, init) {
        calls.container.push({ url, body: JSON.parse(init.body) });
        return response({ stdout: 'hello\n', stderr: '', exitCode: 0, cpuTimeMs: 2, peakMemMb: 12 });
      },
    },
    K2_TELEMETRY: {
      async send(event) {
        calls.telemetry.push(event);
      },
    },
  };
  const ctx = { waitUntil(promise) { this.pending.push(promise); }, pending: [] };
  return { env, ctx, calls };
}

function request(body = execution, headers = {}) {
  return new Request('https://worker.test/v1/execute', {
    method: 'POST',
    headers: { Authorization: ['Bearer', 'valid-key'].join(' '), 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

test('requires payment credentials before allocating resources', async () => {
  const { env, ctx, calls } = setup();
  const res = await worker.fetch(request(execution, { Authorization: '' }), env, ctx);

  assert.equal(res.status, 402);
  assert.equal(calls.payment.length, 0);
  assert.equal(calls.ai.length, 0);
  assert.equal(calls.container.length, 0);
});

test('rejects unauthorized tenants before payment or execution', async () => {
  const { env, ctx, calls } = setup();
  env.AUTH_KV.get = async () => ({ active: false, quotaRemaining: 10 });
  const res = await worker.fetch(request(), env, ctx);

  assert.equal(res.status, 403);
  assert.equal(calls.payment.length, 0);
  assert.equal(calls.container.length, 0);
});

test('executes only after payment and safe triage, with bounded sandbox policy', async () => {
  const { env, ctx, calls } = setup();
  const res = await worker.fetch(
    request({ ...execution, timeoutMs: 60_000 }),
    env,
    ctx,
  );

  assert.equal(res.status, 200);
  assert.equal((await res.json()).success, true);
  assert.equal(calls.payment[0].url, 'https://payment-gateway/authorize');
  assert.equal(calls.payment[1].url, 'https://payment-gateway/settle');
  assert.equal(calls.container[0].body.timeoutMs, 10_000);
  assert.deepEqual(calls.container[0].body.limits, { memoryMb: 128, maxPids: 32, egress: false });
  await Promise.all(ctx.pending);
  assert.equal(calls.telemetry[0].event, 'SANDBOX_EXECUTION');
  assert.equal(calls.telemetry[0].tenantId, 'tenant-1');
});

test('rejects unsafe code and releases the payment authorization without running it', async () => {
  const { env, ctx, calls } = setup({
    triage: { safe: false, tier: 'nano', threatScore: 0.99, reason: 'network escape' },
  });
  const res = await worker.fetch(request(), env, ctx);

  assert.equal(res.status, 400);
  assert.equal(calls.container.length, 0);
  assert.equal(calls.payment.at(-1).url, 'https://payment-gateway/void');
  await Promise.all(ctx.pending);
  assert.equal(calls.telemetry[0].event, 'SECURITY_VIOLATION');
});

test('fails closed on malformed triage and tier overages', async (t) => {
  await t.test('malformed model output', async () => {
    const { env, ctx, calls } = setup({ triage: { safe: true, tier: 'unknown', threatScore: 0 } });
    const res = await worker.fetch(request(), env, ctx);
    assert.equal(res.status, 503);
    assert.equal(calls.container.length, 0);
    assert.equal(calls.payment.at(-1).url, 'https://payment-gateway/void');
  });

  await t.test('classification exceeds paid tier', async () => {
    const { env, ctx, calls } = setup({
      triage: { safe: true, tier: 'heavy', threatScore: 0, reason: '' },
    });
    const res = await worker.fetch(request({ ...execution, tier: 'nano' }), env, ctx);
    assert.equal(res.status, 400);
    assert.equal(calls.container.length, 0);
    assert.equal(calls.payment.at(-1).url, 'https://payment-gateway/void');
  });
});

test('returns payment required without sandbox allocation when payment is denied', async () => {
  const { env, ctx, calls } = setup({ paymentStatus: 402 });
  const res = await worker.fetch(request(), env, ctx);

  assert.equal(res.status, 402);
  assert.equal(calls.ai.length, 0);
  assert.equal(calls.container.length, 0);
});
