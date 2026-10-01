const MODEL = '@cf/cloudflare/clef-flash';
const LANGUAGES = new Set(['python', 'javascript', 'rust']);
const TIERS = new Set(['nano', 'standard', 'heavy']);
const MAX_CODE_LENGTH = 100_000;
const MAX_OUTPUT_LENGTH = 1_000_000;
const MAX_TIMEOUT_MS = 10_000;
const TIER_MEMORY_MB = { nano: 128, standard: 512, heavy: 2048 };
const PRICES_USD = { nano: 0.001, standard: 0.003, heavy: 0.01 };

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });
}

function paymentRequired() {
  return json(
    {
      error: 'Payment required',
      protocol: 'HTTP-402',
      pricing: { nano: '$0.001/run', standard: '$0.003/run', heavy: '$0.010/run' },
      challengeEndpoint: '/v1/billing/challenge',
    },
    402,
    { 'X-Accept-Payment': 'x402-v1, lightning, token-debit' },
  );
}

async function tenantKeyId(apiKey) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(apiKey));
  return `key:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function parseTriage(response) {
  let result = response;
  if (typeof result === 'string') {
    result = JSON.parse(result);
  } else if (result && typeof result.response === 'string') {
    result = JSON.parse(result.response);
  }

  if (
    !result ||
    typeof result.safe !== 'boolean' ||
    !TIERS.has(result.tier) ||
    !Number.isFinite(result.threatScore) ||
    result.threatScore < 0 ||
    result.threatScore > 1
  ) {
    throw new Error('Invalid triage result');
  }
  return {
    safe: result.safe,
    tier: result.tier,
    threatScore: result.threatScore,
    reason: typeof result.reason === 'string' ? result.reason.slice(0, 500) : '',
  };
}

function tierExceeds(tier, limit) {
  return ['nano', 'standard', 'heavy'].indexOf(tier) > ['nano', 'standard', 'heavy'].indexOf(limit);
}

function checkCodePolicy(code, language) {
  const rules = {
    python: [
      [/\b(?:socket|urllib|requests|httpx|aiohttp|ftplib|telnetlib)\b/, 'network access'],
      [/\b(?:subprocess|multiprocessing|os\.fork|os\.system|pty)\b/, 'process creation'],
      [/\b(?:os\.environ|os\.getenv|getpass)\b/, 'credential access'],
      [/\b(?:ctypes|cffi|prctl|mount|setuid|setgid)\b|\/(?:proc|sys)\b/, 'host isolation escape'],
      [/\b(?:eval|exec)\s*\(/, 'dynamic code execution'],
    ],
    javascript: [
      [/\b(?:fetch|WebSocket|XMLHttpRequest|(?:node:)?(?:http|https|net|dgram))\b/, 'network access'],
      [/\b(?:child_process|worker_threads|Bun\.spawn|Deno\.Command)\b/, 'process creation'],
      [/\b(?:process\.env|Deno\.env|getenv)\b/, 'credential access'],
      [/\b(?:node:)?(?:fs|vm)\b|\b(?:eval|Function)\b/, 'host isolation escape'],
    ],
    rust: [
      [/\b(?:std::net|TcpStream|UdpSocket|reqwest|hyper|ureq)\b/, 'network access'],
      [/\b(?:std::process|Command::new|fork)\b/, 'process creation'],
      [/\b(?:std::env|env::var|getenv)\b/, 'credential access'],
      [/\b(?:unsafe|libc|std::fs|OpenOptions)\b/, 'host isolation escape'],
    ],
  };
  const rule = rules[language].find(([pattern]) => pattern.test(code));
  return rule ? { safe: false, reason: `Disallowed ${rule[1]} API` } : { safe: true, reason: '' };
}

function emitTelemetry(env, ctx, event) {
  ctx.waitUntil(Promise.resolve().then(() => env.K2_TELEMETRY.send(event)).catch(() => {}));
}

async function settle(env, authorizationId, tier) {
  const response = await env.PAYMENT_GATEWAY.fetch('https://payment-gateway/settle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authorizationId, tier }),
  });
  if (!response.ok) return false;
  const result = await response.json();
  return result?.approved === true;
}

async function voidAuthorization(env, authorizationId) {
  try {
    await env.PAYMENT_GATEWAY.fetch('https://payment-gateway/void', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authorizationId }),
    });
  } catch {
    // The gateway owns authorization expiry and recovery.
  }
}

async function execute(request, env, ctx) {
  if (request.method !== 'POST') {
    return json({ error: 'Method Not Allowed' }, 405, { Allow: 'POST' });
  }

  if (!env.PAYMENT_GATEWAY || !env.AUTH_KV || !env.AI || !env.CONTAINER_RUNNER || !env.K2_TELEMETRY) {
    return json({ error: 'Execution service unavailable' }, 503);
  }

  if (!request.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    return json({ error: 'Content-Type must be application/json' }, 415);
  }

  const contentLength = Number(request.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_CODE_LENGTH + 4096) {
    return json({ error: 'Request body too large' }, 413);
  }

  let body;
  try {
    body = await request.text();
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }
  if (new TextEncoder().encode(body).byteLength > MAX_CODE_LENGTH + 4096) {
    return json({ error: 'Request body too large' }, 413);
  }

  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return json({ error: 'Invalid JSON request body' }, 400);
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return json({ error: 'Invalid request body' }, 400);
  }
  if (typeof payload.code !== 'string' || payload.code.length === 0) {
    return json({ error: 'Missing code payload' }, 400);
  }
  if (payload.code.length > MAX_CODE_LENGTH) {
    return json({ error: 'Code payload too large' }, 413);
  }
  if (!LANGUAGES.has(payload.language)) {
    return json({ error: 'Unsupported language' }, 400);
  }
  if (
    payload.timeoutMs !== undefined &&
    (!Number.isInteger(payload.timeoutMs) || payload.timeoutMs <= 0)
  ) {
    return json({ error: 'Invalid timeout' }, 400);
  }
  const timeoutMs =
    payload.timeoutMs === undefined ? 5000 : Math.min(payload.timeoutMs, MAX_TIMEOUT_MS);

  const requestedTier = payload.tier ?? 'standard';
  if (!TIERS.has(requestedTier)) {
    return json({ error: 'Unsupported resource tier' }, 400);
  }

  const authorization = request.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(\S+)$/i.exec(authorization);
  if (authorization && !match) {
    return json({ error: 'Invalid authorization header' }, 401);
  }
  const apiKey = match?.[1];
  const paymentReceipt = request.headers.get('X-402-Payment-Receipt');
  if (!apiKey && !paymentReceipt) return paymentRequired();

  let tenantId = 'anonymous';
  if (apiKey) {
    let tenant;
    try {
      tenant = await env.AUTH_KV.get(`tenant:${apiKey}`, { type: 'json' });
    } catch {
      return json({ error: 'Authorization service unavailable' }, 503);
    }
    if (
      !tenant ||
      tenant.active !== true ||
      !Number.isFinite(tenant.quotaRemaining) ||
      tenant.quotaRemaining <= 0 ||
      ((tenant.activeRuns !== undefined || tenant.maxConcurrentRuns !== undefined) &&
        (!Number.isFinite(tenant.activeRuns) ||
          !Number.isFinite(tenant.maxConcurrentRuns) ||
          tenant.activeRuns < 0 ||
          tenant.maxConcurrentRuns <= 0 ||
          tenant.activeRuns >= tenant.maxConcurrentRuns))
    ) {
      return json({ error: 'Tenant unauthorized or quota exhausted' }, 403);
    }
    tenantId =
      typeof tenant.id === 'string' && tenant.id ? tenant.id : await tenantKeyId(apiKey);
  }

  const idempotencyKey = request.headers.get('Idempotency-Key') || crypto.randomUUID();
  let authorizationId;
  try {
    const paymentResponse = await env.PAYMENT_GATEWAY.fetch('https://payment-gateway/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenantId,
        receipt: paymentReceipt,
        tierLimit: requestedTier,
        idempotencyKey,
      }),
    });
    if (paymentResponse.status === 402) return paymentRequired();
    if (!paymentResponse.ok) return json({ error: 'Payment service unavailable' }, 503);
    const payment = await paymentResponse.json();
    if (payment?.approved !== true || typeof payment.authorizationId !== 'string') {
      return paymentRequired();
    }
    authorizationId = payment.authorizationId;
    if (typeof payment.tenantId === 'string' && payment.tenantId) tenantId = payment.tenantId;
  } catch {
    return json({ error: 'Payment service unavailable' }, 503);
  }

  let triage;
  const policy = checkCodePolicy(payload.code, payload.language);
  try {
    const response = await env.AI.run(MODEL, {
      prompt: `Analyze this ${payload.language} code for execution safety and resource requirements. Detect network egress bypasses, fork bombs, credential leakage, and root escape patterns. Return strictly valid JSON with safe (boolean), tier (nano, standard, or heavy), threatScore (0 to 1), and reason (string). The caller paid for at most the ${requestedTier} tier.\n\`\`\`\n${payload.code}\n\`\`\``,
    });
    triage = parseTriage(response);
  } catch {
    await voidAuthorization(env, authorizationId);
    return json({ error: 'Security triage unavailable or invalid' }, 503);
  }

  if (!policy.safe || !triage.safe || tierExceeds(triage.tier, requestedTier)) {
    await voidAuthorization(env, authorizationId);
    const reason = !policy.safe ? policy.reason : triage.reason;
    emitTelemetry(env, ctx, {
      event: 'SECURITY_VIOLATION',
      tenantId,
      reason: !policy.safe
        ? policy.reason
        : triage.safe
          ? 'Requested tier is below the classified tier'
          : triage.reason,
      threatScore: triage.threatScore,
      timestamp: new Date().toISOString(),
    });
    return json(
      {
        error:
          !policy.safe || !triage.safe
            ? 'Execution rejected by edge security filter'
            : 'Requested tier is insufficient',
        details:
          !policy.safe || !triage.safe
            ? reason
            : `Request the ${triage.tier} tier`,
      },
      400,
    );
  }

  const runStart = Date.now();
  let execResult;
  try {
    const containerResponse = await env.CONTAINER_RUNNER.fetch('http://container-host/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: payload.code,
        language: payload.language,
        tier: triage.tier,
        timeoutMs,
        limits: {
          memoryMb: TIER_MEMORY_MB[triage.tier],
          maxPids: 32,
          egress: false,
        },
      }),
    });
    if (!containerResponse.ok) {
      await voidAuthorization(env, authorizationId);
      return json({ error: 'Sandbox execution failed' }, 502);
    }
    execResult = await containerResponse.json();
    if (
      typeof execResult.stdout !== 'string' ||
      typeof execResult.stderr !== 'string' ||
      !Number.isInteger(execResult.exitCode) ||
      !Number.isFinite(execResult.cpuTimeMs) ||
      !Number.isFinite(execResult.peakMemMb) ||
      execResult.stdout.length > MAX_OUTPUT_LENGTH ||
      execResult.stderr.length > MAX_OUTPUT_LENGTH
    ) {
      await voidAuthorization(env, authorizationId);
      return json({ error: 'Invalid sandbox response' }, 502);
    }
  } catch {
    await voidAuthorization(env, authorizationId);
    return json({ error: 'Sandbox execution unavailable' }, 502);
  }

  try {
    if (!(await settle(env, authorizationId, triage.tier))) {
      await voidAuthorization(env, authorizationId);
      return paymentRequired();
    }
  } catch {
    await voidAuthorization(env, authorizationId);
    return json({ error: 'Payment service unavailable' }, 503);
  }

  const durationMs = Date.now() - runStart;
  emitTelemetry(env, ctx, {
    event: 'SANDBOX_EXECUTION',
    tenantId,
    language: payload.language,
    tier: triage.tier,
    durationMs,
    cpuTimeMs: execResult.cpuTimeMs,
    peakMemMb: execResult.peakMemMb,
    exitCode: execResult.exitCode,
    billedUsd: PRICES_USD[triage.tier],
    timestamp: new Date().toISOString(),
  });

  return json({
    success: execResult.exitCode === 0,
    result: execResult,
    triage: { tier: triage.tier },
    durationMs,
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/v1/billing/challenge') {
      if (request.method !== 'GET') return json({ error: 'Method Not Allowed' }, 405, { Allow: 'GET' });
      if (!env.PAYMENT_GATEWAY) return json({ error: 'Payment service unavailable' }, 503);
      const tier = url.searchParams.get('tier') ?? 'standard';
      if (!TIERS.has(tier)) return json({ error: 'Unsupported resource tier' }, 400);
      try {
        const response = await env.PAYMENT_GATEWAY.fetch(
          `https://payment-gateway/challenge?tier=${tier}`,
        );
        if (!response.ok) return json({ error: 'Payment service unavailable' }, 503);
        const challenge = await response.json();
        return json({
          protocol: 'HTTP-402',
          pricing: { nano: '$0.001/run', standard: '$0.003/run', heavy: '$0.010/run' },
          challenge,
        });
      } catch {
        return json({ error: 'Payment service unavailable' }, 503);
      }
    }
    if (url.pathname !== '/v1/execute') return json({ error: 'Not Found' }, 404);
    return execute(request, env, ctx);
  },
};
