# Cloudflare Agent Boxes

An edge API for payment-gated, policy-triaged code execution. The Worker coordinates
payment, tenant checks, code triage, an isolated sandbox service, and asynchronous
execution telemetry; it does not itself run untrusted code.

## API

`POST /v1/execute` accepts JSON:

```json
{
  "code": "print('hello')",
  "language": "python",
  "tier": "nano",
  "timeoutMs": 5000
}
```

Supported languages are `python`, `javascript`, and `rust`; tiers are `nano`,
`standard`, and `heavy`. The code limit is 100,000 characters and the timeout is
capped at 10 seconds. Requests need a `Bearer` API key (at most 256 characters) or an
`X-402-Payment-Receipt`. The request body may be up to `100,000 * 6 + 4096` bytes
(worst-case JSON escaping of a maximal code payload). The optional `Idempotency-Key`
header must match `^[A-Za-z0-9_-]{1,128}$` (otherwise 400); the Worker forwards it to
the gateway as `<tenantId>:<key>` so keys cannot collide across tenants. Billing
always uses the requested tier (default `standard`); model triage is only a ceiling
check and never lowers the price. The response `triage.tier` is the billed tier.
`GET /v1/billing/challenge?tier=nano` obtains the cryptographic payment challenge
and pricing manifest for the selected tier.

## Cloudflare bindings

Configure these bindings for the Worker:

| Binding | Type | Contract |
| --- | --- | --- |
| `AUTH_KV` | KV namespace | `tenant:key:<sha256 hex of api key>` JSON containing `active`, `quotaRemaining`, and optionally `id`, `activeRuns`, and `maxConcurrentRuns`. |
| `PAYMENT_GATEWAY` | Service binding | `GET /challenge?tier=...` returns a payment challenge. `POST /authorize` reserves payment for the requested tier and returns `{ "approved": true, "authorizationId": "..." }` (optionally `tenantId`). `/settle` accepts the requested (billed) tier; `/void` releases an unused authorization. `/settle` and `/void` must be idempotent, and `/void` on an already-settled authorization must be a no-op (the Worker may void after a settle response is lost). `/authorize` receives `idempotencyKey` as `<tenantId>:<client key>`; the gateway must reject (non-2xx or `approved: false`) a replayed idempotency key whose authorization was already settled or voided, so code is never executed twice on one authorization. The service must atomically enforce balances, receipt replay protection, and authoritative quotas. Gateway calls time out after 5 seconds and are treated as unavailable. |
| `AI` | Workers AI | Supports `run('@cf/cloudflare/clef-flash', { prompt })` and returns triage JSON. Invalid, slow (15 second timeout), or unavailable triage fails closed. Code that fails the static policy is rejected without calling the model. |
| `CONTAINER_RUNNER` | Service binding | `POST /run` executes the payload and returns `stdout`, `stderr`, `exitCode`, `cpuTimeMs`, and `peakMemMb`. Limits use the requested tier's memory. The Worker aborts after `timeoutMs` + 5 seconds, rejects responses over about 2 MB, and returns only those five fields to the client. |
| `K2_TELEMETRY` | K2 stream binding | Accepts events with `send(event)`. |

The sandbox service must independently enforce the supplied memory, process,
egress, and timeout limits using OS/container controls. Worker-side limits are a
request contract, not a substitute for sandbox isolation. KV quota fields are
read-only snapshots; the payment gateway must enforce concurrent-run and balance
limits atomically. Never expose the payment or container service bindings publicly.

## Development

Requires Node.js with built-in `node:test`; no npm dependencies are needed.

```sh
npm test
```