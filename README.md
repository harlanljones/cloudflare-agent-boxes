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
capped at 10 seconds. Requests need a `Bearer` API key or an
`X-402-Payment-Receipt`.
`GET /v1/billing/challenge` returns the HTTP 402 pricing manifest.

## Cloudflare bindings

Configure these bindings for the Worker:

| Binding | Type | Contract |
| --- | --- | --- |
| `AUTH_KV` | KV namespace | `tenant:<api-key>` JSON containing `active`, `quotaRemaining`, and optionally `id`, `activeRuns`, and `maxConcurrentRuns`. |
| `PAYMENT_GATEWAY` | Service binding | `POST /authorize` reserves payment for the requested tier and returns `{ "approved": true, "authorizationId": "..." }` (optionally `tenantId`). `/settle` accepts the final tier; `/void` releases an unused authorization. The service must atomically enforce balances, receipt replay protection, and authoritative quotas. |
| `AI` | Workers AI | Supports `run('@cf/cloudflare/clef-flash', { prompt })` and returns triage JSON. Invalid or unavailable triage fails closed. |
| `CONTAINER_RUNNER` | Service binding | `POST /run` executes the payload and returns `stdout`, `stderr`, `exitCode`, `cpuTimeMs`, and `peakMemMb`. |
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