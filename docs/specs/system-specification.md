# System Specification: Autonomous Agentic Code Sandbox

## 1. Purpose and scope

The platform exposes a payment-gated API for executing agent-submitted code in an
isolated sandbox. A Worker validates requests, coordinates payment and tenant
checks, performs edge policy triage, calls a separate sandbox service, and emits
execution telemetry.

The Worker does not execute untrusted code itself. Container isolation,
networking, durable telemetry, payment settlement, and analytical storage depend
on the configured services and their contracts. Product capabilities and latency
figures below are design goals, not guarantees made by the Worker.

## 2. Architecture

```text
 Agent / client
      │ POST /v1/execute
      ▼
 Worker ───────────────► Payment gateway
   │                       challenge / authorize / settle / void
   ├───────────────────► AUTH_KV
   │                       tenant status and quota snapshot
   ├───────────────────► Workers AI (Clef-flash)
   │                       safety triage and resource tier
   ├───────────────────► Sandbox service
   │                       isolated code execution
   └───────────────────► K2 telemetry stream
                             │
                             ▼
                      Basin pipeline / Iceberg
```

| Component | Responsibility | Target or contract |
| --- | --- | --- |
| Worker API | Validate requests and coordinate execution | Reject invalid requests before dispatch; do not execute code in the Worker |
| Payment gateway | Issue challenges, reserve payment, settle the final tier, and release unused authorization | Enforce balance, receipt replay protection, and authoritative quotas atomically |
| `AUTH_KV` | Store tenant profiles and quota snapshots | Lookup by `tenant:key:<sha256 hex of api key>`; snapshots do not replace authoritative gateway checks |
| Workers AI / Clef-flash | Classify safety and execution tier | Invalid or unavailable triage fails closed |
| Sandbox service | Run supported languages under isolation and resource limits | Enforce memory, process, egress, and timeout limits independently of Worker checks |
| K2 telemetry | Accept append-only security and execution events | Durable, ordered retention is a deployment objective, provided by the configured stream |
| Basin pipeline | Transform telemetry for analytics | Iceberg tables and SQL audits are downstream deployment capabilities |

Sub-2 ms KV reads, sub-15 ms triage, and sub-second sandbox startup are
performance goals only. They require measurement in the target deployment and
must not be represented as guaranteed service levels without supporting service
commitments.

## 3. API and execution lifecycle

### Execution request

`POST /v1/execute` accepts a JSON object:

```json
{
  "code": "print('hello')",
  "language": "python",
  "tier": "nano",
  "timeoutMs": 5000
}
```

The current Worker contract supports `python`, `javascript`, and `rust`; tiers
are `nano`, `standard`, and `heavy`. `code` must be a non-empty string of at most
100,000 characters (the body limit is `100,000 * 6 + 4096` bytes to allow for JSON escaping). `timeoutMs` defaults to 5,000 and is capped at 10,000 ms.
The requested tier defaults to `standard`. Requests require an API key (at most
256 characters), a payment receipt, or both. An optional `Idempotency-Key` header
must match `^[A-Za-z0-9_-]{1,128}$`; the Worker forwards it namespaced as
`<tenantId>:<key>`.

### Request flow

1. The Worker checks method, content type, body size, JSON shape, language, tier,
   and timeout before contacting execution services.
2. It checks the tenant in `AUTH_KV` when an API key is provided. A missing,
   inactive, exhausted, or over-concurrency tenant is rejected. KV values are
   snapshots; the gateway remains responsible for atomic balance and quota
   enforcement.
3. The Worker calls the payment gateway's `/authorize` endpoint with the tenant,
   optional receipt, requested tier limit, and idempotency key. An unapproved
   authorization does not proceed to triage or execution.
4. It checks language-specific policy rules first; a policy rejection voids the
   authorization and emits a security event without calling the model. Otherwise it
   calls Workers AI (15 second timeout, code passed as escaped untrusted data) for a
   safety decision and tier estimate. Unsafe triage, a tier above the
   paid limit, or invalid triage prevents sandbox dispatch and releases the
   authorization. Triage errors fail closed.
5. The Worker sends the code, language, requested tier, timeout, and resource
   limits to the sandbox service. The sandbox must independently enforce these
   limits; Worker-provided values alone do not provide isolation.
6. If the sandbox request or response fails validation, the Worker releases the
   authorization. On a valid execution result, it settles payment for the
   requested tier. The classified tier is only a ceiling check and never lowers
   the billed tier. Payment gateway calls time out after 5 seconds and the
   sandbox call after `timeoutMs` + 5 seconds; timeouts void the authorization.
7. The Worker returns the result and emits execution telemetry asynchronously.
   Security rejections also emit a security event. Telemetry delivery is
   best-effort from the Worker and depends on the configured K2 binding.

The standard prices are $0.001 per nano run, $0.003 per standard run, and $0.010
per heavy run. `/v1/billing/challenge?tier=<tier>` obtains a challenge and pricing
manifest from the payment gateway. Payment authorization and settlement are
separate operations: authorization reserves funds before triage; settlement
occurs after a valid sandbox result.

### Responses

Successful sandbox responses include `success`, `result` (`stdout`, `stderr`,
`exitCode`, `cpuTimeMs`, and `peakMemMb`; any other sandbox fields are dropped),
the billed (requested) tier, and total duration. Sandbox responses over about 2 MB
are rejected before parsing.
Input errors use 400, unsupported media types 415, oversized payloads 413,
missing payment 402, invalid or exhausted tenant credentials 403, unavailable
dependencies 5xx, and policy or insufficient-tier rejections 400.

## 4. Binding contracts and sandbox controls

Configure the following Worker bindings:

| Binding | Type | Required behavior |
| --- | --- | --- |
| `AUTH_KV` | KV namespace | `tenant:key:<sha256 hex of api key>` JSON with `active`, numeric `quotaRemaining`, and optionally `id`, `activeRuns`, and `maxConcurrentRuns` |
| `PAYMENT_GATEWAY` | Service binding | `GET /challenge?tier=...`; `POST /authorize`, `/settle`, and `/void` using the request/response contract described in the repository README; `/settle` and `/void` are idempotent, `/void` after settlement is a no-op, and a replayed idempotency key for a settled or voided authorization is rejected |
| `AI` | Workers AI | Supports `run('@cf/cloudflare/clef-flash', { prompt })`; returns triage JSON |
| `CONTAINER_RUNNER` | Service binding | `POST /run`; returns execution output and resource measurements |
| `K2_TELEMETRY` | K2 stream binding | Accepts event objects with `send(event)` |

The Worker currently sends resource limits of 128 MB (nano), 512 MB (standard),
or 2,048 MB (heavy), a maximum of 32 processes, disabled egress, and the bounded
timeout. The sandbox service must enforce these using OS/container controls,
including a hard wall-clock termination. The sandbox should use ephemeral
filesystems and deny unrestricted outbound networking; any permitted egress
must be explicitly allowlisted. Never expose payment or sandbox service bindings
publicly.

Static and model-based triage are defense-in-depth signals, not proof that code
is safe. Sandbox isolation and least privilege remain mandatory for every run.

## 5. Telemetry and analytics

The Worker emits `SANDBOX_EXECUTION` events containing the tenant identifier,
language, tier, duration, CPU time, peak memory, exit code, billed amount, and
timestamp. It emits `SECURITY_VIOLATION` events for policy/triage rejections.
API keys and submitted source code must not be included in telemetry. The
downstream stream and lakehouse should restrict access and retention according
to the platform's data policy.

An example Iceberg table for downstream execution records is:

```sql
CREATE TABLE basin_catalog.prod.sandbox_executions (
    execution_id STRING,
    tenant_id STRING,
    language STRING,
    tier STRING,
    exit_code INT,
    cpu_time_ms DOUBLE,
    peak_mem_mb DOUBLE,
    billed_usd DECIMAL(8, 4),
    execution_duration_ms INT,
    created_at TIMESTAMP
)
USING iceberg
PARTITIONED BY (days(created_at), tier);
```

The ingestion pipeline must supply a stable `execution_id` and map Worker event
fields to the table schema. The table is a proposed downstream schema, not a
table created or managed by the Worker.

Example seven-day tier and margin audit:

```sql
SELECT
    tier,
    COUNT(*) AS total_runs,
    AVG(cpu_time_ms) AS avg_cpu_time,
    MAX(peak_mem_mb) AS max_memory_mb,
    SUM(billed_usd) AS total_revenue_usd,
    SUM(billed_usd) - (SUM(cpu_time_ms) / 1000.0 * 0.000015)
      AS estimated_gross_margin_usd
FROM basin_catalog.prod.sandbox_executions
WHERE created_at >= CURRENT_DATE - INTERVAL '7' DAY
GROUP BY tier;
```

The compute cost in this query is an illustrative estimate and should be
replaced with reconciled provider costs before financial reporting.

## 6. Failure modes and mitigations

| Failure vector | Detection | Mitigation |
| --- | --- | --- |
| Network scanning or egress | Sandbox network policy and execution telemetry | Deny outbound connections by default; allowlist only explicitly required destinations |
| Process or memory exhaustion | OS/container resource controls | Apply tier memory caps, `pids.max = 32`, CPU constraints, and hard timeout termination |
| Triage outage or malformed output | AI binding errors and schema validation | Fail closed, release payment authorization, and record operational errors without submitting code to the sandbox |
| Unsafe code missed by triage | Defense-in-depth monitoring and security-event analysis | Keep sandbox isolation mandatory; analyze incidents and update policy rules |
| Payment replay or concurrency race | Payment gateway authorization records | Enforce idempotency, receipt replay protection, balances, and quotas atomically in the gateway |
| Sandbox failure after authorization | Sandbox status and response validation | Do not settle invalid/failed responses; void authorization and return an error |
| Telemetry delivery failure | Stream health and downstream completeness checks | Monitor delivery and retention; treat Worker-side asynchronous telemetry as best effort |
| Insufficient funds for classified tier | Compare classified tier with authorized tier limit | Reject before sandbox dispatch and request authorization for a sufficient tier |

## 7. Operational requirements

- Keep payment authorization, settlement, and void behavior idempotent and
  recoverable; define authorization expiry and reconciliation procedures.
- Monitor dependency availability, triage latency, sandbox startup/runtime,
  payment outcomes, telemetry delivery, and quota rejections.
- Test the sandbox's isolation and resource controls independently of Worker
  tests, including attempted egress, process exhaustion, timeout, and filesystem
  access.
- Reconcile billed amounts against recorded execution measurements and actual
  provider costs before using analytics for financial decisions.
