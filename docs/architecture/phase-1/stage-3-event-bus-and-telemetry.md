# SHADOW : HELIX NEBULA (SHN) — PHASE 1 STAGE 3
## Event Bus & Telemetry Infrastructure Architecture & Verification Report

---

### 1. Executive Summary

Phase 1 Stage 3 establishes the sovereign event messaging substrate and observability framework for Shadow : Helix Nebula (SHN). Adhering strictly to frozen Phase 0 specifications (0.3, 0.7, 0.10, 0.11, 0.12, 0.13, 0.14), this stage delivers:

1. **`@shn/telemetry`**: A zero-external-dependency, production-grade observability engine incorporating structured JSON logging, deep recursive credential redaction, W3C distributed tracing, Prometheus-compatible metric instruments with cardinality protection, and decoupled liveness/readiness probes.
2. **`@shn/event-bus`**: A durable, decoupled event distribution substrate with transactional outbox persistence, non-blocking PostgreSQL `SKIP LOCKED` batch claiming, consumer check-and-set idempotency logging (`events.deduplication_log`), exponential backoff retries, poison-pill dead-letter quarantine (`events.dead_letter`), administrative replay with loop prevention, and per-partition FIFO sequencing.
3. **Database Migration `002_event_outbox_and_idempotency.sql`**: Forward-only, deterministic migration establishing schema `events` and its relational tables, foreign key constraints to `workspace.workspaces(id)` on delete restrict, composite indexes for high-throughput polling, and tenant isolation.

---

### 2. Package Responsibilities & Architecture Boundaries

```mermaid
graph TD
    subgraph "@shn/telemetry"
        Logger[Structured Logger]
        Redactor[Security-Aware Redactor]
        Tracer[W3C Distributed Tracer]
        Meter[Prometheus Meter + CardinalityGuard]
        Health[Health & Diagnostics Registry]
    end

    subgraph "@shn/event-bus"
        Validator[Event Envelope Validator]
        Registry[Event Registry & SemVer Compatibility]
        Publisher[Transactional & Outbox Publisher]
        Poller[SKIP LOCKED Outbox Poller]
        Dispatcher[Event Dispatcher & Retry Pipeline]
        Replay[Dead-Letter Replay Manager]
        PartitionQueue[Per-Partition FIFO Queue]
    end

    subgraph "@shn/data-access"
        OutboxRepo[OutboxRepository]
        DedupRepo[DeduplicationRepository]
        DLQRepo[DeadLetterRepository]
        MigrationRunner[Deterministic Migration Engine]
    end

    subgraph "PostgreSQL 17 Database"
        OutboxTable[(events.outbox)]
        DedupTable[(events.deduplication_log)]
        DLQTable[(events.dead_letter)]
    end

    Publisher --> OutboxRepo
    Poller --> OutboxRepo
    Dispatcher --> DedupRepo
    Dispatcher --> DLQRepo
    Replay --> DLQRepo
    Replay --> OutboxRepo
    OutboxRepo --> OutboxTable
    DedupRepo --> DedupTable
    DLQRepo --> DLQTable
```

#### Monorepo Dependency DAG:
- `@shn/shared-kernel` (Primal leaf — zero runtime dependencies)
- `@shn/error-catalog` (Depends only on `@shn/shared-kernel`)
- `@shn/data-access` (Depends on `@shn/shared-kernel`, `@shn/error-catalog`, and authorized driver `pg`)
- `@shn/telemetry` (Depends on `@shn/shared-kernel`, `@shn/error-catalog` — zero external runtime dependencies)
- `@shn/event-bus` (Depends on `@shn/shared-kernel`, `@shn/error-catalog`, `@shn/data-access`, `@shn/telemetry` — zero external broker dependencies)

Enforced mechanically via `scripts/check-deps.js` during `npm run lint:deps`.

---

### 3. Event Delivery & Idempotency Semantics

#### At-Least-Once Delivery Guarantee:
The transactional outbox pattern guarantees that every committed domain state change is accompanied by its corresponding event in `events.outbox` within the exact same database transaction. No network call or broker write occurs during the transaction.
- If the domain transaction rolls back, the outbox event rolls back atomically (zero phantom events).
- Once committed, background workers claim events via `SELECT ... FOR UPDATE SKIP LOCKED`.
- Because network partitions, consumer crashes, or lease expirations may cause an event to be redelivered, **at-least-once** delivery is guaranteed. Exactly-once transport delivery is physically impossible in distributed systems and is **explicitly disclaimed**.

#### Effectively-Once Consumer Idempotency (ADR-API-04):
To achieve effectively-once domain side effects, consumers utilize the durable `events.deduplication_log` table:
1. **Check-and-Set (`acquire`)**: Prior to executing domain logic, the consumer attempts an atomic insert into `events.deduplication_log` with `idempotency_key = '${consumerName}:${eventId}'` and `status = 'IN_FLIGHT'`.
2. **Conflict Resolution**:
   - If the key already exists with status `COMPLETED` and has not expired, the execution is bypassed (`ALREADY_COMPLETED`), preventing duplicate business logic execution.
   - If currently `IN_FLIGHT` and unexpired, concurrent executions defer (`IN_FLIGHT`).
3. **Completion Commit (`markCompleted`)**: Upon successful domain processing, status transitions to `COMPLETED` with configured TTL (default 24 hours).
4. **Transient Failure (`markFailed`)**: If the handler throws or returns an error, the `IN_FLIGHT` record is deleted to permit retry re-acquisition.

---

### 4. Outbox Lifecycle & Dead-Letter Quarantine

```
[ Domain Operation + Outbox Insert ] 
                 | (Same DB Transaction)
                 v
           [ PENDING ] <-------------------------\
                 |                               |
                 | Worker Claims (SKIP LOCKED)   | Lease Expiry Recovery
                 v                               | (recoverExpiredLeases)
          [ PROCESSING ] ------------------------/
                 |
        +--------+--------+
        |                 |
  (All Handlers     (Handler Failure)
    Succeeded)            |
        |                 v
        v         [ Attempt < Max? ]
  [ PUBLISHED ]     /            \
                  YES             NO
                  /                \
        [ Scheduled Retry ]    [ Terminally Failed ]
        (Exponential Backoff)           |
                                        v
                               [ Quarantined in ]
                            [ events.dead_letter ]
                                        |
                            (Admin Operator Replay)
                                        |
                                        v
                            [ Re-queued in Outbox ]
                            (Status: PENDING, att: 0)
```

#### Lease Expiry Recovery:
If a worker crashes mid-processing, its lease (`lease_expires_at`) lapses. The periodic lease recovery routine executes:
```sql
UPDATE events.outbox
SET status = 'PENDING',
    attempt_count = attempt_count + 1,
    claimed_at = NULL,
    claimed_by = NULL,
    lease_expires_at = NULL,
    updated_at = clock_timestamp()
WHERE status = 'PROCESSING'
  AND lease_expires_at <= clock_timestamp();
```
Incrementing `attempt_count` ensures that a poison pill that crashes worker processes cannot bypass retry limits.

#### Administrative Replay (`ReplayManager`):
- Replay requires an authorized operator principal (`authorizedOperator`).
- Increments `replay_count` in `events.dead_letter`.
- Caps replay attempts (default: 3) to prevent infinite poison-pill retry loops (`ERR_RATE_LIMIT_EXCEEDED`, HTTP 429).

---

### 5. Telemetry Architecture & Security Redaction

#### Zero-Dependency Observability:
Implemented using native Node.js APIs (`node:crypto`, `node:async_hooks`), `@shn/telemetry` introduces no external telemetry daemons, agents, or proprietary dependencies.

#### Security Redaction Pipeline (`Redactor`):
- Automatically executed before logs or error messages leave the process memory boundary.
- **Key-Based Redaction**: Case-insensitive matching for `password`, `token`, `secret`, `authorization`, `api_key`, `private_key`, `credentials`, `bearer`, etc.
- **String Regex Pattern Redaction**:
  - `Bearer [token]` -> `Bearer [REDACTED]`
  - `Basic [base64]` -> `Basic [REDACTED]`
  - `postgres://user:pass@host/db` -> `postgres://user:[REDACTED]@host/db`
  - `-----BEGIN [RSA/EC/PRIVATE] KEY-----` -> `[REDACTED PRIVATE KEY]`
- **Defensive Recursion Limits**: Max depth 8, max string length 2048 characters, max array items 50, and circular reference tracking via `WeakSet`.
- Non-mutating: Original input objects are never modified.

#### Metrics Cardinality Guard:
Prometheus labels can easily exhaust process memory if unconstrained (cardinality explosion). `@shn/telemetry`'s `CardinalityGuard` enforces a strict ceiling of 50 unique label sets per instrument. Once exceeded, high-cardinality values are folded into an `_overflow_` bucket.

---

### 6. Environment Configuration

All settings are strictly validated fail-closed with bounded constraints and sensible defaults:

| Environment Variable | Description | Default | Allowed Range |
|---|---|---|---|
| `SHN_LOG_LEVEL` | Minimum log severity level | `info` | `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `SHN_LOG_SINK` | Destination sink | `console` | `console`, `buffered` |
| `SHN_LOG_BUFFER_SIZE` | Max log buffer entries | `1000` | 10 – 100,000 |
| `SHN_EVENT_POLL_INTERVAL_MS` | Outbox polling frequency | `100` | 10ms – 60,000ms |
| `SHN_EVENT_BATCH_SIZE` | Outbox worker batch size | `25` | 1 – 500 |
| `SHN_EVENT_MAX_CONCURRENCY` | Max concurrent worker tasks | `10` | 1 – 100 |
| `SHN_EVENT_LEASE_DURATION_MS` | Claim lease duration | `30000` | 1,000ms – 3,600,000ms |
| `SHN_EVENT_MAX_ATTEMPTS` | Max retry attempts before DLQ | `5` | 1 – 20 |
| `SHN_EVENT_INITIAL_RETRY_DELAY_MS`| Initial retry delay | `1000` | 100ms – 60,000ms |
| `SHN_EVENT_MAX_RETRY_DELAY_MS` | Max exponential backoff ceiling | `60000` | 1,000ms – 3,600,000ms |
| `SHN_EVENT_RETRY_MULTIPLIER` | Exponential backoff multiplier | `2.0` | 1.1 – 10.0 |
| `SHN_EVENT_RETRY_JITTER` | Apply random jitter to delay | `true` | `true`, `false` |
| `SHN_EVENT_DEDUP_TTL_HOURS` | Deduplication log retention | `24` | 1 – 720 hours |
| `SHN_EVENT_SHUTDOWN_TIMEOUT_MS` | Poller graceful drain timeout | `5000` | 100ms – 60,000ms |

---

### 7. Verified Quality Gates & Test Results

Executed on Windows with native Node.js 24 and real PostgreSQL 17 test cluster:

| Quality Gate | Command | Result |
|---|---|---|
| Dependency Boundary Linting | `npm run lint:deps` | **PASSED** (0 architectural violations) |
| Strict TypeScript Compilation | `npm run build` | **PASSED** (0 compiler diagnostics across 5 packages) |
| Whitespace & Git Check | `git diff --check` | **PASSED** (0 trailing whitespace or format issues) |
| Pure Unit Test Suite | `npm run test:unit` | **PASSED** (90 tests across 18 test suites) |
| PostgreSQL Integration Suite | `npm run test:integration` | **PASSED** (49 tests across 11 test suites) |
| Complete Monorepo Test Suite | `npm test` | **PASSED** (**139 tests across 29 test suites, 0 failures**) |

#### Comprehensive Test Coverage Summary:
- **Shared Kernel & Domain Primitives**: 15 tests (Branded IDs, UUIDv7, IPv4, loopback/metadata blocks, Port bounds, FQDNs, Result/Option monads, Canonical Envelope).
- **Error Catalog & Problem Details**: 3 tests (RFC 7807 compliance, invalid params, HTTP status mapping).
- **Persistence & Migrations (Stage 2)**: 34 tests (Advisory locks, checksum tamper detection, relational constraints, workspace isolation, transaction rollbacks, savepoints, mechanical trigger immutability for `audit.events`).
- **Telemetry Infrastructure (Stage 3)**: 33 tests (Structured logger, recursive redaction, private key masking, connection string scrubbing, circular ref breaking, W3C traceparent parsing/formatting, AsyncLocalStorage context, Prometheus metrics, cardinality guards, liveness/readiness probes).
- **Event Bus & Outbox Infrastructure (Stage 3)**: 54 tests (Envelope validator, SemVer compatibility, in-process pub/sub, partition queue FIFO ordering, atomic transactional commit/rollback, non-blocking SKIP LOCKED concurrent claiming, abandoned lease recovery, check-and-set idempotency, retry backoff, DLQ quarantine, administrative replay with loop prevention, SQL injection defense, cross-workspace isolation).
