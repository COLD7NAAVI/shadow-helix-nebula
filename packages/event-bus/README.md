# @shn/event-bus

Production-grade event substrate, transactional outbox, and durable dispatch engine for Shadow : Helix Nebula (SHN).

## Purpose
Enforces `INV-04`, `INV-06`, `INV-09`, `API-INV-06`, `API-INV-16`, `ADR-API-04`, and `MOD-INV-01`:
- **Transactional Outbox Persistence**: Atomically records domain events in `events.outbox` within the caller's database transaction, preventing phantom events and guaranteeing at-least-once delivery without false exactly-once claims.
- **Concurrent SKIP LOCKED Poller**: High-throughput non-blocking outbox polling with backpressure control, lease duration tracking, and graceful task draining.
- **Consumer Deduplication Log**: Atomic check-and-set idempotency via `events.deduplication_log` with `IN_FLIGHT` and `COMPLETED` state transitions, eliminating duplicate side effects under concurrent or redelivered events.
- **Exponential Backoff Retries & Dead-Letter Quarantine**: Bounded retry policy with jitter and exponential backoff; exhausted events transition to `events.dead_letter`.
- **Administrative Replay & Loop Prevention**: Controlled re-drive of dead letters with operator validation and replay-count thresholds preventing infinite poison-pill loops.
- **Per-Aggregate/Workspace Partition Ordering**: Guarantees serial execution per partition key while allowing full concurrency across independent partitions.
- **Canonical Envelope Validation**: Strict structural runtime validation of all 13 required canonical envelope fields fail-closed before persistence or dispatch.
