# @shn/telemetry

Zero-external-dependency observability substrate for Shadow : Helix Nebula (SHN).

## Purpose
Enforces `INV-04`, `INV-06`, `INV-09`, `SEC-INV-07`, and `MOD-INV-01`:
- **Structured Machine-Readable Logging**: JSON log emission with monotonic timestamps, severity levels, correlation/causation tracking, and pluggable sinks (`ConsoleLogSink`, `BufferedLogSink`).
- **Security-Aware Recursive Redaction**: Redacts passwords, API keys, Bearer/Basic auth tokens, database connection URLs with embedded credentials, and RSA/Ed25519 private keys with depth limits and circular-reference breaking.
- **W3C Distributed Tracing**: Distributed context propagation adhering to W3C `traceparent` (32-character trace ID, 16-character span ID, 8-bit trace flags) via `AsyncLocalStorage`.
- **Prometheus-Compatible Metrics**: In-memory `Counter`, `Gauge`, and `Histogram` instruments with `CardinalityGuard` label bounding (capped at 50 unique label values) to prevent memory leaks and cardinality explosion.
- **Operational Health Diagnostics**: Independent liveness and readiness probe evaluation with fail-closed non-leaky error masking.
- **Zero Runtime Dependencies**: Native Node.js standard library only (`node:crypto`, `node:async_hooks`).
