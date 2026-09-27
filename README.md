# Shadow : Helix Nebula (SHN)

> **Sovereign Cybersecurity Architecture & Platform**

This repository contains the authoritative architecture and implementation of Shadow : Helix Nebula (SHN).

---

## Phase 0: Foundational Architecture (FROZEN)

The complete foundational architecture is permanently frozen and codified under `docs/architecture/phase-0/`:
- `0.1-product-identity-and-purpose.md`
- `0.2-architectural-requirements.md`
- `0.3-domain-and-system-boundaries.md`
- `0.4-architectural-principles-and-invariants.md`
- `0.5-architecture-traceability-matrix.md`
- `0.6-high-level-system-architecture.md`
- `0.7-core-module-architecture.md`
- `0.8-plugin-architecture.md`
- `0.9-tool-integration-architecture.md`
- `0.10-data-architecture.md`
- `0.11-security-architecture-and-trust-boundaries.md`
- `0.12-ai-and-intelligence-architecture.md`
- `0.13-workflow-and-orchestration-architecture.md`
- `0.14-api-and-event-architecture.md`

---

## Phase 1: Stage 2 Implementation — Data Substrate & Migrations

Stage 2 establishes the PostgreSQL persistence layer, deterministic migration engine, connection pool lifecycle, and multi-tenant schema boundaries.

### Workspace Structure
- `packages/shared-kernel`: Core domain primitives, nominal branded IDs, network value objects, functional `Result<T, E>` monads, Canonical Event Envelope DTOs, and abstract configuration contracts.
- `packages/error-catalog`: RFC 7807 Problem Details serialization and canonical error taxonomy.
- `packages/data-access`: PostgreSQL persistence substrate, connection pooling, transactional boundaries, advisory-locked migrations, IAM/Workspace/Audit repositories, and database-level audit immutability triggers.

### Architectural Invariants Enforced
- **`MOD-INV-01`**: Strict public contract compliance via facade exports.
- **`MOD-INV-02`**: Zero circular imports; strict DAG module hierarchy.
- **`SEC-INV-14`**: Safe deserialization; strict schema validation; zero reflection.
- **`API-INV-06`**: Canonical Event Envelope schema enforcement (all 13 fields persisted).
- **`API-INV-14`**: Machine-readable RFC 7807 error format with zero stack trace leakage.
- **`DATA-INV-01`**: PostgreSQL canonical relational system of record.
- **`DATA-INV-05`**: Single module table ownership; zero cross-context SQL joins.
- **`DATA-INV-07` / `SEC-INV-11`**: Append-only audit ledger with engine-level mutation triggers rejecting `UPDATE`, `DELETE`, and `TRUNCATE`.
- **`DATA-INV-08`**: Multi-tenant workspace hermeticity enforced at query and constraint levels.

### Developer Commands
```bash
# Typecheck & build all packages
npm run build

# Run architectural dependency lint (enforces package-aware DAG rules)
npm run lint:deps

# Run pure unit tests (zero database required)
npm run test:unit

# Start isolated PostgreSQL test database (Docker Compose or local fallback)
npm run db:test:start

# Run PostgreSQL integration tests
npm run test:integration

# Run full project test suite (unit + integration)
npm test

# Stop isolated test database
npm run db:test:stop
```
