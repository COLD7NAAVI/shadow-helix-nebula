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

## Phase 1: Stage 1 Implementation — Repository Workspace & Shared Kernel

Stage 1 establishes the foundational workspace and core type kernel without business logic, databases, or external runtime dependencies.

### Workspace Structure
- `packages/shared-kernel`: Core domain primitives, nominal branded IDs, network value objects, functional `Result<T, E>` monads, Canonical Event Envelope DTOs, and abstract configuration contracts.
- `packages/error-catalog`: RFC 7807 Problem Details serialization and canonical error taxonomy.

### Architectural Invariants Enforced
- **`MOD-INV-01`**: Strict public contract compliance via facade exports.
- **`MOD-INV-02`**: Zero circular imports; strict DAG module hierarchy.
- **`SEC-INV-14`**: Safe deserialization; strict schema validation; zero reflection.
- **`API-INV-06`**: Canonical Event Envelope schema enforcement.
- **`API-INV-14`**: Machine-readable RFC 7807 error format with zero stack trace leakage.
- **`INV-09`**: Infrastructure neutrality; zero external database or cloud dependencies.

### Developer Commands
```bash
# Typecheck all packages
npm run typecheck

# Run unit test suite
npm run test

# Run architectural dependency lint
npm run lint:deps
```
