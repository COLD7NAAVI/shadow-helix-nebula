# Shadow : Helix Nebula (SHN)

> **Sovereign Cybersecurity Architecture & Platform**

Shadow : Helix Nebula (SHN) is an enterprise-grade sovereign cybersecurity architecture and platform. It delivers zero-trust workspace tenancy, cryptographic scope boundary containment, protocol-isolated sandboxed worker execution, asset inventory normalization, vulnerability finding lifecycle tracking, Server-Sent Events (SSE) telemetry streaming, OpenAPI 3.1 contracts, and an integrated Web Console UI.

---

## 1. Modular Package Architecture

SHN is organized as a strict Directed Acyclic Graph (DAG) monorepo adhering strictly to `MOD-INV-01` and `MOD-INV-02`:

| Package | Role & Responsibility | Trust Boundary |
| :--- | :--- | :--- |
| **`@shn/shared-kernel`** | Branded UUIDv7 nominal IDs, network primitives (CIDR, IPv4/v6, FQDN, Port), Result/Option monads, Canonical Event Envelope. | Cross-cutting Core |
| **`@shn/error-catalog`** | RFC 7807 Problem Details taxonomy with zero stack-trace or secret leakage (`API-INV-14`). | Cross-cutting Core |
| **`@shn/telemetry`** | W3C distributed tracing (`traceparent`), structured JSON logging with secret redaction, and bounded-cardinality Prometheus metrics. | Observability Substrate |
| **`@shn/data-access`** | PostgreSQL 17 pooled persistence, transactional outbox atomicity, immutable append-only audit triggers, and advisory-locked migrations. | Persistence Substrate |
| **`@shn/event-bus`** | High-throughput asynchronous publish-subscribe event routing with transactional outbox polling and deduplication. | Integration Substrate |
| **`@shn/auth-rbac`** | Identity, authentication, argon2/PBKDF2 credential hashing, HMAC-SHA256 SecurityContext token signing, and bitmask RBAC evaluation. | Control Plane (IAM) |
| **`@shn/scope-gatekeeper`**| Zero-Trust operational boundary containment: inclusions, exclusions, cloud-metadata/loopback permanent defense, and HMAC ScopeTokens. | Control Plane (Scope) |
| **`@shn/execution-supervisor`** | Sandboxed worker execution isolation, resource boundaries, wall-clock/startup timeouts, output limits, and cancellation escalation. | Control Plane (Execution) |
| **`@shn/capability-registry`** | Signed tool manifest catalog, platform compatibility checks, permission enforcement, and extensible tool adapters (PortScan, HttpProbe). | Control Plane (Tools) |
| **`@shn/asset-inventory`** | Canonicalized target asset registry, vulnerability finding lifecycle states (`DRAFT` → `CONFIRMED` → `REMEDIATED`), and forensic evidence SHA-256 hashes. | Business Context (Assets) |
| **`@shn/ingress-gateway`** | Level 2/3 REST router, RFC 7807 problem filter, sliding-window rate limiter, OpenAPI 3.1 dynamic spec, real-time SSE stream hub, and CLI runner. | Perimeter B (Edge API) |
| **`@shn/web-console`** | Vanilla TypeScript SPA featuring glassmorphism design, real-time SSE event consumption, workspace switcher, and interactive security views. | Presentation Tier |

---

## 2. Quick Start & Developer Workflow

### 2.1 Prerequisites
- **Node.js**: `>= 24.0.0`
- **npm**: `>= 11.0.0`
- **PostgreSQL**: Version 17 (or use local test cluster script)

### 2.2 Local Development Commands

```bash
# 1. Install dependencies
npm ci

# 2. Check strict package architectural boundaries
npm run lint:deps

# 3. Typecheck and compile all TypeScript packages
npm run build

# 4. Start isolated PostgreSQL 17 test database (Port 54329)
npm run db:test:start

# 5. Run deterministic schema migrations
npm run db:migrate

# 6. Run pure unit tests (380+ tests)
npm run test:unit

# 7. Run database integration tests (150+ tests)
npm run test:integration

# 8. Run full test suite (unit + integration)
npm test

# 9. Run full end-to-end integration harness
npm run test:e2e

# 10. Start standalone server with bundled Web Console UI
npm start
```

Access the running platform:
- **Web Console UI**: `http://localhost:8080`
- **OpenAPI 3.1 Spec**: `http://localhost:8080/openapi.json`
- **Health Probes**: `http://localhost:8080/health/live` & `http://localhost:8080/health/ready`
- **Prometheus Metrics**: `http://localhost:8080/metrics`
- **Vite Web Console Dev Mode**: `npm run web:dev` (`http://localhost:3000`)

---

## 3. Production Deployment with Docker Compose

Deploy the production stack with PostgreSQL 17, persistent storage, non-root execution, and automated readiness probes:

```bash
# 1. Copy production environment configuration template
cp .env.production.example .env.production

# 2. Edit secrets in .env.production (or leave blank for secure automated key generation)
# 3. Launch with Docker Compose
docker compose --env-file .env.production up -d --build

# 4. Check cluster status
docker compose ps
```

Full operational procedures, backup/restore instructions, and disaster recovery workflows are documented in [`docs/deployment/0.1-production-deployment-guide.md`](file:///c:/DESK/Desktop/FOLDERS/Projects/shadow-helix-nebula/docs/deployment/0.1-production-deployment-guide.md).

---

## 4. Architectural Invariants Enforced

- **`MOD-INV-01`**: Strict public contract compliance via facade exports in `src/index.ts`.
- **`MOD-INV-02`**: Zero circular imports; strict DAG module hierarchy checked via `npm run lint:deps`.
- **`SEC-INV-01`**: Stateless HMAC-SHA256 signed authorization tokens with fail-closed cryptographic signature verification.
- **`SEC-INV-08`**: Cloud metadata IP (`169.254.169.254`) and loopback addresses permanently rejected across all scope evaluators.
- **`SEC-INV-14`**: Zero reflection, strict input schemas, and RFC 7807 Problem Details serialization.
- **`API-INV-06`**: Canonical Event Envelope schema enforcement (all 13 fields persisted).
- **`DATA-INV-01`**: PostgreSQL canonical relational system of record.
- **`DATA-INV-07` / `SEC-INV-11`**: Append-only audit ledger with engine-level database triggers rejecting `UPDATE`, `DELETE`, and `TRUNCATE`.
- **`DATA-INV-08` / `WKS-ISO-001`**: Multi-tenant workspace hermeticity enforced across database constraints, queries, and SSE event streams.
