# @shn/data-access

> **Shadow : Helix Nebula (SHN) — Control & Data Plane PostgreSQL Persistence Substrate**
> Phase 1, Stage 2 Implementation

This package implements the PostgreSQL relational persistence tier for Shadow : Helix Nebula (SHN), adhering strictly to Phase 0 architecture:
- **`DATA-INV-01`**: PostgreSQL is the single canonical relational system of record.
- **`DATA-INV-05`**: Single-module table ownership; zero cross-context SQL joins.
- **`DATA-INV-07` / `SEC-INV-11`**: Mechanical database-level immutability for the append-only audit ledger.
- **`DATA-INV-08`**: Multi-tenant workspace hermeticity enforced at query and constraint levels.
- **`MOD-INV-01`**: Strict public contract compliance via facade exports.
- **`MOD-INV-02`**: Strict module DAG hierarchy (no circular dependencies).

---

## 1. Package Architecture & Public Contracts

All public contracts are exported through the package facade `src/index.ts` / `./dist/index.js`:

```typescript
import {
  // Configuration
  type DatabaseConfig,
  type RedactedDatabaseConfig,
  parseDatabaseConfig,
  parseDatabaseUrl,
  redactDatabaseConfig,
  loadDatabaseConfigFromEnv,

  // Pooling & Health
  type DatabasePool,
  type DatabaseClient,
  type DatabaseHealth,
  createDatabasePool,
  checkDatabaseHealth,
  closeDatabasePool,

  // Transactions
  type IsolationLevel,
  type TransactionOptions,
  runInTransaction,

  // Deterministic Migrations
  type MigrationRecord,
  type MigrationReport,
  type MigrationStatus,
  loadMigrationFiles,
  getAppliedMigrations,
  getMigrationStatus,
  runMigrations,

  // Repositories
  OrganizationRepository,
  WorkspaceRepository,
  UserRepository,
  AuditEventRepository,
} from '@shn/data-access';
```

---

## 2. Configuration System & Precedence

Database configuration is loaded and validated fail-closed with RFC 7807 `ProblemDetails` error reporting.

### Precedence Hierarchy
1. **Connection URL**: `SHN_DATABASE_URL` or `DATABASE_URL` (`postgresql://user:pass@host:port/database?sslmode=...`)
2. **Discrete Overrides**: `SHN_DB_*` variables take precedence over URL components if both are specified.
3. **Driver Fallbacks**: `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`.

### Environment Variables
| Variable | Description | Default (Dev) | Default (Test) |
| :--- | :--- | :--- | :--- |
| `SHN_DATABASE_URL` | Full connection URI | - | - |
| `SHN_DB_HOST` | Database host | `127.0.0.1` | `127.0.0.1` |
| `SHN_DB_PORT` | Port number | `5432` | `54329` |
| `SHN_DB_NAME` | Database name | `shn_primary` | `shn_test` |
| `SHN_DB_USER` | Database role | `shn_app` | `postgres` |
| `SHN_DB_PASSWORD` | Password (never logged) | - | - |
| `SHN_DB_SSL` | Enable TLS (`true`/`false`) | `false` | `false` |
| `SHN_DB_MAX_CONNECTIONS` | Pool maximum size | `20` | `10` |
| `SHN_DB_MIN_CONNECTIONS` | Pool minimum idle | `2` | `1` |
| `SHN_DB_IDLE_TIMEOUT_MS` | Idle client timeout | `10000` | `5000` |
| `SHN_DB_CONNECTION_TIMEOUT_MS` | Connect timeout | `5000` | `5000` |

---

## 3. Transaction Isolation & Nested Savepoints

Transactions support explicit ACID isolation levels:
- `READ COMMITTED` (default operational isolation)
- `REPEATABLE READ` (consistent snapshot isolation)
- `SERIALIZABLE` (strict tenancy, scope, and financial updates)

### Nested Transaction Semantics
Passing an existing `DatabaseClient` into `runInTransaction()` automatically establishes an isolated PostgreSQL `SAVEPOINT`:
```typescript
await runInTransaction(pool, async client => {
  await client.query('INSERT INTO iam.organizations ...');

  // Nested operation with independent savepoint rollback safety
  try {
    await runInTransaction(client, async innerClient => {
      await innerClient.query('INSERT INTO ...');
      throw new Error('Inner failure'); // Triggers ROLLBACK TO SAVEPOINT
    });
  } catch (err) {
    // Outer transaction remains valid and uncorrupted
  }
});
```

---

## 4. Deterministic Migration Engine

Migrations are ordered lexicographically by a 3-digit prefix (`001_initial_schema.sql`).

- **Advisory Concurrency Locks**: Uses `pg_advisory_lock(829104820194821)` to serialize concurrent migrations across application instances.
- **Checksum Invariance**: Computes SHA-256 over normalized LF migration bytes. Any modification to a previously applied migration triggers an immediate, unrecoverable exception.
- **Atomic Execution**: Each migration runs within its own transaction.

---

## 5. Bounded-Context Schemas & Repositories

| Schema | Table | Module Context | Invariants Enforced |
| :--- | :--- | :--- | :--- |
| `iam` | `organizations` | `mod_auth_rbac` | Unique slug, UUIDv7 PK |
| `workspace` | `workspaces` | `mod_workspace` | Unique `(organization_id, slug)`, tenant boundary anchor (`DATA-INV-08`) |
| `iam` | `users` | `mod_auth_rbac` | Unique `(organization_id, email)`, FK restrict |
| `audit` | `events` | `mod_evidence_ledger` | 13 Canonical Envelope fields (`API-INV-06`), append-only (`SEC-INV-11`), mechanical triggers rejecting `UPDATE`, `DELETE`, `TRUNCATE` |

---

## 6. Testing Strategy

Tests are separated into two hermetic tiers:
1. **Pure Unit Tests** (`test/unit/`): Zero database connection required. Validates config parser, URL decoder, credential redaction, filename formats, duplicate version detection, and checksum determinism.
2. **PostgreSQL Integration Tests** (`test/integration/`): Executed against isolated PostgreSQL 17 test cluster on port `54329`. Validates advisory locks, ACID rollbacks, savepoints, tenancy isolation, audit immutability triggers, and SQL injection defense.
