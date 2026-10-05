/**
 * @shn/data-access — Public Facade
 *
 * PostgreSQL persistence substrate adhering to bounded-context single ownership,
 * strict multi-tenant workspace isolation, and mechanical audit immutability.
 * Enforces MOD-INV-01: Explicit exported contracts only.
 */

// Database Configuration
export {
  type DatabaseConfig,
  type RedactedDatabaseConfig,
  parseDatabaseConfig,
  parseDatabaseUrl,
  redactDatabaseConfig,
  loadDatabaseConfigFromEnv,
} from './config.js';

// Connection Pool & Health Substrate
export {
  type DatabasePool,
  type DatabaseClient,
  type QueryResult,
  type DatabaseHealth,
  createDatabasePool,
  checkDatabaseHealth,
  closeDatabasePool,
} from './pool.js';

// Transaction Boundaries
export {
  type TransactionOptions,
  type IsolationLevel,
  runInTransaction,
} from './transaction.js';

// Deterministic Migrations
export {
  type MigrationRecord,
  type MigrationReport,
  type MigrationFile,
  type MigrationStatus,
  calculateChecksum,
  loadMigrationFiles,
  getAppliedMigrations,
  getMigrationStatus,
  runMigrations,
  getDefaultMigrationsDir,
} from './migrator.js';

// Bounded-Context Repositories
export {
  OrganizationRepository,
  type OrganizationRecord,
  type CreateOrganizationInput,
} from './repositories/organization-repository.js';

export {
  WorkspaceRepository,
  type WorkspaceRecord,
  type CreateWorkspaceInput,
} from './repositories/workspace-repository.js';

export {
  UserRepository,
  type UserRecord,
  type CreateUserInput,
} from './repositories/user-repository.js';

export {
  AuditEventRepository,
} from './repositories/audit-repository.js';

export {
  OutboxRepository,
  type OutboxRecord,
  type OutboxStatus,
  type ClaimBatchOptions,
} from './repositories/outbox-repository.js';

export {
  DeduplicationRepository,
  type DeduplicationRecord,
  type DeduplicationStatus,
  type DeduplicationAcquireResult,
} from './repositories/deduplication-repository.js';

export {
  DeadLetterRepository,
  type DeadLetterRecord,
  type CreateDeadLetterInput,
  type ListDeadLettersOptions,
} from './repositories/dead-letter-repository.js';

export {
  CredentialRepository,
  type UserCredentialRecord,
} from './repositories/credential-repository.js';

export {
  SessionRepository,
  type SessionRecord,
  type CreateSessionInput,
} from './repositories/session-repository.js';

export {
  RoleRepository,
  type RoleRecord,
  type UserRoleRecord,
} from './repositories/role-repository.js';

export {
  PermissionRepository,
  type PermissionRecord,
} from './repositories/permission-repository.js';

export {
  SecretsMetadataRepository,
  type SecretMetadataRecord,
  type CreateSecretMetadataInput,
} from './repositories/secrets-metadata-repository.js';

export {
  SecretsVersionRepository,
  type SecretVersionRecord,
  type CreateSecretVersionInput,
} from './repositories/secrets-version-repository.js';
