/**
 * @shn/shared-kernel — Public Facade
 * Enforces MOD-INV-01: Explicit exported contracts only.
 */

// Algebraic Result Monad
export {
  Ok,
  Err,
  Some,
  None,
  ok,
  err,
  some,
  none,
  type Result,
  type Option,
} from './result/result.js';

// Nominal Domain Identifiers
export {
  type Brand,
  type OrganizationId,
  type WorkspaceId,
  type EngagementId,
  type AssetId,
  type FindingId,
  type TaskId,
  type RunId,
  type EventId,
  type CorrelationId,
  type CausationId,
  type TraceId,
  type UserId,
  type RoleId,
  type PermissionId,
  type SecretId,
  type SessionId,
  type SecretVersionId,
  type ScopeId,
  type ExecutionId,
  type WorkerId,
  isValidUUID,
  parseUUID,
  generateUUIDv4,
  generateUUIDv7,
  createWorkspaceId,
  createOrganizationId,
  createEngagementId,
  createFindingId,
  createTaskId,
  createRunId,
  createEventId,
  createCorrelationId,
  createCausationId,
  createUserId,
  createRoleId,
  createPermissionId,
  createSecretId,
  createSessionId,
  createSecretVersionId,
  createScopeId,
  createExecutionId,
  createWorkerId,
} from './primitives/identifiers.js';

// Network Target Primitives & Anti-SSRF
export {
  type IPv4Address,
  type IPv6Address,
  type CidrBlock,
  type Hostname,
  type Port,
  type PortRange,
  isProhibitedTarget,
  parseIPv4,
  parseIPv6,
  parseCidr,
  parsePort,
  parsePortRange,
  parseHostname,
} from './primitives/network.js';

// Timestamp Primitives
export {
  type IsoTimestamp,
  nowIso,
  parseIsoTimestamp,
} from './primitives/timestamps.js';

// Security Context Token Contract
export {
  type SecurityContextToken,
  isSecurityContextExpired,
} from './contracts/security-context.js';

// Scope Envelope Contract
export {
  type ScopeEnvelope,
  isScopeWindowActive,
} from './contracts/scope-envelope.js';

// Canonical Event Envelope Contract
export {
  type CanonicalEventEnvelope,
  type ProducerMetadata,
  type ScopeReference,
  type IntegrityBlock,
  type CreateEventEnvelopeOptions,
  createCanonicalEventEnvelope,
} from './contracts/event-envelope.js';

// Configuration Contracts
export {
  type DatabaseConfigContract,
  type RedisConfigContract,
  type SecurityConfigContract,
  type TelemetryConfigContract,
  type PlatformConfigContract,
} from './config/config-contract.js';
