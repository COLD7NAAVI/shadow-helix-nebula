/**
 * @shn/auth-rbac — Public Facade
 *
 * Sovereign Identity Verification, Granular RBAC, Centralized Authorization,
 * Stateless Security Context Token Signing, and AES-256-GCM Secrets Envelope Encryption.
 * Enforces MOD-INV-01: Explicit exported public contracts only.
 */

// Contracts & Enums
export {
  PermissionBit,
  type PermissionBitType,
  RoleName,
  type RoleNameType,
  type UserStatus,
  type ClientInfo,
  type AuthSessionResult,
  type IAuthorizationService,
  type SecretEnvelope,
  type CreateSecretParams,
  type DecryptedSecret,
  type RotateSecretParams,
  type RevokeSecretParams,
  type KeyRotationSummary,
  type ISecretsVault,
} from './contracts.js';

// Problem Details Helper
export { makeAuthProblem } from './errors.js';

// Password Hashing & Timing Attack Defense
export {
  PasswordHasher,
  defaultPasswordHasher,
  type ScryptParams,
} from './password-hasher.js';

// Security Context Token Signing & Verification
export {
  SecurityContextSigner,
  DEFAULT_CONTEXT_TTL_SECONDS,
  type CreateSecurityContextTokenParams,
} from './crypto/security-context-signer.js';

// Secrets Envelope Encryption & Memory Zeroization
export {
  EnvelopeEncryptionEngine,
  zeroizeMemory,
  deriveOrgKek,
  GCM_NONCE_LENGTH,
  GCM_TAG_LENGTH,
  DEK_LENGTH,
  WRAPPED_DEK_LENGTH,
  type EncryptedEnvelopeResult,
} from './crypto/envelope-encryption.js';

// Session & Token Management
export {
  SessionManager,
  hashToken,
  generateToken,
  BEARER_PREFIX,
  REFRESH_PREFIX,
  DEFAULT_SESSION_TTL_HOURS,
  DEFAULT_REFRESH_TTL_DAYS,
} from './identity/session-manager.js';

// Authorization & Identity Service
export {
  AuthorizationService,
  type AuthorizationServiceOptions,
} from './identity/authorization-service.js';

// Secrets Vault Engine
export {
  SecretsVault,
  type SecretsVaultOptions,
} from './secrets/secrets-vault.js';
