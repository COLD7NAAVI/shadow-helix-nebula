/**
 * Shadow : Helix Nebula (SHN) — Auth, RBAC & Secrets Vault Contracts
 *
 * Authoritative Spec: Phase 0.3 (BC-IAM, BC-SEC), 0.7 (mod_auth_rbac, mod_secrets_vault),
 *                    0.10 (Section 9), 0.11 (Sections 3, 6), 0.14 (Section 19)
 */

import type {
  UserId,
  OrganizationId,
  WorkspaceId,
  SessionId,
  SecretId,
  SecurityContextToken,
  Result,
} from '@shn/shared-kernel';
import type { ProblemDetails } from '@shn/error-catalog';
import type {
  SessionRecord,
  SecretMetadataRecord,
} from '@shn/data-access';

export const PermissionBit = {
  SCOPE_READ: 1 << 0,             // 1
  SCOPE_ADMIN: 1 << 1,            // 2
  WORKFLOW_READ: 1 << 2,          // 4
  WORKFLOW_AUTHOR: 1 << 3,        // 8
  WORKFLOW_EXECUTE: 1 << 4,       // 16
  RECON_PASSIVE: 1 << 5,          // 32
  PROBING_ACTIVE: 1 << 6,         // 64
  SCAN_INVASIVE: 1 << 7,          // 128
  REPORT_DRAFT: 1 << 8,           // 256
  REPORT_SIGNOFF: 1 << 9,         // 512
  SECRETS_READ_METADATA: 1 << 10, // 1024
  SECRETS_READ_MATERIAL: 1 << 11, // 2048
  SECRETS_WRITE: 1 << 12,         // 4096
  SECRETS_ROTATE: 1 << 13,        // 8192
  SECRETS_REVOKE: 1 << 14,        // 16384
  AUDIT_READ: 1 << 15,            // 32768
  IAM_ADMIN: 1 << 16,             // 65536
} as const;

export type PermissionBitType = typeof PermissionBit[keyof typeof PermissionBit];

export const RoleName = {
  ORG_ADMIN: 'ORG_ADMIN',
  WORKSPACE_ADMIN: 'WORKSPACE_ADMIN',
  OPERATOR: 'OPERATOR',
  ANALYST: 'ANALYST',
  AUDITOR: 'AUDITOR',
  OBSERVER: 'OBSERVER',
} as const;

export type RoleNameType = typeof RoleName[keyof typeof RoleName];

export type UserStatus = 'ACTIVE' | 'DISABLED' | 'SUSPENDED' | 'REVOKED';

export interface ClientInfo {
  readonly ip_address?: string;
  readonly user_agent?: string;
}

export interface AuthSessionResult {
  readonly user_id: UserId;
  readonly organization_id: OrganizationId;
  readonly workspace_id: WorkspaceId | null;
  readonly session: SessionRecord;
  readonly bearer_token: string;
  readonly refresh_token: string;
  readonly security_context_token: SecurityContextToken;
  readonly roles: readonly string[];
  readonly permission_mask: number;
}

/**
 * Phase 0.7 Section 4.1.2: IAuthorizationService exported interface
 */
export interface IAuthorizationService {
  authenticateSession(
    organizationId: OrganizationId | string,
    email: string,
    password: string,
    workspaceId?: WorkspaceId | string,
    clientInfo?: ClientInfo
  ): Promise<Result<AuthSessionResult, ProblemDetails>>;

  refreshSession(
    refreshToken: string,
    clientInfo?: ClientInfo
  ): Promise<Result<AuthSessionResult, ProblemDetails>>;

  revokeToken(
    sessionId: SessionId | string,
    reason: string,
    operatorContext?: SecurityContextToken
  ): Promise<Result<void, ProblemDetails>>;

  evaluatePermission(
    token: SecurityContextToken,
    requiredPermissionBit: number,
    targetWorkspaceId?: WorkspaceId | string
  ): Result<boolean, ProblemDetails>;

  enforceTenantIsolation(
    token: SecurityContextToken,
    targetOrganizationId: OrganizationId | string,
    targetWorkspaceId?: WorkspaceId | string
  ): Result<void, ProblemDetails>;
}

/**
 * Phase 0.7 Section 4.1.3 & Phase 0.11 Section 6: Secrets Vault Contracts
 */
export interface SecretEnvelope {
  readonly secret_id: SecretId;
  readonly version: number;
  readonly ciphertext: Buffer;
  readonly encrypted_dek: Buffer;
  readonly nonce: Buffer;
  readonly auth_tag: Buffer;
  readonly kek_id: string;
  readonly algorithm: string;
}

export interface CreateSecretParams {
  readonly id?: SecretId | string;
  readonly organization_id: OrganizationId | string;
  readonly workspace_id: WorkspaceId | string;
  readonly name: string;
  readonly description?: string | null;
  readonly secret_type?: string;
  readonly tags?: Record<string, string>;
  readonly access_policy?: Record<string, unknown>;
  readonly expires_at?: Date | null;
  readonly plaintext: string | Buffer;
  readonly created_by: UserId | string;
}

export interface DecryptedSecret {
  readonly secret_id: SecretId;
  readonly version: number;
  readonly plaintext: Buffer;
  readonly secret_type: string;
  readonly zeroize: () => void;
}

export interface RotateSecretParams {
  readonly secret_id: SecretId | string;
  readonly workspace_id: WorkspaceId | string;
  readonly new_plaintext: string | Buffer;
  readonly rotated_by: UserId | string;
}

export interface RevokeSecretParams {
  readonly secret_id: SecretId | string;
  readonly workspace_id: WorkspaceId | string;
  readonly reason: string;
  readonly revoked_by?: UserId | string | null;
}

export interface KeyRotationSummary {
  readonly rotated_versions_count: number;
  readonly active_kek_id: string;
}

/**
 * Phase 0.7 Section 4.1.3: ISecretsVault exported interface
 */
export interface ISecretsVault {
  encryptSecret(
    plaintext: Buffer | string,
    organizationId: OrganizationId | string,
    kekId?: string
  ): Promise<Result<{ ciphertext: Buffer; encrypted_dek: Buffer; nonce: Buffer; auth_tag: Buffer; kek_id: string; algorithm: string }, ProblemDetails>>;

  decryptSecret(
    envelope: { ciphertext: Buffer; encrypted_dek: Buffer; nonce: Buffer; auth_tag: Buffer },
    organizationId: OrganizationId | string
  ): Promise<Result<Buffer, ProblemDetails>>;

  zeroizeMemory(buffer: Buffer | Uint8Array): void;

  createSecret(
    params: CreateSecretParams,
    securityContext?: SecurityContextToken
  ): Promise<Result<SecretMetadataRecord, ProblemDetails>>;

  getSecret(
    secretId: SecretId | string,
    workspaceId: WorkspaceId | string,
    securityContext?: SecurityContextToken
  ): Promise<Result<DecryptedSecret, ProblemDetails>>;

  getSecretMetadata(
    secretId: SecretId | string,
    workspaceId: WorkspaceId | string,
    securityContext?: SecurityContextToken
  ): Promise<Result<SecretMetadataRecord, ProblemDetails>>;

  rotateSecret(
    params: RotateSecretParams,
    securityContext?: SecurityContextToken
  ): Promise<Result<SecretMetadataRecord, ProblemDetails>>;

  revokeSecret(
    params: RevokeSecretParams,
    securityContext?: SecurityContextToken
  ): Promise<Result<void, ProblemDetails>>;

  rotateMasterKey(
    newMasterKey: Buffer
  ): Promise<Result<KeyRotationSummary, ProblemDetails>>;
}
