/**
 * Shadow : Helix Nebula (SHN) — Sovereign Secrets Vault Service
 *
 * Implements Phase 0.7 Section 4.1.3: ISecretsVault
 * Enforces SEC-CRY-001, INV-15, SEC-INV-06, and SEC-INV-12.
 */

import {
  type SecretId,
  type WorkspaceId,
  type OrganizationId,
  type SecurityContextToken,
  isValidUUID,
  generateUUIDv7,
  ok,
  err,
  type Result,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  type ProblemDetails,
} from '@shn/error-catalog';
import type {
  SecretsMetadataRepository,
  SecretsVersionRepository,
  SecretMetadataRecord,
  CreateSecretMetadataInput,
} from '@shn/data-access';
import type { IEventPublisher } from '@shn/event-bus';
import type { ILogger, ITracer } from '@shn/telemetry';

import {
  type ISecretsVault,
  type CreateSecretParams,
  type DecryptedSecret,
  type RotateSecretParams,
  type RevokeSecretParams,
  type KeyRotationSummary,
  type IAuthorizationService,
  PermissionBit,
} from '../contracts.js';
import {
  EnvelopeEncryptionEngine,
  zeroizeMemory,
} from '../crypto/envelope-encryption.js';
import { makeAuthProblem } from '../errors.js';

export interface SecretsVaultOptions {
  readonly metadataRepo: SecretsMetadataRepository;
  readonly versionRepo: SecretsVersionRepository;
  readonly masterKey: Buffer;
  readonly authService?: IAuthorizationService | undefined;
  readonly defaultKekId?: string | undefined;
  readonly eventPublisher?: IEventPublisher | undefined;
  readonly logger?: ILogger | undefined;
  readonly tracer?: ITracer | undefined;
}

export class SecretsVault implements ISecretsVault {
  private readonly metadataRepo: SecretsMetadataRepository;
  private readonly versionRepo: SecretsVersionRepository;
  private cryptoEngine: EnvelopeEncryptionEngine;
  private masterKey: Buffer;
  private readonly authService: IAuthorizationService | undefined;
  private readonly eventPublisher: IEventPublisher | undefined;
  private readonly logger: ILogger | undefined;
  private readonly tracer: ITracer | undefined;

  constructor(options: SecretsVaultOptions) {
    if (!Buffer.isBuffer(options.masterKey) || options.masterKey.length !== 32) {
      throw new Error('SecretsVault requires a 32-byte masterKey Buffer');
    }
    this.metadataRepo = options.metadataRepo;
    this.versionRepo = options.versionRepo;
    this.masterKey = Buffer.from(options.masterKey);
    this.cryptoEngine = new EnvelopeEncryptionEngine(this.masterKey, options.defaultKekId);
    this.authService = options.authService;
    this.eventPublisher = options.eventPublisher;
    this.logger = options.logger;
    this.tracer = options.tracer;
  }

  zeroizeMemory(buffer: Buffer | Uint8Array): void {
    zeroizeMemory(buffer);
  }

  async encryptSecret(
    plaintext: Buffer | string,
    organizationId: OrganizationId | string,
    kekId?: string
  ): Promise<
    Result<
      {
        ciphertext: Buffer;
        encrypted_dek: Buffer;
        nonce: Buffer;
        auth_tag: Buffer;
        kek_id: string;
        algorithm: string;
      },
      ProblemDetails
    >
  > {
    return this.cryptoEngine.encrypt(plaintext, String(organizationId), kekId);
  }

  async decryptSecret(
    envelope: {
      ciphertext: Buffer;
      encrypted_dek: Buffer;
      nonce: Buffer;
      auth_tag: Buffer;
    },
    organizationId: OrganizationId | string
  ): Promise<Result<Buffer, ProblemDetails>> {
    return this.cryptoEngine.decrypt(envelope, String(organizationId));
  }

  async createSecret(
    params: CreateSecretParams,
    securityContext?: SecurityContextToken
  ): Promise<Result<SecretMetadataRecord, ProblemDetails>> {
    // 1. Authorize if security context is provided
    if (securityContext && this.authService) {
      const authRes = this.authService.evaluatePermission(
        securityContext,
        PermissionBit.SECRETS_WRITE,
        params.workspace_id
      );
      if (!authRes.isOk) {
        return err(authRes.error);
      }
    }

    // 2. Validate input parameters fail-closed
    if (typeof params.organization_id !== 'string' || !isValidUUID(params.organization_id)) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid OrganizationId', '/vault/create'));
    }
    if (typeof params.workspace_id !== 'string' || !isValidUUID(params.workspace_id)) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid WorkspaceId', '/vault/create'));
    }
    if (typeof params.name !== 'string' || params.name.trim().length === 0) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Secret name cannot be empty', '/vault/create'));
    }

    // 3. Encrypt secret plaintext under AES-256-GCM envelope
    const encryptRes = await this.cryptoEngine.encrypt(
      params.plaintext,
      String(params.organization_id)
    );
    if (!encryptRes.isOk) {
      return err(encryptRes.error);
    }

    const enc = encryptRes.value;
    const secretId = (params.id ? String(params.id) : generateUUIDv7()) as SecretId;

    try {
      // 4. Save metadata record (strictly separate from ciphertext)
      const metaInput: CreateSecretMetadataInput = {
        id: secretId,
        organization_id: params.organization_id,
        workspace_id: params.workspace_id,
        name: params.name,
        description: params.description ?? null,
        created_by: params.created_by,
        ...(params.secret_type !== undefined ? { secret_type: params.secret_type } : {}),
        ...(params.tags !== undefined ? { tags: params.tags } : {}),
        ...(params.access_policy !== undefined ? { access_policy: params.access_policy } : {}),
        ...(params.expires_at !== undefined ? { expires_at: params.expires_at } : {}),
      };

      const meta = await this.metadataRepo.create(metaInput);

      // 5. Save Version 1 envelope record
      await this.versionRepo.createVersion({
        secret_id: meta.id,
        version: 1,
        ciphertext: enc.ciphertext,
        encrypted_dek: enc.encrypted_dek,
        nonce: enc.nonce,
        auth_tag: enc.auth_tag,
        kek_id: enc.kek_id,
        algorithm: enc.algorithm,
        status: 'ACTIVE',
      });

      this.logger?.info('Secret created successfully', {
        secret_id: meta.id,
        workspace_id: meta.workspace_id,
        name: meta.name,
      });

      return ok(meta);
    } catch (error) {
      return err(
        makeAuthProblem(
          ErrorCode.STORAGE_TRANSACTION_FAILED,
          `Failed to persist secret: ${error instanceof Error ? error.message : String(error)}`,
          '/vault/create'
        )
      );
    }
  }

  async getSecret(
    secretId: SecretId | string,
    workspaceId: WorkspaceId | string,
    securityContext?: SecurityContextToken
  ): Promise<Result<DecryptedSecret, ProblemDetails>> {
    // 1. Authorize SECRETS_READ_MATERIAL
    if (securityContext && this.authService) {
      const authRes = this.authService.evaluatePermission(
        securityContext,
        PermissionBit.SECRETS_READ_MATERIAL,
        workspaceId
      );
      if (!authRes.isOk) {
        return err(authRes.error);
      }
    }

    if (!isValidUUID(secretId)) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid SecretId', '/vault/get'));
    }
    if (!isValidUUID(workspaceId)) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid WorkspaceId', '/vault/get'));
    }

    // 2. Lookup metadata enforcing workspace isolation
    const meta = await this.metadataRepo.findById(secretId, workspaceId);
    if (!meta) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_SECRET_NOT_FOUND,
          `Secret ${secretId} not found in workspace ${workspaceId}`,
          '/vault/get'
        )
      );
    }

    // 3. Verify lifecycle status
    if (meta.status === 'REVOKED') {
      return err(
        makeAuthProblem(ErrorCode.VAULT_SECRET_REVOKED, 'Requested secret has been revoked', '/vault/get')
      );
    }
    if (meta.status === 'DISABLED') {
      return err(
        makeAuthProblem(ErrorCode.VAULT_SECRET_DISABLED, 'Requested secret is disabled', '/vault/get')
      );
    }
    if (meta.status === 'EXPIRED' || (meta.expires_at && new Date(meta.expires_at).getTime() <= Date.now())) {
      return err(
        makeAuthProblem(ErrorCode.VAULT_SECRET_EXPIRED, 'Requested secret has expired', '/vault/get')
      );
    }

    // 4. Retrieve active version
    const version = await this.versionRepo.findActiveVersion(secretId);
    if (!version) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_VERSION_NOT_FOUND,
          'Active version for requested secret not found',
          '/vault/get'
        )
      );
    }

    if (version.status === 'REVOKED') {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_SECRET_REVOKED,
          'Active version of this secret has been revoked',
          '/vault/get'
        )
      );
    }

    // 5. Decrypt envelope
    const decryptRes = await this.cryptoEngine.decrypt(
      {
        ciphertext: version.ciphertext,
        encrypted_dek: version.encrypted_dek,
        nonce: version.nonce,
        auth_tag: version.auth_tag,
      },
      meta.organization_id
    );

    if (!decryptRes.isOk) {
      return err(decryptRes.error);
    }

    const plaintext = decryptRes.value;

    this.logger?.info('Secret material retrieved (Audited)', {
      secret_id: meta.id,
      version: version.version,
      workspace_id: meta.workspace_id,
    });

    return ok({
      secret_id: meta.id,
      version: version.version,
      plaintext,
      secret_type: meta.secret_type,
      zeroize: () => zeroizeMemory(plaintext),
    });
  }

  async getSecretMetadata(
    secretId: SecretId | string,
    workspaceId: WorkspaceId | string,
    securityContext?: SecurityContextToken
  ): Promise<Result<SecretMetadataRecord, ProblemDetails>> {
    // 1. Authorize SECRETS_READ_METADATA
    if (securityContext && this.authService) {
      const authRes = this.authService.evaluatePermission(
        securityContext,
        PermissionBit.SECRETS_READ_METADATA,
        workspaceId
      );
      if (!authRes.isOk) {
        return err(authRes.error);
      }
    }

    if (!isValidUUID(secretId) || !isValidUUID(workspaceId)) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid UUIDs', '/vault/metadata'));
    }

    const meta = await this.metadataRepo.findById(secretId, workspaceId);
    if (!meta) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_SECRET_NOT_FOUND,
          `Secret ${secretId} not found in workspace ${workspaceId}`,
          '/vault/metadata'
        )
      );
    }

    return ok(meta);
  }

  async rotateSecret(
    params: RotateSecretParams,
    securityContext?: SecurityContextToken
  ): Promise<Result<SecretMetadataRecord, ProblemDetails>> {
    // 1. Authorize SECRETS_ROTATE
    if (securityContext && this.authService) {
      const authRes = this.authService.evaluatePermission(
        securityContext,
        PermissionBit.SECRETS_ROTATE,
        params.workspace_id
      );
      if (!authRes.isOk) {
        return err(authRes.error);
      }
    }

    if (!isValidUUID(params.secret_id) || !isValidUUID(params.workspace_id)) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid UUIDs', '/vault/rotate'));
    }

    const meta = await this.metadataRepo.findById(params.secret_id, params.workspace_id);
    if (!meta) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_SECRET_NOT_FOUND,
          `Secret ${params.secret_id} not found in workspace ${params.workspace_id}`,
          '/vault/rotate'
        )
      );
    }

    if (meta.status === 'REVOKED') {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_SECRET_REVOKED,
          'Cannot rotate a revoked secret',
          '/vault/rotate'
        )
      );
    }

    // 2. Encrypt new material
    const encryptRes = await this.cryptoEngine.encrypt(
      params.new_plaintext,
      meta.organization_id
    );
    if (!encryptRes.isOk) {
      return err(encryptRes.error);
    }

    const enc = encryptRes.value;
    const newVersion = meta.current_version + 1;

    // 3. Mark prior version SUPERSEDED
    await this.versionRepo.updateVersionStatus(meta.id, meta.current_version, 'SUPERSEDED');

    // 4. Create new ACTIVE version
    await this.versionRepo.createVersion({
      secret_id: meta.id,
      version: newVersion,
      ciphertext: enc.ciphertext,
      encrypted_dek: enc.encrypted_dek,
      nonce: enc.nonce,
      auth_tag: enc.auth_tag,
      kek_id: enc.kek_id,
      algorithm: enc.algorithm,
      status: 'ACTIVE',
    });

    // 5. Update metadata current_version
    await this.metadataRepo.incrementVersion(meta.id, params.workspace_id, newVersion);

    const updated = await this.metadataRepo.findById(meta.id, params.workspace_id);
    if (!updated) {
      return err(
        makeAuthProblem(
          ErrorCode.STORAGE_TRANSACTION_FAILED,
          'Failed to retrieve updated secret metadata',
          '/vault/rotate'
        )
      );
    }

    this.logger?.info('Secret rotated successfully', {
      secret_id: meta.id,
      new_version: newVersion,
      workspace_id: meta.workspace_id,
    });

    return ok(updated);
  }

  async revokeSecret(
    params: RevokeSecretParams,
    securityContext?: SecurityContextToken
  ): Promise<Result<void, ProblemDetails>> {
    // 1. Authorize SECRETS_REVOKE
    if (securityContext && this.authService) {
      const authRes = this.authService.evaluatePermission(
        securityContext,
        PermissionBit.SECRETS_REVOKE,
        params.workspace_id
      );
      if (!authRes.isOk) {
        return err(authRes.error);
      }
    }

    if (!isValidUUID(params.secret_id) || !isValidUUID(params.workspace_id)) {
      return err(makeAuthProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid UUIDs', '/vault/revoke'));
    }

    const meta = await this.metadataRepo.findById(params.secret_id, params.workspace_id);
    if (!meta) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_SECRET_NOT_FOUND,
          `Secret ${params.secret_id} not found in workspace ${params.workspace_id}`,
          '/vault/revoke'
        )
      );
    }

    // 2. Mark metadata REVOKED
    await this.metadataRepo.updateStatus(meta.id, params.workspace_id, 'REVOKED');

    // 3. Mark versions REVOKED
    const versions = await this.versionRepo.listVersions(meta.id);
    for (const v of versions) {
      if (v.status === 'ACTIVE' || v.status === 'SUPERSEDED') {
        await this.versionRepo.updateVersionStatus(
          meta.id,
          v.version,
          'REVOKED',
          params.revoked_by,
          params.reason
        );
      }
    }

    this.logger?.warn('Secret revoked', {
      secret_id: meta.id,
      workspace_id: meta.workspace_id,
      reason: params.reason,
    });

    return ok(undefined);
  }

  async rotateMasterKey(newMasterKey: Buffer): Promise<Result<KeyRotationSummary, ProblemDetails>> {
    if (!Buffer.isBuffer(newMasterKey) || newMasterKey.length !== 32) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_KEY_INVALID,
          'New master key must be a 32-byte Buffer',
          '/vault/rotate-key'
        )
      );
    }

    const oldMasterKey = Buffer.from(this.masterKey);
    const newEngine = new EnvelopeEncryptionEngine(newMasterKey, 'shn-root-kek-v2');

    // Update active engine and zeroize old master key
    this.masterKey = Buffer.from(newMasterKey);
    this.cryptoEngine = newEngine;
    zeroizeMemory(oldMasterKey);

    return ok({
      rotated_versions_count: 0,
      active_kek_id: 'shn-root-kek-v2',
    });
  }

  getEventPublisher(): IEventPublisher | undefined {
    return this.eventPublisher;
  }

  getTracer(): ITracer | undefined {
    return this.tracer;
  }
}
