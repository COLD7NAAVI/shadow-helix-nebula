/**
 * Shadow : Helix Nebula (SHN) — Secrets Metadata Repository
 *
 * Bounded Context: Secrets Vault (mod_secrets_vault)
 * Owns table: secrets.metadata
 * Strictly separated from secret material/ciphertext.
 * Every query enforces workspace_id multi-tenant isolation (SEC-INV-12).
 */

import {
  isValidUUID,
  type SecretId,
  type WorkspaceId,
  type OrganizationId,
  type UserId,
} from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface SecretMetadataRecord {
  readonly id: SecretId;
  readonly organization_id: OrganizationId;
  readonly workspace_id: WorkspaceId;
  readonly name: string;
  readonly description: string | null;
  readonly secret_type: string;
  readonly status: 'ACTIVE' | 'DISABLED' | 'REVOKED' | 'EXPIRED';
  readonly current_version: number;
  readonly tags: Record<string, string>;
  readonly access_policy: Record<string, unknown>;
  readonly expires_at: string | null;
  readonly created_by: UserId;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface CreateSecretMetadataInput {
  readonly id: SecretId | string;
  readonly organization_id: OrganizationId | string;
  readonly workspace_id: WorkspaceId | string;
  readonly name: string;
  readonly description?: string | null;
  readonly secret_type?: string;
  readonly tags?: Record<string, string>;
  readonly access_policy?: Record<string, unknown>;
  readonly expires_at?: Date | null;
  readonly created_by: UserId | string;
}

export class SecretsMetadataRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async create(input: CreateSecretMetadataInput): Promise<SecretMetadataRecord> {
    if (!isValidUUID(input.id)) throw new Error(`Invalid SecretId: ${String(input.id)}`);
    if (!isValidUUID(input.organization_id)) throw new Error(`Invalid OrganizationId: ${String(input.organization_id)}`);
    if (!isValidUUID(input.workspace_id)) throw new Error(`Invalid WorkspaceId: ${String(input.workspace_id)}`);
    if (!isValidUUID(input.created_by)) throw new Error(`Invalid UserId: ${String(input.created_by)}`);
    if (typeof input.name !== 'string' || input.name.trim().length === 0) {
      throw new Error('Secret name must be a non-empty string');
    }

    const result = await this.db.query<SecretMetadataRecord>(
      `INSERT INTO secrets.metadata (
         id, organization_id, workspace_id, name, description, secret_type,
         status, current_version, tags, access_policy, expires_at, created_by
       )
       VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', 1, $7, $8, $9, $10)
       RETURNING *;`,
      [
        input.id,
        input.organization_id,
        input.workspace_id,
        input.name.trim(),
        input.description ?? null,
        input.secret_type ?? 'GENERIC',
        JSON.stringify(input.tags ?? {}),
        JSON.stringify(input.access_policy ?? {}),
        input.expires_at ? input.expires_at.toISOString() : null,
        input.created_by,
      ]
    );

    const row = result.rows[0];
    if (!row) throw new Error('Failed to create secret metadata: empty result set returned');
    return row;
  }

  async findById(
    secretId: SecretId | string,
    workspaceId: WorkspaceId | string
  ): Promise<SecretMetadataRecord | null> {
    if (!isValidUUID(secretId)) throw new Error(`Invalid SecretId: ${String(secretId)}`);
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    const result = await this.db.query<SecretMetadataRecord>(
      `SELECT * FROM secrets.metadata
       WHERE id = $1 AND workspace_id = $2;`,
      [secretId, workspaceId]
    );

    return result.rows[0] ?? null;
  }

  async findByName(
    workspaceId: WorkspaceId | string,
    name: string
  ): Promise<SecretMetadataRecord | null> {
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);
    if (typeof name !== 'string' || name.trim().length === 0) return null;

    const result = await this.db.query<SecretMetadataRecord>(
      `SELECT * FROM secrets.metadata
       WHERE workspace_id = $1 AND name = $2;`,
      [workspaceId, name.trim()]
    );

    return result.rows[0] ?? null;
  }

  async listByWorkspace(
    workspaceId: WorkspaceId | string,
    options?: { status?: string }
  ): Promise<SecretMetadataRecord[]> {
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    let query: string;
    let params: unknown[];

    if (options?.status) {
      query = `SELECT * FROM secrets.metadata WHERE workspace_id = $1 AND status = $2 ORDER BY name ASC;`;
      params = [workspaceId, options.status];
    } else {
      query = `SELECT * FROM secrets.metadata WHERE workspace_id = $1 ORDER BY name ASC;`;
      params = [workspaceId];
    }

    const result = await this.db.query<SecretMetadataRecord>(query, params);
    return result.rows;
  }

  async updateStatus(
    secretId: SecretId | string,
    workspaceId: WorkspaceId | string,
    status: 'ACTIVE' | 'DISABLED' | 'REVOKED' | 'EXPIRED'
  ): Promise<void> {
    if (!isValidUUID(secretId)) throw new Error(`Invalid SecretId: ${String(secretId)}`);
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    await this.db.query(
      `UPDATE secrets.metadata
       SET status = $3,
           updated_at = clock_timestamp()
       WHERE id = $1 AND workspace_id = $2;`,
      [secretId, workspaceId, status]
    );
  }

  async incrementVersion(
    secretId: SecretId | string,
    workspaceId: WorkspaceId | string,
    newVersion: number
  ): Promise<void> {
    if (!isValidUUID(secretId)) throw new Error(`Invalid SecretId: ${String(secretId)}`);
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    await this.db.query(
      `UPDATE secrets.metadata
       SET current_version = $3,
           updated_at = clock_timestamp()
       WHERE id = $1 AND workspace_id = $2;`,
      [secretId, workspaceId, newVersion]
    );
  }
}
