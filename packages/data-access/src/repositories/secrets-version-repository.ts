/**
 * Shadow : Helix Nebula (SHN) — Secrets Version Repository
 *
 * Bounded Context: Secrets Vault (mod_secrets_vault)
 * Owns table: secrets.versions
 * Persists AES-256-GCM ciphertext, encrypted DEK, IV/nonce, and auth tag.
 */

import {
  isValidUUID,
  type SecretId,
  type UserId,
} from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface SecretVersionRecord {
  readonly id: string;
  readonly secret_id: SecretId;
  readonly version: number;
  readonly ciphertext: Buffer;
  readonly encrypted_dek: Buffer;
  readonly nonce: Buffer;
  readonly auth_tag: Buffer;
  readonly kek_id: string;
  readonly algorithm: string;
  readonly status: 'ACTIVE' | 'SUPERSEDED' | 'REVOKED' | 'DISABLED';
  readonly created_at: string;
  readonly revoked_at: string | null;
  readonly revoked_by: UserId | null;
  readonly revocation_reason: string | null;
}

export interface CreateSecretVersionInput {
  readonly secret_id: SecretId | string;
  readonly version: number;
  readonly ciphertext: Buffer;
  readonly encrypted_dek: Buffer;
  readonly nonce: Buffer;
  readonly auth_tag: Buffer;
  readonly kek_id: string;
  readonly algorithm?: string;
  readonly status?: 'ACTIVE' | 'SUPERSEDED' | 'REVOKED' | 'DISABLED';
}

export class SecretsVersionRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async createVersion(input: CreateSecretVersionInput): Promise<SecretVersionRecord> {
    if (!isValidUUID(input.secret_id)) {
      throw new Error(`Invalid SecretId: ${String(input.secret_id)}`);
    }
    if (typeof input.version !== 'number' || input.version < 1) {
      throw new Error(`Invalid secret version: must be a positive integer (received: ${input.version})`);
    }
    if (!Buffer.isBuffer(input.ciphertext) || input.ciphertext.length === 0) {
      throw new Error('Ciphertext must be a non-empty Buffer');
    }
    if (!Buffer.isBuffer(input.encrypted_dek) || input.encrypted_dek.length === 0) {
      throw new Error('Encrypted DEK must be a non-empty Buffer');
    }
    if (!Buffer.isBuffer(input.nonce) || input.nonce.length !== 12) {
      throw new Error('Nonce must be a 12-byte Buffer (AES-GCM standard)');
    }
    if (!Buffer.isBuffer(input.auth_tag) || input.auth_tag.length !== 16) {
      throw new Error('Auth tag must be a 16-byte Buffer (AES-GCM standard)');
    }

    const result = await this.db.query<SecretVersionRecord>(
      `INSERT INTO secrets.versions (
         secret_id, version, ciphertext, encrypted_dek, nonce, auth_tag,
         kek_id, algorithm, status
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *;`,
      [
        input.secret_id,
        input.version,
        input.ciphertext,
        input.encrypted_dek,
        input.nonce,
        input.auth_tag,
        input.kek_id,
        input.algorithm ?? 'AES-256-GCM',
        input.status ?? 'ACTIVE',
      ]
    );

    const row = result.rows[0];
    if (!row) throw new Error('Failed to create secret version: empty result set returned');
    return row;
  }

  async findByVersion(
    secretId: SecretId | string,
    version: number
  ): Promise<SecretVersionRecord | null> {
    if (!isValidUUID(secretId)) throw new Error(`Invalid SecretId: ${String(secretId)}`);
    if (typeof version !== 'number' || version < 1) return null;

    const result = await this.db.query<SecretVersionRecord>(
      `SELECT * FROM secrets.versions
       WHERE secret_id = $1 AND version = $2;`,
      [secretId, version]
    );

    return result.rows[0] ?? null;
  }

  async findActiveVersion(secretId: SecretId | string): Promise<SecretVersionRecord | null> {
    if (!isValidUUID(secretId)) throw new Error(`Invalid SecretId: ${String(secretId)}`);

    const result = await this.db.query<SecretVersionRecord>(
      `SELECT * FROM secrets.versions
       WHERE secret_id = $1 AND status = 'ACTIVE'
       ORDER BY version DESC
       LIMIT 1;`,
      [secretId]
    );

    return result.rows[0] ?? null;
  }

  async listVersions(secretId: SecretId | string): Promise<SecretVersionRecord[]> {
    if (!isValidUUID(secretId)) throw new Error(`Invalid SecretId: ${String(secretId)}`);

    const result = await this.db.query<SecretVersionRecord>(
      `SELECT * FROM secrets.versions
       WHERE secret_id = $1
       ORDER BY version DESC;`,
      [secretId]
    );

    return result.rows;
  }

  async updateVersionStatus(
    secretId: SecretId | string,
    version: number,
    status: 'ACTIVE' | 'SUPERSEDED' | 'REVOKED' | 'DISABLED',
    revokedBy?: UserId | string | null,
    reason?: string | null
  ): Promise<void> {
    if (!isValidUUID(secretId)) throw new Error(`Invalid SecretId: ${String(secretId)}`);

    if (status === 'REVOKED') {
      await this.db.query(
        `UPDATE secrets.versions
         SET status = $3,
             revoked_at = clock_timestamp(),
             revoked_by = $4,
             revocation_reason = $5
         WHERE secret_id = $1 AND version = $2;`,
        [secretId, version, status, revokedBy ?? null, reason ?? null]
      );
    } else {
      await this.db.query(
        `UPDATE secrets.versions
         SET status = $3
         WHERE secret_id = $1 AND version = $2;`,
        [secretId, version, status]
      );
    }
  }
}
