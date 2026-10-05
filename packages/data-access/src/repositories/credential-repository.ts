/**
 * Shadow : Helix Nebula (SHN) — Credential Repository
 *
 * Bounded Context: IAM (mod_auth_rbac)
 * Owns table: iam.user_credentials
 * Strictly stores cryptographically secure password hashes; NEVER plaintext passwords.
 */

import { isValidUUID, type UserId } from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface UserCredentialRecord {
  readonly user_id: UserId;
  readonly password_hash: string;
  readonly failed_attempts: number;
  readonly locked_until: string | null;
  readonly last_authenticated_at: string | null;
  readonly password_changed_at: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export class CredentialRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findByUserId(userId: UserId | string): Promise<UserCredentialRecord | null> {
    if (typeof userId !== 'string' || !isValidUUID(userId)) {
      throw new Error(`Invalid UserId: must be a valid UUID string (received: ${String(userId)})`);
    }

    const result = await this.db.query<UserCredentialRecord>(
      `SELECT user_id, password_hash, failed_attempts, locked_until, last_authenticated_at,
              password_changed_at, created_at, updated_at
       FROM iam.user_credentials
       WHERE user_id = $1;`,
      [userId]
    );

    return result.rows[0] ?? null;
  }

  async saveCredential(userId: UserId | string, passwordHash: string): Promise<void> {
    if (typeof userId !== 'string' || !isValidUUID(userId)) {
      throw new Error(`Invalid UserId in saveCredential: must be a valid UUID (received: ${String(userId)})`);
    }
    if (typeof passwordHash !== 'string' || passwordHash.trim().length === 0) {
      throw new Error('Password hash must be a non-empty string');
    }

    await this.db.query(
      `INSERT INTO iam.user_credentials (user_id, password_hash, failed_attempts, locked_until, updated_at)
       VALUES ($1, $2, 0, NULL, clock_timestamp())
       ON CONFLICT (user_id) DO UPDATE
       SET password_hash = EXCLUDED.password_hash,
           failed_attempts = 0,
           locked_until = NULL,
           password_changed_at = clock_timestamp(),
           updated_at = clock_timestamp();`,
      [userId, passwordHash]
    );
  }

  async recordFailedAttempt(
    userId: UserId | string,
    lockoutThreshold = 5,
    lockoutDurationMinutes = 15
  ): Promise<{ failedAttempts: number; isLocked: boolean; lockedUntil: Date | null }> {
    if (typeof userId !== 'string' || !isValidUUID(userId)) {
      throw new Error(`Invalid UserId: must be a valid UUID string (received: ${String(userId)})`);
    }

    const result = await this.db.query<{ failed_attempts: number; locked_until: string | null }>(
      `UPDATE iam.user_credentials
       SET failed_attempts = failed_attempts + 1,
           locked_until = CASE
             WHEN (failed_attempts + 1) >= $2 THEN clock_timestamp() + ($3 || ' minutes')::interval
             ELSE locked_until
           END,
           updated_at = clock_timestamp()
       WHERE user_id = $1
       RETURNING failed_attempts, locked_until;`,
      [userId, lockoutThreshold, String(lockoutDurationMinutes)]
    );

    const row = result.rows[0];
    if (!row) {
      return { failedAttempts: 0, isLocked: false, lockedUntil: null };
    }

    const lockedUntil = row.locked_until ? new Date(row.locked_until) : null;
    const isLocked = lockedUntil !== null && lockedUntil.getTime() > Date.now();

    return {
      failedAttempts: row.failed_attempts,
      isLocked,
      lockedUntil,
    };
  }

  async recordSuccessfulAuth(userId: UserId | string): Promise<void> {
    if (typeof userId !== 'string' || !isValidUUID(userId)) {
      throw new Error(`Invalid UserId: must be a valid UUID string (received: ${String(userId)})`);
    }

    await this.db.query(
      `UPDATE iam.user_credentials
       SET failed_attempts = 0,
           locked_until = NULL,
           last_authenticated_at = clock_timestamp(),
           updated_at = clock_timestamp()
       WHERE user_id = $1;`,
      [userId]
    );
  }
}
