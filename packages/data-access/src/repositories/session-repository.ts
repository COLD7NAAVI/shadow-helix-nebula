/**
 * Shadow : Helix Nebula (SHN) — Session Repository
 *
 * Bounded Context: IAM (mod_auth_rbac)
 * Owns table: iam.sessions
 * Plaintext tokens are NEVER persisted; only cryptographically secure SHA-256 hashes.
 */

import { isValidUUID, type SessionId, type UserId, type OrganizationId, type WorkspaceId } from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface SessionRecord {
  readonly id: SessionId;
  readonly user_id: UserId;
  readonly organization_id: OrganizationId;
  readonly workspace_id: WorkspaceId | null;
  readonly token_hash: string;
  readonly refresh_token_hash: string | null;
  readonly status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  readonly ip_address: string | null;
  readonly user_agent: string | null;
  readonly expires_at: string;
  readonly refreshed_at: string | null;
  readonly revoked_at: string | null;
  readonly revoked_reason: string | null;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface CreateSessionInput {
  readonly id: SessionId | string;
  readonly user_id: UserId | string;
  readonly organization_id: OrganizationId | string;
  readonly workspace_id?: WorkspaceId | string | null;
  readonly token_hash: string;
  readonly refresh_token_hash?: string | null;
  readonly expires_at: Date;
  readonly ip_address?: string | null;
  readonly user_agent?: string | null;
}

export class SessionRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async createSession(input: CreateSessionInput): Promise<SessionRecord> {
    if (!isValidUUID(input.id)) {
      throw new Error(`Invalid SessionId: must be a valid UUID (received: ${String(input.id)})`);
    }
    if (!isValidUUID(input.user_id)) {
      throw new Error(`Invalid UserId: must be a valid UUID (received: ${String(input.user_id)})`);
    }
    if (!isValidUUID(input.organization_id)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID (received: ${String(input.organization_id)})`);
    }
    if (input.workspace_id && !isValidUUID(input.workspace_id)) {
      throw new Error(`Invalid WorkspaceId: must be a valid UUID (received: ${String(input.workspace_id)})`);
    }
    if (typeof input.token_hash !== 'string' || input.token_hash.length !== 64) {
      throw new Error('token_hash must be a 64-char SHA-256 hex string');
    }

    const result = await this.db.query<SessionRecord>(
      `INSERT INTO iam.sessions (
         id, user_id, organization_id, workspace_id, token_hash, refresh_token_hash,
         status, ip_address, user_agent, expires_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7, $8, $9)
       RETURNING *;`,
      [
        input.id,
        input.user_id,
        input.organization_id,
        input.workspace_id ?? null,
        input.token_hash,
        input.refresh_token_hash ?? null,
        input.ip_address ?? null,
        input.user_agent ?? null,
        input.expires_at.toISOString(),
      ]
    );

    const row = result.rows[0];
    if (!row) {
      throw new Error('Failed to create session: empty result returned');
    }
    return row;
  }

  async findByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    if (typeof tokenHash !== 'string' || tokenHash.length !== 64) {
      return null;
    }

    const result = await this.db.query<SessionRecord>(
      `SELECT * FROM iam.sessions
       WHERE token_hash = $1;`,
      [tokenHash]
    );

    return result.rows[0] ?? null;
  }

  async findByRefreshTokenHash(refreshTokenHash: string): Promise<SessionRecord | null> {
    if (typeof refreshTokenHash !== 'string' || refreshTokenHash.length !== 64) {
      return null;
    }

    const result = await this.db.query<SessionRecord>(
      `SELECT * FROM iam.sessions
       WHERE refresh_token_hash = $1;`,
      [refreshTokenHash]
    );

    return result.rows[0] ?? null;
  }

  async rotateSessionToken(
    sessionId: SessionId | string,
    newTokenHash: string,
    newRefreshTokenHash: string,
    newExpiresAt: Date
  ): Promise<SessionRecord> {
    if (!isValidUUID(sessionId)) {
      throw new Error(`Invalid SessionId: must be a valid UUID (received: ${String(sessionId)})`);
    }
    if (typeof newTokenHash !== 'string' || newTokenHash.length !== 64) {
      throw new Error('newTokenHash must be a 64-char SHA-256 hex string');
    }

    const result = await this.db.query<SessionRecord>(
      `UPDATE iam.sessions
       SET token_hash = $2,
           refresh_token_hash = $3,
           expires_at = $4,
           refreshed_at = clock_timestamp(),
           updated_at = clock_timestamp()
       WHERE id = $1 AND status = 'ACTIVE'
       RETURNING *;`,
      [sessionId, newTokenHash, newRefreshTokenHash, newExpiresAt.toISOString()]
    );

    const row = result.rows[0];
    if (!row) {
      throw new Error(`Failed to rotate session: session not found or not active (id: ${sessionId})`);
    }
    return row;
  }

  async revokeSession(sessionId: SessionId | string, reason: string): Promise<void> {
    if (!isValidUUID(sessionId)) {
      throw new Error(`Invalid SessionId: must be a valid UUID (received: ${String(sessionId)})`);
    }

    await this.db.query(
      `UPDATE iam.sessions
       SET status = 'REVOKED',
           revoked_at = clock_timestamp(),
           revoked_reason = $2,
           updated_at = clock_timestamp()
       WHERE id = $1;`,
      [sessionId, reason]
    );
  }

  async revokeAllUserSessions(userId: UserId | string, reason: string): Promise<number> {
    if (!isValidUUID(userId)) {
      throw new Error(`Invalid UserId: must be a valid UUID (received: ${String(userId)})`);
    }

    const result = await this.db.query<{ count: string }>(
      `WITH updated AS (
         UPDATE iam.sessions
         SET status = 'REVOKED',
             revoked_at = clock_timestamp(),
             revoked_reason = $2,
             updated_at = clock_timestamp()
         WHERE user_id = $1 AND status = 'ACTIVE'
         RETURNING id
       )
       SELECT count(*)::text as count FROM updated;`,
      [userId, reason]
    );

    return parseInt(result.rows[0]?.count ?? '0', 10);
  }

  async getActiveSessionsCount(): Promise<number> {
    const result = await this.db.query<{ count: string }>(
      `SELECT count(*)::text as count
       FROM iam.sessions
       WHERE status = 'ACTIVE' AND expires_at > clock_timestamp();`
    );

    return parseInt(result.rows[0]?.count ?? '0', 10);
  }
}
