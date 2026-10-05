/**
 * Shadow : Helix Nebula (SHN) — Cryptographic Session & Token Lifecycle Manager
 *
 * Enforces SEC-AUT-001 & Phase 0.11 Section 3:
 * - High-entropy session tokens and refresh tokens.
 * - Plaintext tokens are NEVER persisted; only SHA-256 digests.
 * - Secure rotation and revocation primitives.
 */

import { randomBytes, createHash } from 'node:crypto';
import type {
  SessionId,
  UserId,
  OrganizationId,
  WorkspaceId,
} from '@shn/shared-kernel';
import type {
  SessionRepository,
  SessionRecord,
  CreateSessionInput,
} from '@shn/data-access';

export const BEARER_PREFIX = 'shn_sec_';
export const REFRESH_PREFIX = 'shn_ref_';
export const DEFAULT_SESSION_TTL_HOURS = 12;
export const DEFAULT_REFRESH_TTL_DAYS = 7;

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function generateToken(prefix: string): string {
  const entropy = randomBytes(32).toString('hex');
  return `${prefix}${entropy}`;
}

export class SessionManager {
  private readonly sessionRepo: SessionRepository;
  private readonly sessionTtlHours: number;
  private readonly refreshTtlDays: number;

  constructor(
    sessionRepo: SessionRepository,
    sessionTtlHours = DEFAULT_SESSION_TTL_HOURS,
    refreshTtlDays = DEFAULT_REFRESH_TTL_DAYS
  ) {
    this.sessionRepo = sessionRepo;
    this.sessionTtlHours = sessionTtlHours;
    this.refreshTtlDays = refreshTtlDays;
  }

  getRefreshTtlDays(): number {
    return this.refreshTtlDays;
  }

  async createSession(params: {
    sessionId: SessionId | string;
    userId: UserId | string;
    organizationId: OrganizationId | string;
    workspaceId?: WorkspaceId | string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<{
    session: SessionRecord;
    bearerToken: string;
    refreshToken: string;
  }> {
    const bearerToken = generateToken(BEARER_PREFIX);
    const refreshToken = generateToken(REFRESH_PREFIX);

    const tokenHash = hashToken(bearerToken);
    const refreshTokenHash = hashToken(refreshToken);

    const expiresAt = new Date(Date.now() + this.sessionTtlHours * 3600 * 1000);

    const input: CreateSessionInput = {
      id: params.sessionId,
      user_id: params.userId,
      organization_id: params.organizationId,
      workspace_id: params.workspaceId ?? null,
      token_hash: tokenHash,
      refresh_token_hash: refreshTokenHash,
      expires_at: expiresAt,
      ip_address: params.ipAddress ?? null,
      user_agent: params.userAgent ?? null,
    };

    const session = await this.sessionRepo.createSession(input);

    return {
      session,
      bearerToken,
      refreshToken,
    };
  }

  async rotateSession(
    sessionId: SessionId | string
  ): Promise<{
    session: SessionRecord;
    newBearerToken: string;
    newRefreshToken: string;
  }> {
    const newBearerToken = generateToken(BEARER_PREFIX);
    const newRefreshToken = generateToken(REFRESH_PREFIX);

    const newTokenHash = hashToken(newBearerToken);
    const newRefreshTokenHash = hashToken(newRefreshToken);

    const newExpiresAt = new Date(Date.now() + this.sessionTtlHours * 3600 * 1000);

    const session = await this.sessionRepo.rotateSessionToken(
      sessionId,
      newTokenHash,
      newRefreshTokenHash,
      newExpiresAt
    );

    return {
      session,
      newBearerToken,
      newRefreshToken,
    };
  }

  async revokeSession(sessionId: SessionId | string, reason: string): Promise<void> {
    await this.sessionRepo.revokeSession(sessionId, reason);
  }

  async revokeAllUserSessions(userId: UserId | string, reason: string): Promise<number> {
    return this.sessionRepo.revokeAllUserSessions(userId, reason);
  }

  async findByBearerToken(bearerToken: string): Promise<SessionRecord | null> {
    if (typeof bearerToken !== 'string' || !bearerToken.startsWith(BEARER_PREFIX)) {
      return null;
    }
    const tokenHash = hashToken(bearerToken);
    return this.sessionRepo.findByTokenHash(tokenHash);
  }

  async findByRefreshToken(refreshToken: string): Promise<SessionRecord | null> {
    if (typeof refreshToken !== 'string' || !refreshToken.startsWith(REFRESH_PREFIX)) {
      return null;
    }
    const tokenHash = hashToken(refreshToken);
    return this.sessionRepo.findByRefreshTokenHash(tokenHash);
  }
}
