/**
 * Shadow : Helix Nebula (SHN) — Security Context Token Cryptographic Signer
 *
 * Enforces API-INV-01 & SEC-INV-01: Stateless HMAC-signed authorization context.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  type SecurityContextToken,
  type WorkspaceId,
  type IsoTimestamp,
  isSecurityContextExpired,
  isValidUUID,
  ok,
  err,
  type Result,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { makeAuthProblem } from '../errors.js';

export const DEFAULT_CONTEXT_TTL_SECONDS = 900; // 15 minutes (Phase 0.11 Section 3.1)

export interface CreateSecurityContextTokenParams {
  readonly subjectId: string;
  readonly subjectType?: 'OPERATOR' | 'SYSTEM' | 'WORKER' | 'AUTOMATION';
  readonly workspaceId: WorkspaceId;
  readonly roles: readonly string[];
  readonly permissionMask: number;
  readonly ttlSeconds?: number;
}

export class SecurityContextSigner {
  private readonly secretKey: Buffer;

  constructor(secretKey: string | Buffer) {
    if (typeof secretKey === 'string') {
      if (secretKey.trim().length === 0) {
        throw new Error('SecurityContextSigner secretKey cannot be empty');
      }
      this.secretKey = Buffer.from(secretKey, 'utf8');
    } else if (Buffer.isBuffer(secretKey)) {
      if (secretKey.length === 0) {
        throw new Error('SecurityContextSigner secretKey Buffer cannot be empty');
      }
      this.secretKey = secretKey;
    } else {
      throw new Error('SecurityContextSigner requires a string or Buffer secretKey');
    }
  }

  computeSignature(claims: {
    subject_id: string;
    subject_type: string;
    workspace_id: string;
    roles: readonly string[];
    permission_mask: number;
    issued_at: string;
    expires_at: string;
  }): string {
    const canonicalRoles = [...claims.roles].sort().join(',');
    const canonicalClaims = [
      claims.subject_id,
      claims.subject_type,
      claims.workspace_id,
      canonicalRoles,
      String(claims.permission_mask),
      claims.issued_at,
      claims.expires_at,
    ].join(':');

    return createHmac('sha256', this.secretKey)
      .update(canonicalClaims, 'utf8')
      .digest('hex');
  }

  createToken(params: CreateSecurityContextTokenParams): SecurityContextToken {
    if (!isValidUUID(params.subjectId)) {
      throw new Error(`Invalid subjectId: must be a valid UUID (received: ${String(params.subjectId)})`);
    }
    if (!isValidUUID(params.workspaceId)) {
      throw new Error(`Invalid workspaceId: must be a valid UUID (received: ${String(params.workspaceId)})`);
    }

    const now = Date.now();
    const issuedAt = new Date(now).toISOString() as IsoTimestamp;
    const ttlMs = (params.ttlSeconds ?? DEFAULT_CONTEXT_TTL_SECONDS) * 1000;
    const expiresAt = new Date(now + ttlMs).toISOString() as IsoTimestamp;

    const tokenClaims = {
      subject_id: params.subjectId,
      subject_type: params.subjectType ?? 'OPERATOR',
      workspace_id: params.workspaceId,
      roles: Object.freeze([...params.roles]),
      permission_mask: params.permissionMask,
      issued_at: issuedAt,
      expires_at: expiresAt,
    };

    const signature = this.computeSignature(tokenClaims);

    return Object.freeze({
      ...tokenClaims,
      signature,
    });
  }

  verifyToken(token: unknown, now = Date.now()): Result<SecurityContextToken, ProblemDetails> {
    if (!token || typeof token !== 'object') {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_TOKEN_INVALID,
          'Security context token must be a non-null object',
          '/auth/token'
        )
      );
    }

    const candidate = token as Partial<SecurityContextToken>;

    if (
      typeof candidate.subject_id !== 'string' ||
      !isValidUUID(candidate.subject_id) ||
      typeof candidate.subject_type !== 'string' ||
      typeof candidate.workspace_id !== 'string' ||
      !isValidUUID(candidate.workspace_id) ||
      !Array.isArray(candidate.roles) ||
      typeof candidate.permission_mask !== 'number' ||
      typeof candidate.issued_at !== 'string' ||
      typeof candidate.expires_at !== 'string' ||
      typeof candidate.signature !== 'string'
    ) {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_TOKEN_INVALID,
          'Security context token structure is malformed or missing required claims',
          '/auth/token'
        )
      );
    }

    // Check expiration fail-closed
    if (isSecurityContextExpired(candidate as SecurityContextToken, now)) {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_TOKEN_EXPIRED,
          `Security context token expired at ${candidate.expires_at}`,
          '/auth/token'
        )
      );
    }

    // Recompute signature and compare constant-time
    const expectedSig = this.computeSignature({
      subject_id: candidate.subject_id,
      subject_type: candidate.subject_type,
      workspace_id: candidate.workspace_id,
      roles: candidate.roles,
      permission_mask: candidate.permission_mask,
      issued_at: candidate.issued_at,
      expires_at: candidate.expires_at,
    });

    try {
      const sigBuffer = Buffer.from(candidate.signature, 'hex');
      const expectedBuffer = Buffer.from(expectedSig, 'hex');

      if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
        return err(
          makeAuthProblem(
            ErrorCode.AUTH_TOKEN_INVALID,
            'Security context cryptographic signature verification failed: invalid signature',
            '/auth/token'
          )
        );
      }
    } catch {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_TOKEN_INVALID,
          'Security context signature comparison failed fail-closed',
          '/auth/token'
        )
      );
    }

    return ok(candidate as SecurityContextToken);
  }
}
