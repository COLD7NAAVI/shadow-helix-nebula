/**
 * Shadow : Helix Nebula (SHN) — Scope Token Cryptographic Signer & Anti-Tamper Verifier
 *
 * Enforces API-INV-02, INV-06, SEC-INV-01:
 * - Cryptographic HMAC-SHA256 minting and verification
 * - Canonical claims serialization
 * - Replay & tamper detection (nonce, scope_sha256 seal, constant-time signature comparison)
 * - Strict multi-tenant binding (organization, workspace, actor)
 * - Temporal window enforcement (valid_from / valid_until)
 */

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import {
  type IsoTimestamp,
  isValidUUID,
  ok,
  err,
  type Result,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import type {
  ScopeToken,
  ScopeTokenClaims,
  MintScopeTokenParams,
} from '../contracts.js';
import { makeScopeProblem } from '../errors.js';
import { calculateCanonicalScopeSha256 } from '../evaluators/scope-composition.js';

export const DEFAULT_SCOPE_TOKEN_TTL_SECONDS = 3600; // 1 hour

export interface ScopeTokenHeader {
  readonly alg: 'HS256';
  readonly typ: 'SHN-SCOPE';
  readonly v: 1;
}

export class ScopeTokenSigner {
  private readonly secretKey: Buffer;

  constructor(secretKey: string | Buffer) {
    if (typeof secretKey === 'string') {
      if (secretKey.trim().length === 0) {
        throw new Error('ScopeTokenSigner secretKey cannot be empty');
      }
      this.secretKey = Buffer.from(secretKey, 'utf8');
    } else if (Buffer.isBuffer(secretKey)) {
      if (secretKey.length === 0) {
        throw new Error('ScopeTokenSigner secretKey Buffer cannot be empty');
      }
      this.secretKey = secretKey;
    } else {
      throw new Error('ScopeTokenSigner requires a string or Buffer secretKey');
    }
  }

  private base64UrlEncode(data: string | Buffer): string {
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    return buf.toString('base64url');
  }

  private base64UrlDecode(data: string): string {
    return Buffer.from(data, 'base64url').toString('utf8');
  }

  private computeSignature(headerEncoded: string, payloadEncoded: string): Buffer {
    const signingInput = `${headerEncoded}.${payloadEncoded}`;
    return createHmac('sha256', this.secretKey).update(signingInput, 'utf8').digest();
  }

  /**
   * Mints an HMAC-SHA256 protected ScopeToken from an active ScopeDefinition and Actor.
   */
  mintScopeToken(params: MintScopeTokenParams): Result<ScopeToken, ProblemDetails> {
    const { scope, actorId, ttlSeconds } = params;

    if (!isValidUUID(scope.id)) {
      return err(
        makeScopeProblem(ErrorCode.SCOPE_TOKEN_INVALID, `Invalid scopeId: '${scope.id}'`)
      );
    }
    if (!isValidUUID(scope.workspaceId)) {
      return err(
        makeScopeProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, `Invalid workspaceId: '${scope.workspaceId}'`)
      );
    }
    if (!isValidUUID(scope.organizationId)) {
      return err(
        makeScopeProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, `Invalid organizationId: '${scope.organizationId}'`)
      );
    }
    if (!isValidUUID(actorId)) {
      return err(
        makeScopeProblem(ErrorCode.AUTH_CREDENTIALS_INVALID, `Invalid actorId: '${actorId}'`)
      );
    }

    const now = Date.now();
    const issuedAt = new Date(now).toISOString() as IsoTimestamp;

    // Use scope validUntil or ttlSeconds, whichever is earlier
    const ttlMs = (ttlSeconds ?? DEFAULT_SCOPE_TOKEN_TTL_SECONDS) * 1000;
    const computedExpiryTime = Math.min(new Date(scope.validUntil).getTime(), now + ttlMs);
    const validUntil = new Date(computedExpiryTime).toISOString() as IsoTimestamp;
    const validFrom = scope.validFrom;

    const nonce = randomBytes(16).toString('hex');

    const scopeSha256 = calculateCanonicalScopeSha256({
      inclusions: scope.inclusions,
      exclusions: scope.exclusions,
      allowedActions: scope.allowedActions,
      disallowedActions: scope.disallowedActions,
      portRanges: scope.portRanges,
      validFrom,
      validUntil,
    });

    const claims: ScopeTokenClaims = {
      scope_id: scope.id,
      organization_id: scope.organizationId,
      workspace_id: scope.workspaceId,
      actor_id: actorId,
      inclusions: scope.inclusions,
      exclusions: scope.exclusions,
      allowed_actions: scope.allowedActions,
      disallowed_actions: scope.disallowedActions,
      port_ranges: scope.portRanges,
      valid_from: validFrom,
      valid_until: validUntil,
      scope_sha256: scopeSha256,
      version: scope.version,
      nonce,
      issued_at: issuedAt,
    };

    const header: ScopeTokenHeader = {
      alg: 'HS256',
      typ: 'SHN-SCOPE',
      v: 1,
    };

    const headerEncoded = this.base64UrlEncode(JSON.stringify(header));
    const payloadEncoded = this.base64UrlEncode(JSON.stringify(claims));
    const signature = this.computeSignature(headerEncoded, payloadEncoded);
    const signatureEncoded = this.base64UrlEncode(signature);

    const token = `${headerEncoded}.${payloadEncoded}.${signatureEncoded}` as ScopeToken;
    return ok(token);
  }

  /**
   * Verifies cryptographic integrity, tamper immunity, tenant bindings, and temporal validity of a ScopeToken.
   */
  verifyScopeToken(tokenStr: string, now = Date.now()): Result<ScopeTokenClaims, ProblemDetails> {
    if (typeof tokenStr !== 'string' || !tokenStr.trim()) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_INVALID,
          'Scope token must be a non-empty string'
        )
      );
    }

    const parts = tokenStr.trim().split('.');
    if (parts.length !== 3) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_INVALID,
          'Scope token format malformed: expected 3 dot-separated parts'
        )
      );
    }

    const [headerEncoded, payloadEncoded, sigEncoded] = parts as [string, string, string];

    // Decode header
    let header: ScopeTokenHeader;
    try {
      header = JSON.parse(this.base64UrlDecode(headerEncoded));
    } catch {
      return err(
        makeScopeProblem(ErrorCode.SCOPE_TOKEN_INVALID, 'Scope token header is not valid JSON')
      );
    }

    if (header.alg !== 'HS256' || header.typ !== 'SHN-SCOPE' || header.v !== 1) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_INVALID,
          `Unsupported scope token header: alg=${header.alg}, typ=${header.typ}, v=${header.v}`
        )
      );
    }

    // Verify signature constant-time
    const expectedSig = this.computeSignature(headerEncoded, payloadEncoded);
    let providedSig: Buffer;
    try {
      providedSig = Buffer.from(sigEncoded, 'base64url');
    } catch {
      return err(
        makeScopeProblem(ErrorCode.SCOPE_TOKEN_INVALID, 'Scope token signature is not valid base64url')
      );
    }

    if (expectedSig.length !== providedSig.length || !timingSafeEqual(expectedSig, providedSig)) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_INVALID,
          'Scope token cryptographic signature verification failed: invalid signature or tampered claims'
        )
      );
    }

    // Decode claims payload
    let claims: ScopeTokenClaims;
    try {
      claims = JSON.parse(this.base64UrlDecode(payloadEncoded));
    } catch {
      return err(
        makeScopeProblem(ErrorCode.SCOPE_TOKEN_INVALID, 'Scope token payload is not valid JSON')
      );
    }

    // Validate claims structure
    if (
      !claims.scope_id ||
      !isValidUUID(claims.scope_id) ||
      !claims.workspace_id ||
      !isValidUUID(claims.workspace_id) ||
      !claims.organization_id ||
      !isValidUUID(claims.organization_id) ||
      !claims.actor_id ||
      !isValidUUID(claims.actor_id) ||
      !claims.valid_from ||
      !claims.valid_until ||
      !claims.scope_sha256 ||
      typeof claims.nonce !== 'string'
    ) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_INVALID,
          'Scope token claims structure missing required attributes or malformed UUIDs'
        )
      );
    }

    // Check temporal window
    const startTime = new Date(claims.valid_from).getTime();
    const expiryTime = new Date(claims.valid_until).getTime();

    if (now > expiryTime) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_EXPIRED,
          `Scope token expired at ${claims.valid_until}`
        )
      );
    }

    if (now < startTime) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_INVALID,
          `Scope token not yet valid (valid_from: ${claims.valid_from})`
        )
      );
    }

    // Anti-tamper verification of scope_sha256 against claims content
    const recomputedSha = calculateCanonicalScopeSha256({
      inclusions: claims.inclusions || {},
      exclusions: claims.exclusions || {},
      allowedActions: claims.allowed_actions || [],
      disallowedActions: claims.disallowed_actions || [],
      portRanges: claims.port_ranges || [],
      validFrom: claims.valid_from,
      validUntil: claims.valid_until,
    });

    if (recomputedSha !== claims.scope_sha256) {
      return err(
        makeScopeProblem(
          ErrorCode.SCOPE_TOKEN_INVALID,
          'Scope token content tampered: scope_sha256 does not match canonical claims hash'
        )
      );
    }

    return ok(claims);
  }
}
