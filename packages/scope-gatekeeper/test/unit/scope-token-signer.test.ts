/**
 * Shadow : Helix Nebula (SHN) — Scope Token Signer Pure Unit Tests
 *
 * Enforces API-INV-02, INV-06, and SEC-INV-01:
 * - Cryptographic HMAC-SHA256 minting & verification
 * - Temporal window enforcement (expiration & future valid_from)
 * - Tamper detection across all protected claims
 * - Constant-time signature comparison
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateUUIDv7,
  createScopeId,
  createWorkspaceId,
  createOrganizationId,
  createUserId,
  type IsoTimestamp,
} from '@shn/shared-kernel';
import { ErrorCode } from '@shn/error-catalog';
import {
  ScopeTokenSigner,
  calculateCanonicalScopeSha256,
  type ScopeDefinition,
} from '../../dist/index.js';

describe('Scope Token Signer & Anti-Tamper Verification (Pure Unit Tests)', () => {
  const secretKey = 'test-secret-key-for-scope-token-signing-32b!';
  const signer = new ScopeTokenSigner(secretKey);

  const orgId = createOrganizationId(generateUUIDv7()).value;
  const wsId = createWorkspaceId(generateUUIDv7()).value;
  const actorId = createUserId(generateUUIDv7()).value;
  const scopeId = createScopeId(generateUUIDv7()).value;

  function makeTestScope(overrides: Partial<ScopeDefinition> = {}): ScopeDefinition {
    const base = {
      id: scopeId,
      workspaceId: wsId,
      organizationId: orgId,
      name: 'Signer Test Scope',
      inclusions: {
        cidrs: ['10.0.0.0/24'],
        hostnames: ['*.example.com'],
        urls: ['https://example.com/api'],
        resources: ['res:target-1'],
      },
      exclusions: {
        cidrs: ['10.0.0.50/32'],
        hostnames: [],
        urls: [],
        resources: [],
      },
      allowedActions: ['read', 'scan'],
      disallowedActions: ['admin'],
      portRanges: [{ start: 80, end: 443 }],
      validFrom: new Date(Date.now() - 60000).toISOString() as IsoTimestamp,
      validUntil: new Date(Date.now() + 3600000).toISOString() as IsoTimestamp,
      scopeSha256: '',
      status: 'active' as const,
      version: 1,
      ...overrides,
    };
    const scopeSha256 = calculateCanonicalScopeSha256(base);
    return { ...base, scopeSha256 };
  }

  describe('Minting & Valid Verification', () => {
    it('should mint a 3-part base64url scope token', () => {
      const scope = makeTestScope();
      const mintRes = signer.mintScopeToken({ scope, actorId });

      assert.strictEqual(mintRes.isOk, true);
      const token = mintRes.value;
      const parts = token.split('.');
      assert.strictEqual(parts.length, 3);
    });

    it('should verify a valid scope token and return all claims', () => {
      const scope = makeTestScope();
      const token = signer.mintScopeToken({ scope, actorId }).value;

      const verifyRes = signer.verifyScopeToken(token);
      assert.strictEqual(verifyRes.isOk, true);

      const claims = verifyRes.value;
      assert.strictEqual(claims.scope_id, scope.id);
      assert.strictEqual(claims.organization_id, scope.organizationId);
      assert.strictEqual(claims.workspace_id, scope.workspaceId);
      assert.strictEqual(claims.actor_id, actorId);
      assert.deepStrictEqual(claims.allowed_actions, ['read', 'scan']);
      assert.strictEqual(claims.scope_sha256, scope.scopeSha256);
      assert.ok(claims.nonce.length > 0);
    });
  });

  describe('Temporal Window Enforcement', () => {
    it('should fail closed with SCOPE_TOKEN_EXPIRED when token is expired', () => {
      const pastTime = new Date(Date.now() - 10000).toISOString() as IsoTimestamp;
      const earlierPastTime = new Date(Date.now() - 50000).toISOString() as IsoTimestamp;
      const expiredScope = makeTestScope({
        validFrom: earlierPastTime,
        validUntil: pastTime,
      });

      const token = signer.mintScopeToken({ scope: expiredScope, actorId }).value;
      const verifyRes = signer.verifyScopeToken(token);

      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_EXPIRED);
    });

    it('should fail closed when token valid_from is in the future', () => {
      const futureStart = new Date(Date.now() + 600000).toISOString() as IsoTimestamp;
      const futureEnd = new Date(Date.now() + 1200000).toISOString() as IsoTimestamp;
      const futureScope = makeTestScope({
        validFrom: futureStart,
        validUntil: futureEnd,
      });

      const token = signer.mintScopeToken({ scope: futureScope, actorId }).value;
      const verifyRes = signer.verifyScopeToken(token);

      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_INVALID);
    });
  });

  describe('Adversarial Tamper Detection', () => {
    function tamperClaim(token: string, mutator: (claims: Record<string, unknown>) => void): string {
      const [headerEnc, payloadEnc, sigEnc] = token.split('.') as [string, string, string];
      const payload = JSON.parse(Buffer.from(payloadEnc, 'base64url').toString('utf8'));
      mutator(payload);
      const tamperedPayloadEnc = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
      return `${headerEnc}.${tamperedPayloadEnc}.${sigEnc}`;
    }

    it('should detect altered workspace_id (tenant hopping attack)', () => {
      const scope = makeTestScope();
      const token = signer.mintScopeToken({ scope, actorId }).value;

      const attackerWsId = createWorkspaceId(generateUUIDv7()).value;
      const tamperedToken = tamperClaim(token, (c) => {
        c.workspace_id = attackerWsId;
      });

      const verifyRes = signer.verifyScopeToken(tamperedToken);
      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_INVALID);
    });

    it('should detect altered actor_id (identity impersonation attack)', () => {
      const scope = makeTestScope();
      const token = signer.mintScopeToken({ scope, actorId }).value;

      const victimActorId = createUserId(generateUUIDv7()).value;
      const tamperedToken = tamperClaim(token, (c) => {
        c.actor_id = victimActorId;
      });

      const verifyRes = signer.verifyScopeToken(tamperedToken);
      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_INVALID);
    });

    it('should detect extended valid_until (expiration bypass attack)', () => {
      const scope = makeTestScope();
      const token = signer.mintScopeToken({ scope, actorId }).value;

      const nextYear = new Date(Date.now() + 31536000000).toISOString();
      const tamperedToken = tamperClaim(token, (c) => {
        c.valid_until = nextYear;
      });

      const verifyRes = signer.verifyScopeToken(tamperedToken);
      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_INVALID);
    });

    it('should detect injected target inclusions (scope broadening attack)', () => {
      const scope = makeTestScope();
      const token = signer.mintScopeToken({ scope, actorId }).value;

      const tamperedToken = tamperClaim(token, (c) => {
        (c.inclusions as Record<string, unknown>).cidrs = ['0.0.0.0/0'];
      });

      const verifyRes = signer.verifyScopeToken(tamperedToken);
      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_INVALID);
    });

    it('should detect elevated actions (privilege escalation attack)', () => {
      const scope = makeTestScope();
      const token = signer.mintScopeToken({ scope, actorId }).value;

      const tamperedToken = tamperClaim(token, (c) => {
        c.allowed_actions = ['read', 'scan', 'admin', 'root'];
      });

      const verifyRes = signer.verifyScopeToken(tamperedToken);
      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_INVALID);
    });

    it('should reject token verified with a different secret key', () => {
      const scope = makeTestScope();
      const token = signer.mintScopeToken({ scope, actorId }).value;

      const impostorSigner = new ScopeTokenSigner('different-wrong-secret-key-32b-long!');
      const verifyRes = impostorSigner.verifyScopeToken(token);

      assert.strictEqual(verifyRes.isErr, true);
      assert.strictEqual(verifyRes.error.error_code, ErrorCode.SCOPE_TOKEN_INVALID);
    });

    it('should reject malformed token strings', () => {
      assert.strictEqual(signer.verifyScopeToken('').isErr, true);
      assert.strictEqual(signer.verifyScopeToken('part1.part2').isErr, true);
      assert.strictEqual(signer.verifyScopeToken('p1.p2.p3.p4').isErr, true);
      assert.strictEqual(signer.verifyScopeToken('invalid!@#$').isErr, true);
    });
  });
});
