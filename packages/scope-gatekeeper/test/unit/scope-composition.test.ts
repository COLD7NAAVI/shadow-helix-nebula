/**
 * Shadow : Helix Nebula (SHN) — Scope Composition Pure Unit Tests
 *
 * Enforces INV-06, API-INV-02, and SEC-INV-01:
 * - Downward-narrowing scope intersection
 * - Inclusions: Strict intersection
 * - Exclusions: Union
 * - Port ranges: Overlap intersection
 * - Actions: Allowed actions intersect, disallowed actions union
 * - Temporal window: max(valid_from) and min(valid_until)
 * - Cryptographic SHA-256 sealing of canonical representation
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateUUIDv7,
  createScopeId,
  createWorkspaceId,
  createOrganizationId,
  type IsoTimestamp,
} from '@shn/shared-kernel';
import { ErrorCode } from '@shn/error-catalog';
import {
  type ScopeDefinition,
  calculateCanonicalScopeSha256,
  intersectPortRanges,
  intersectScopes,
} from '../../dist/index.js';

describe('Scope Composition & Sealing (Pure Unit Tests)', () => {
  const orgId = createOrganizationId(generateUUIDv7()).value;
  const wsId = createWorkspaceId(generateUUIDv7()).value;

  function makeSampleScope(overrides: Partial<ScopeDefinition> = {}): ScopeDefinition {
    const id = createScopeId(generateUUIDv7()).value;
    const base = {
      id,
      workspaceId: wsId,
      organizationId: orgId,
      name: 'Sample Scope',
      inclusions: {
        cidrs: ['10.0.0.0/16'],
        hostnames: ['*.example.com'],
        urls: ['https://example.com/api'],
        resources: ['res:db-1'],
      },
      exclusions: {
        cidrs: ['10.0.99.0/24'],
        hostnames: ['admin.example.com'],
        urls: [],
        resources: [],
      },
      allowedActions: ['read', 'scan'],
      disallowedActions: ['admin'],
      portRanges: [{ start: 80, end: 443 }],
      validFrom: '2026-01-01T00:00:00.000Z' as IsoTimestamp,
      validUntil: '2026-12-31T23:59:59.000Z' as IsoTimestamp,
      scopeSha256: '',
      status: 'active' as const,
      version: 1,
      ...overrides,
    };

    const scopeSha256 = calculateCanonicalScopeSha256(base);
    return { ...base, scopeSha256 };
  }

  describe('Cryptographic SHA-256 Scope Sealing', () => {
    it('should generate identical SHA-256 hash regardless of inclusion/action array ordering', () => {
      const scopeA = makeSampleScope({
        inclusions: {
          cidrs: ['10.0.0.0/16', '192.168.1.0/24'],
          hostnames: ['b.example.com', 'a.example.com'],
        },
        allowedActions: ['scan', 'read'],
      });

      const scopeB = makeSampleScope({
        inclusions: {
          cidrs: ['192.168.1.0/24', '10.0.0.0/16'],
          hostnames: ['a.example.com', 'b.example.com'],
        },
        allowedActions: ['read', 'scan'],
      });

      assert.strictEqual(scopeA.scopeSha256, scopeB.scopeSha256);
      assert.strictEqual(scopeA.scopeSha256.length, 64);
    });

    it('should generate different SHA-256 hash when any boundary changes', () => {
      const scopeBase = makeSampleScope();
      const scopeModified = makeSampleScope({
        inclusions: {
          cidrs: ['10.0.0.0/16', '10.1.0.0/16'],
        },
      });

      assert.notStrictEqual(scopeBase.scopeSha256, scopeModified.scopeSha256);
    });
  });

  describe('Port Range Intersection', () => {
    it('should compute overlapping port range interval', () => {
      const parent = [{ start: 80, end: 443 }];
      const child = [{ start: 400, end: 8080 }];
      const intersected = intersectPortRanges(parent, child);

      assert.deepStrictEqual(intersected, [{ start: 400, end: 443 }]);
    });

    it('should return empty list when port intervals do not overlap', () => {
      const parent = [{ start: 80, end: 80 }];
      const child = [{ start: 443, end: 443 }];
      const intersected = intersectPortRanges(parent, child);

      assert.deepStrictEqual(intersected, []);
    });

    it('should merge adjacent/overlapping intervals in result', () => {
      const parent = [{ start: 1, end: 1000 }];
      const child = [
        { start: 80, end: 90 },
        { start: 91, end: 100 },
      ];
      const intersected = intersectPortRanges(parent, child);

      assert.deepStrictEqual(intersected, [{ start: 80, end: 100 }]);
    });
  });

  describe('Downward-Narrowing Scope Intersection', () => {
    it('should intersect inclusions and union exclusions', () => {
      const parent = makeSampleScope({
        inclusions: {
          cidrs: ['10.0.0.0/16'],
          hostnames: ['*.example.com'],
          urls: ['https://example.com/api'],
        },
        exclusions: {
          cidrs: ['10.0.1.0/24'],
        },
        allowedActions: ['read', 'scan', 'probe'],
        portRanges: [{ start: 80, end: 443 }],
      });

      const child = makeSampleScope({
        inclusions: {
          cidrs: ['10.0.2.0/24', '192.168.1.0/24'], // 192.168.1.0 is outside parent!
          hostnames: ['api.example.com', 'evil.com'],  // evil.com is outside parent!
          urls: ['https://example.com/api/v1', 'https://other.com/api'],
        },
        exclusions: {
          cidrs: ['10.0.2.50/32'],
        },
        allowedActions: ['scan', 'admin'], // admin is not allowed by parent!
        portRanges: [{ start: 443, end: 8443 }],
      });

      const res = intersectScopes(parent, child);
      assert.strictEqual(res.isOk, true);
      const intersected = res.value;

      // Inclusions: only items within parent bounds survive
      assert.deepStrictEqual(intersected.inclusions.cidrs, ['10.0.2.0/24']);
      assert.deepStrictEqual(intersected.inclusions.hostnames, ['api.example.com']);
      assert.deepStrictEqual(intersected.inclusions.urls, ['https://example.com/api/v1']);

      // Exclusions: union of both parent and child exclusions
      assert.ok(intersected.exclusions.cidrs?.includes('10.0.1.0/24'));
      assert.ok(intersected.exclusions.cidrs?.includes('10.0.2.50/32'));

      // Allowed actions: intersection only
      assert.deepStrictEqual(intersected.allowedActions, ['scan']);

      // Ports: intersection
      assert.deepStrictEqual(intersected.portRanges, [{ start: 443, end: 443 }]);
    });

    it('should narrow temporal validity window to [max(start), min(end)]', () => {
      const parent = makeSampleScope({
        validFrom: '2026-02-01T00:00:00.000Z' as IsoTimestamp,
        validUntil: '2026-11-01T00:00:00.000Z' as IsoTimestamp,
      });

      const child = makeSampleScope({
        validFrom: '2026-03-01T00:00:00.000Z' as IsoTimestamp,
        validUntil: '2026-10-01T00:00:00.000Z' as IsoTimestamp,
      });

      const res = intersectScopes(parent, child);
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.validFrom, '2026-03-01T00:00:00.000Z');
      assert.strictEqual(res.value.validUntil, '2026-10-01T00:00:00.000Z');
    });

    it('should fail closed when temporal windows do not overlap', () => {
      const parent = makeSampleScope({
        validFrom: '2026-01-01T00:00:00.000Z' as IsoTimestamp,
        validUntil: '2026-03-01T00:00:00.000Z' as IsoTimestamp,
      });

      const child = makeSampleScope({
        validFrom: '2026-04-01T00:00:00.000Z' as IsoTimestamp,
        validUntil: '2026-06-01T00:00:00.000Z' as IsoTimestamp,
      });

      const res = intersectScopes(parent, child);
      assert.strictEqual(res.isErr, true);
      assert.strictEqual(res.error.error_code, ErrorCode.SCOPE_WINDOW_CLOSED);
    });

    it('should fail closed when attempting cross-organization scope intersection', () => {
      const parent = makeSampleScope();
      const otherOrgId = createOrganizationId(generateUUIDv7()).value;
      const child = makeSampleScope({ organizationId: otherOrgId });

      const res = intersectScopes(parent, child);
      assert.strictEqual(res.isErr, true);
      assert.strictEqual(res.error.error_code, ErrorCode.AUTH_CROSS_ORG_DENIED);
    });

    it('should fail closed when attempting cross-workspace scope intersection', () => {
      const parent = makeSampleScope();
      const otherWsId = createWorkspaceId(generateUUIDv7()).value;
      const child = makeSampleScope({ workspaceId: otherWsId });

      const res = intersectScopes(parent, child);
      assert.strictEqual(res.isErr, true);
      assert.strictEqual(res.error.error_code, ErrorCode.AUTH_CROSS_WORKSPACE_DENIED);
    });
  });
});
