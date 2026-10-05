/**
 * Shadow : Helix Nebula (SHN) — Tenancy Boundary Validator Pure Unit Tests
 *
 * Enforces SEC-INV-05, INV-01, and INV-19.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  type SecurityContextToken,
  type IsoTimestamp,
} from '@shn/shared-kernel';
import { ErrorCode } from '@shn/error-catalog';
import { TenancyValidator } from '../../dist/index.js';

describe('Tenancy Boundary Validator (Pure Unit Tests)', () => {
  const validator = new TenancyValidator();

  describe('Identifier Validation', () => {
    it('should validate compliant UUIDv7 organization and workspace identifiers', () => {
      const orgId = generateUUIDv7();
      const wsId = generateUUIDv7();

      const res = validator.validateIdentifiers(orgId, wsId);
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.organizationId, orgId);
      assert.strictEqual(res.value.workspaceId, wsId);
    });

    it('should fail closed when organizationId is missing or invalid', () => {
      const wsId = generateUUIDv7();

      assert.strictEqual(validator.validateIdentifiers(undefined, wsId).isErr, true);
      assert.strictEqual(validator.validateIdentifiers('', wsId).isErr, true);
      assert.strictEqual(validator.validateIdentifiers('invalid-org-uuid', wsId).isErr, true);
      assert.strictEqual(
        validator.validateIdentifiers('not-a-uuid', wsId).error.error_code,
        ErrorCode.INVALID_PAYLOAD_SCHEMA
      );
    });

    it('should fail closed when workspaceId is missing or invalid', () => {
      const orgId = generateUUIDv7();

      assert.strictEqual(validator.validateIdentifiers(orgId, undefined).isErr, true);
      assert.strictEqual(validator.validateIdentifiers(orgId, '').isErr, true);
      assert.strictEqual(validator.validateIdentifiers(orgId, '12345').isErr, true);
      assert.strictEqual(
        validator.validateIdentifiers(orgId, 'bad-ws').error.error_code,
        ErrorCode.INVALID_PAYLOAD_SCHEMA
      );
    });
  });

  describe('Workspace Isolation Assertion', () => {
    function makeContext(wsId: string): SecurityContextToken {
      return {
        subject_id: generateUUIDv7(),
        subject_type: 'OPERATOR',
        workspace_id: createWorkspaceId(wsId).value,
        roles: ['OPERATOR'],
        permission_mask: 1,
        issued_at: new Date().toISOString() as IsoTimestamp,
        expires_at: new Date(Date.now() + 900000).toISOString() as IsoTimestamp,
        signature: 'valid-sig',
      };
    }

    it('should succeed when context workspace matches resource workspace', () => {
      const wsId = createWorkspaceId(generateUUIDv7()).value;
      const ctx = makeContext(wsId);

      const res = validator.assertWorkspaceMatch(ctx, wsId);
      assert.strictEqual(res.isOk, true);
    });

    it('should fail closed with AUTH_CROSS_WORKSPACE_DENIED on workspace mismatch', () => {
      const ctxWs = createWorkspaceId(generateUUIDv7()).value;
      const resWs = createWorkspaceId(generateUUIDv7()).value;
      const ctx = makeContext(ctxWs);

      const res = validator.assertWorkspaceMatch(ctx, resWs);
      assert.strictEqual(res.isErr, true);
      assert.strictEqual(res.error.error_code, ErrorCode.AUTH_CROSS_WORKSPACE_DENIED);
    });
  });

  describe('Database-backed Tenancy Hierarchy Verification', () => {
    it('should verify workspace ownership against mocked repository', async () => {
      const orgId = createOrganizationId(generateUUIDv7()).value;
      const wsId = createWorkspaceId(generateUUIDv7()).value;

      const mockWorkspaceRepo = {
        findById: async (id: string) => {
          if (id === wsId) {
            return {
              id: wsId,
              organization_id: orgId,
              name: 'Test WS',
              slug: 'test-ws',
              environment: 'production',
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
          }
          return null;
        },
      } as any;

      const otherOrg = createOrganizationId(generateUUIDv7()).value;

      const mockOrgRepo = {
        findById: async (id: string) => {
          if (id === orgId || id === otherOrg) {
            return {
              id,
              name: 'Test Org',
              slug: 'test-org',
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
          }
          return null;
        },
      } as any;

      const v = new TenancyValidator(mockWorkspaceRepo, mockOrgRepo);

      // Valid ownership
      const validRes = await v.verifyWorkspaceBelongsToOrg(wsId, orgId);
      assert.strictEqual(validRes.isOk, true);

      // Other org (cross-tenant mismatch)
      const mismatchRes = await v.verifyWorkspaceBelongsToOrg(wsId, otherOrg);
      assert.strictEqual(mismatchRes.isErr, true);
      assert.strictEqual(mismatchRes.error.error_code, ErrorCode.AUTH_CROSS_WORKSPACE_DENIED);

      // Non-existent workspace
      const nonExistentWs = createWorkspaceId(generateUUIDv7()).value;
      const notFoundRes = await v.verifyWorkspaceBelongsToOrg(nonExistentWs, orgId);
      assert.strictEqual(notFoundRes.isErr, true);
      assert.strictEqual(notFoundRes.error.error_code, ErrorCode.STORAGE_NOT_FOUND);
    });
  });
});
