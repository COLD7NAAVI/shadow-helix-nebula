/**
 * Shadow : Helix Nebula (SHN) — RBAC Evaluation & Boundary Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  SecurityContextSigner,
  PermissionBit,
  AuthorizationService,
} from '../../dist/index.js';
import type { WorkspaceId } from '@shn/shared-kernel';

const SECRET_KEY = 'unit-test-rbac-evaluation-secret-key-32b!!';
const WORKSPACE_1 = '00000000-0000-7000-8000-000000000001' as WorkspaceId;
const WORKSPACE_2 = '00000000-0000-7000-8000-000000000002' as WorkspaceId;

describe('Centralized RBAC Evaluation & Tenant Isolation (Pure Unit Tests)', () => {
  const signer = new SecurityContextSigner(SECRET_KEY);

  // Minimal mock repositories for pure unit evaluation tests
  const mockAuthService = new AuthorizationService({
    userRepo: {} as any,
    credentialRepo: {} as any,
    sessionRepo: {} as any,
    roleRepo: {} as any,
    permissionRepo: {} as any,
    signer,
  });

  it('should grant access when required permission bit is present in token bitmask', () => {
    const token = signer.createToken({
      subjectId: '00000000-0000-7000-8000-000000000010',
      workspaceId: WORKSPACE_1,
      roles: ['OPERATOR'],
      permissionMask: PermissionBit.SCOPE_READ | PermissionBit.WORKFLOW_EXECUTE,
    });

    const res = mockAuthService.evaluatePermission(token, PermissionBit.SCOPE_READ, WORKSPACE_1);
    assert.strictEqual(res.isOk, true);
    if (res.isOk) {
      assert.strictEqual(res.value, true);
    }
  });

  it('should deny access (403 AUTH_FORBIDDEN) when required permission bit is absent', () => {
    const token = signer.createToken({
      subjectId: '00000000-0000-7000-8000-000000000010',
      workspaceId: WORKSPACE_1,
      roles: ['OBSERVER'],
      permissionMask: PermissionBit.SCOPE_READ, // Missing SCAN_INVASIVE
    });

    const res = mockAuthService.evaluatePermission(token, PermissionBit.SCAN_INVASIVE, WORKSPACE_1);
    assert.strictEqual(res.isOk, false);
    if (!res.isOk) {
      assert.strictEqual(res.error.error_code, 'ERR_AUTH_FORBIDDEN');
      assert.strictEqual(res.error.status, 403);
    }
  });

  it('should reject cross-workspace access attempts fail-closed (404 AUTH_CROSS_WORKSPACE_DENIED)', () => {
    const token = signer.createToken({
      subjectId: '00000000-0000-7000-8000-000000000010',
      workspaceId: WORKSPACE_1, // Token belongs to Workspace 1
      roles: ['WORKSPACE_ADMIN'],
      permissionMask: PermissionBit.SCOPE_ADMIN,
    });

    // Attempting action on Workspace 2
    const res = mockAuthService.evaluatePermission(token, PermissionBit.SCOPE_ADMIN, WORKSPACE_2);
    assert.strictEqual(res.isOk, false);
    if (!res.isOk) {
      assert.strictEqual(res.error.error_code, 'ERR_AUTH_CROSS_WORKSPACE_DENIED');
      assert.strictEqual(res.error.status, 404);
    }
  });

  it('should enforce multi-tenant isolation via enforceTenantIsolation', () => {
    const token = signer.createToken({
      subjectId: '00000000-0000-7000-8000-000000000010',
      workspaceId: WORKSPACE_1,
      roles: ['WORKSPACE_ADMIN'],
      permissionMask: PermissionBit.SCOPE_ADMIN,
    });

    const validRes = mockAuthService.enforceTenantIsolation(token, '00000000-0000-7000-8000-000000000099', WORKSPACE_1);
    assert.strictEqual(validRes.isOk, true);

    const crossRes = mockAuthService.enforceTenantIsolation(token, '00000000-0000-7000-8000-000000000099', WORKSPACE_2);
    assert.strictEqual(crossRes.isOk, false);
    if (!crossRes.isOk) {
      assert.strictEqual(crossRes.error.error_code, 'ERR_AUTH_CROSS_WORKSPACE_DENIED');
    }
  });
});
