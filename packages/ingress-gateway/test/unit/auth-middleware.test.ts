/**
 * Shadow : Helix Nebula (SHN) — Auth Middleware Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateUUIDv7,
  createWorkspaceId,
} from '@shn/shared-kernel';
import { SecurityContextSigner } from '@shn/auth-rbac';
import { createAuthMiddleware, requirePermission } from '../../dist/index.js';
import type { IngressRequest, IngressResponse } from '../../dist/index.js';

describe('Auth & RBAC Middleware (Unit Tests)', () => {
  const secretKey = 'test-secret-key-32-bytes-minimum!';
  const signer = new SecurityContextSigner(secretKey);
  const authMiddleware = createAuthMiddleware({ signer });
  const workspaceId = createWorkspaceId(generateUUIDv7())._unsafeUnwrap ? createWorkspaceId(generateUUIDv7()).value : generateUUIDv7() as any;

  function createReq(authHeader?: string): IngressRequest {
    return {
      raw: {} as any,
      method: 'GET',
      url: '/api/v1/workspaces',
      path: '/api/v1/workspaces',
      query: {},
      params: {},
      headers: authHeader ? { authorization: authHeader } : {},
      body: undefined,
      correlationId: 'c-1',
      requestId: 'r-1',
      traceId: 't-1',
      clientIp: '127.0.0.1',
    };
  }

  function createRes(): { res: IngressResponse; getStatus: () => number; getBody: () => any } {
    let status = 200;
    let body: any = null;
    const res: IngressResponse = {
      raw: {} as any,
      status(c) {
        status = c;
        return this;
      },
      setHeader() {
        return this;
      },
      json(p) {
        body = p;
      },
      text(p) {
        body = p;
      },
      problem(pd) {
        status = pd.status;
        body = pd;
      },
      empty() {},
    };
    return { res, getStatus: () => status, getBody: () => body };
  }

  it('should reject requests without Authorization header with 401', async () => {
    const req = createReq();
    const { res, getStatus, getBody } = createRes();
    let calledNext = false;

    await authMiddleware(req, res, async () => {
      calledNext = true;
    });

    assert.strictEqual(calledNext, false);
    assert.strictEqual(getStatus(), 401);
    assert.strictEqual(getBody().error_code, 'ERR_AUTH_UNAUTHENTICATED');
  });

  it('should verify valid SecurityContextToken base64 bearer token and set req.securityContext', async () => {
    const tokenClaims = signer.createToken({
      subjectId: generateUUIDv7(),
      workspaceId,
      roles: ['OPERATOR'],
      permissionMask: 0x01 | 0x02,
      ttlSeconds: 300,
    });
    const base64Token = Buffer.from(JSON.stringify(tokenClaims), 'utf8').toString('base64');
    const req = createReq(`Bearer ${base64Token}`);
    const { res, getStatus } = createRes();
    let calledNext = false;

    await authMiddleware(req, res, async () => {
      calledNext = true;
    });

    assert.strictEqual(calledNext, true);
    assert.strictEqual(getStatus(), 200);
    assert.strictEqual(req.securityContext !== undefined, true);
    assert.strictEqual(req.securityContext?.roles[0], 'OPERATOR');
  });

  it('requirePermission should allow when bitmask matches and reject with 403 when lacking', async () => {
    const checkRead = requirePermission(0x01); // Read required
    const checkAdmin = requirePermission(0x80); // Admin required

    const req = createReq();
    req.securityContext = {
      subject_id: generateUUIDv7(),
      subject_type: 'OPERATOR',
      workspace_id: workspaceId,
      roles: ['ANALYST'],
      permission_mask: 0x01, // Only read
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 100000).toISOString(),
      signature: 'valid',
    };

    const { res: res1, getStatus: getStatus1 } = createRes();
    let readCalled = false;
    await checkRead(req, res1, async () => {
      readCalled = true;
    });
    assert.strictEqual(readCalled, true);

    const { res: res2, getStatus: getStatus2, getBody: getBody2 } = createRes();
    let adminCalled = false;
    await checkAdmin(req, res2, async () => {
      adminCalled = true;
    });
    assert.strictEqual(adminCalled, false);
    assert.strictEqual(getStatus2(), 403);
    assert.strictEqual(getBody2().error_code, 'ERR_AUTH_FORBIDDEN');
  });
});
