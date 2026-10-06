import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { PermissionBit } from '@shn/auth-rbac';
import { setupSupervisorTestEnv, type SupervisorTestEnvironment } from './supervisor-test-helper.ts';

describe('Execution Security & Adversarial Defenses (Integration)', () => {
  let env: SupervisorTestEnvironment;

  before(async () => {
    env = await setupSupervisorTestEnv('shn_test_supervisor_security');
  });

  after(async () => {
    await env.cleanup();
  });

  it('should reject unauthenticated request with tampered token signature fail-closed', async () => {
    const validToken = env.mintToken();
    const tamperedToken = {
      ...validToken,
      signature: 'deadbeef' + validToken.signature.substring(8),
    };

    const req = env.createRequest({
      securityContext: tamperedToken,
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_AUTH_TOKEN_INVALID');
  });

  it('should reject expired security context tokens fail-closed', async () => {
    const expiredToken = env.authSigner.createToken({
      subjectId: env.userId as any,
      workspaceId: env.workspaceId as any,
      roles: ['OPERATOR'],
      permissionMask: PermissionBit.SCAN_INVASIVE | PermissionBit.SCOPE_READ,
      ttlSeconds: -10, // already expired
    });

    const req = env.createRequest({
      securityContext: expiredToken,
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_AUTH_TOKEN_EXPIRED');
  });

  it('should reject cross-workspace execution attempt (workspace tenancy violation)', async () => {
    // Token minted for otherWorkspaceId, but request targets workspaceId
    const crossToken = env.mintToken({
      workspace_id: env.otherWorkspaceId,
    });

    const req = env.createRequest({
      workspaceId: env.workspaceId,
      securityContext: crossToken,
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_AUTH_CROSS_WORKSPACE_DENIED');
  });

  it('should reject actor subject mismatch fail-closed', async () => {
    const req = env.createRequest({
      requestedBy: '01955ef2-2253-7c5e-85a7-999999999999' as any, // does not match token subject
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_AUTH_FORBIDDEN');
  });

  it('should reject workspace belonging to foreign organization', async () => {
    const req = env.createRequest({
      organizationId: env.otherOrgId, // workspace actually belongs to orgId
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_AUTH_CROSS_WORKSPACE_DENIED');
  });

  it('should reject execution when actor lacks required action permission bit', async () => {
    // Mint token with only SCOPE_READ, lacking SCAN_INVASIVE
    const readOnlyToken = env.mintToken({
      permission_mask: PermissionBit.SCOPE_READ,
    });

    const req = env.createRequest({
      action: 'scan', // requires SCAN_INVASIVE
      securityContext: readOnlyToken,
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_AUTH_FORBIDDEN');
  });

  it('should reject out-of-bounds target via ScopeGatekeeper and record REJECTED state', async () => {
    const req = env.createRequest({
      target: '10.50.50.50', // Out of bounds (scope only allows 192.168.1.0/24)
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_SCOPE_VIOLATION_OUT_OF_BOUNDS');

    // Verify record saved in REJECTED state
    const records = await env.pool.query(
      `SELECT state, target FROM execution.executions WHERE target = '10.50.50.50';`
    );
    assert.equal(records.rows.length, 1);
    assert.equal(records.rows[0].state, 'REJECTED');
  });

  it('should permanently reject cloud metadata targets fail-closed (SEC-INV-08)', async () => {
    const req = env.createRequest({
      target: 'http://169.254.169.254/latest/meta-data',
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isErr, true);
    assert.equal(res.error.error_code, 'ERR_SCOPE_METADATA_PROHIBITED');
  });

  it('should guarantee zero host secret leakage into sandboxed worker subprocess (INV-14)', async () => {
    // Set simulated host secrets
    const origAuthKey = process.env['SHN_AUTH_SIGNING_KEY'];
    const origDbPass = process.env['POSTGRES_PASSWORD'];
    process.env['SHN_AUTH_SIGNING_KEY'] = 'HOST_CONTROL_PLANE_SECRET_KEY';
    process.env['POSTGRES_PASSWORD'] = 'HOST_DATABASE_PASSWORD_KEY';

    try {
      // Subprocess checks its own process.env and reports any findings
      const inspectScript = `
        const leaked = [];
        for (const [k, v] of Object.entries(process.env)) {
          if (v && (v.includes('HOST_CONTROL_PLANE') || v.includes('HOST_DATABASE'))) {
            leaked.push(k + '=' + v);
          }
        }
        if (leaked.length > 0) {
          process.stderr.write("LEAKED: " + leaked.join(', ') + "\\n");
          process.exit(1);
        }
        process.stdout.write("OK: zero host secrets detected\\n");
      `;

      const req = env.createRequest({
        command: {
          executable: process.execPath,
          args: ['-e', inspectScript],
        },
      });

      const res = await env.supervisor.execute(req);
      assert.equal(res.isOk, true);

      const result = res.unwrapOr(null as any);
      assert.equal(result.state, 'SUCCEEDED');
      assert.ok(result.stdout.includes('OK: zero host secrets detected'));
    } finally {
      if (origAuthKey) process.env['SHN_AUTH_SIGNING_KEY'] = origAuthKey;
      else delete process.env['SHN_AUTH_SIGNING_KEY'];
      if (origDbPass) process.env['POSTGRES_PASSWORD'] = origDbPass;
      else delete process.env['POSTGRES_PASSWORD'];
    }
  });
});
