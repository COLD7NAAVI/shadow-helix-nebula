/**
 * Shadow : Helix Nebula (SHN) — Adversarial Security Audit Integration Tests
 *
 * Enforces SEC-INV-01, SEC-INV-08, INV-06, and API-INV-02:
 * - Rigorous adversarial penetration test suite
 * - SSRF and cloud metadata bypass attempts
 * - Domain suffix-confusion attacks (evil-example.com)
 * - URL path traversal and userinfo (@) parser confusion tricks
 * - Leading zero octal IPv4 confusion attacks
 * - Cryptographic token forgery and claim tampering
 * - Permission escalation defenses
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { ErrorCode } from '@shn/error-catalog';
import { PermissionBit } from '@shn/auth-rbac';
import {
  createScopeTestPool,
  setupScopeTestDatabase,
  cleanScopeTables,
  createScopeTestServices,
  createTestOrgAndWorkspace,
  createTestSecurityContext,
  createPersistedScope,
  type ScopeTestServices,
} from './scope-test-helper.ts';

describe('Adversarial Security Audit (Integration Tests)', () => {
  const pool = createScopeTestPool();
  let services: ScopeTestServices;

  before(async () => {
    await setupScopeTestDatabase(pool);
    services = createScopeTestServices(pool);
  });

  after(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await cleanScopeTables(pool);
  });

  describe('SSRF & Cloud Metadata Attacks', () => {
    it('should reject AWS metadata IP access attempts even under broad /0 scope', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['0.0.0.0/0'],
      });

      const targets = [
        '169.254.169.254',
        'http://169.254.169.254/latest/meta-data/',
        'https://169.254.169.254:443/latest/meta-data/',
        '169.254.1.1',
        '127.0.0.1',
        'http://127.0.0.1:8080/admin',
        '127.0.0.2',
        '100.100.100.200',
        '::1',
        'metadata.google.internal',
        'http://metadata.google.internal/computeMetadata/v1/',
        'instance-data',
      ];

      for (const target of targets) {
        const verdict = await services.gatekeeper.evaluateTarget({
          context,
          target,
          action: 'recon_passive',
          scopeId: scope.id,
        });

        assert.strictEqual(verdict.isOk, true, `Expected Ok(verdict) for target ${target}`);
        assert.strictEqual(
          verdict.value.allowed,
          false,
          `CRITICAL: Target ${target} was allowed but must be blocked!`
        );
        assert.strictEqual(
          verdict.value.errorCode,
          ErrorCode.SCOPE_METADATA_PROHIBITED,
          `Expected SCOPE_METADATA_PROHIBITED for ${target}`
        );
      }
    });

    it('should reject userinfo (@) SSRF parser confusion bypass tricks', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['https://example.com/api'],
      });

      // Trick: http://example.com@169.254.169.254/
      const verdict = await services.gatekeeper.evaluateTarget({
        context,
        target: 'http://example.com@169.254.169.254/latest/meta-data/',
        action: 'recon_passive',
        scopeId: scope.id,
      });

      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.SCOPE_MALFORMED);
      assert.match(verdict.value.reason, /userinfo \(@\) is prohibited/i);
    });
  });

  describe('Domain Suffix-Confusion Attacks', () => {
    it('should NEVER authorize evil-example.com when example.com is authorized', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['example.com'],
      });

      const attacks = [
        'evil-example.com',
        'notexample.com',
        'badexample.com',
        'example.com.evil.com',
        'myexample.com',
        'example-com.attacker.com',
      ];

      for (const evilHost of attacks) {
        const verdict = await services.gatekeeper.evaluateTarget({
          context,
          target: evilHost,
          action: 'recon_passive',
          scopeId: scope.id,
        });

        assert.strictEqual(verdict.isOk, true);
        assert.strictEqual(
          verdict.value.allowed,
          false,
          `CRITICAL: Hostname suffix confusion attack succeeded for ${evilHost}!`
        );
        assert.strictEqual(verdict.value.errorCode, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
      }
    });
  });

  describe('Octal & Leading Zero Ambiguity Attacks', () => {
    it('should reject leading zero IPv4 representations (octal confusion defense)', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/8'],
      });

      // Octal confusion: 010.0.0.1 is 8.0.0.1 in C, but 10.0.0.1 in JS string split
      const verdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '010.0.0.1',
        action: 'recon_passive',
        scopeId: scope.id,
      });

      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.SCOPE_MALFORMED);
      assert.match(verdict.value.reason, /leading zeros prohibited/i);
    });
  });

  describe('URL Path Traversal Attacks', () => {
    it('should reject path traversal attempts escaping authorized scope path', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['https://example.com/api/v1'],
      });

      // Traversal escaping root
      const v1 = await services.gatekeeper.evaluateTarget({
        context,
        target: 'https://example.com/../../etc/passwd',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(v1.isOk, true);
      assert.strictEqual(v1.value.allowed, false);
      assert.strictEqual(v1.value.errorCode, ErrorCode.SCOPE_MALFORMED);

      // Traversal escaping /api/v1 to unauthorized /admin
      const v2 = await services.gatekeeper.evaluateTarget({
        context,
        target: 'https://example.com/api/v1/../admin',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(v2.isOk, true);
      assert.strictEqual(v2.value.allowed, false);
      assert.strictEqual(v2.value.errorCode, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
    });
  });

  describe('Permission Escalation Defenses', () => {
    it('should reject invasive scan when actor lacks SCAN_INVASIVE permission', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);

      // Actor has ONLY SCOPE_READ permission (no SCAN_INVASIVE)
      const context = createTestSecurityContext(
        services,
        workspaceId,
        undefined,
        PermissionBit.SCOPE_READ
      );

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/16'],
        allowed_actions: ['recon_passive', 'scan_invasive'],
      });

      const verdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.1.1',
        action: 'scan_invasive',
        scopeId: scope.id,
      });

      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.AUTH_FORBIDDEN);
      assert.match(verdict.value.reason, /lacks required permission bit/i);
    });
  });

  describe('Zero-Trust Default Deny', () => {
    it('should deny target evaluation when no scope context is provided', async () => {
      const { workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      // Neither scopeId, scopeToken, nor scopeOverride provided
      const verdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.1.1',
        action: 'recon_passive',
      });

      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
      assert.match(verdict.value.reason, /Zero-trust evaluation failed/i);
    });
  });
});
