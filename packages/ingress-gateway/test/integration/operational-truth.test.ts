/**
 * Shadow : Helix Nebula (SHN) — Operational Truth Integration Test
 *
 * Verifies that the platform adheres to authoritative operational truth:
 * 1. Default bootstrap provisions ONLY essential system identity (Org, Admin, Roles, 1 Primary Workspace).
 * 2. Operational state begins completely clean (0 assets, 0 findings, 0 executions, 0 scopes).
 * 3. Scope Gatekeeper mechanically enforces default-deny when zero scopes exist.
 * 4. Production invariant: blocks loading demo fixtures in production (NODE_ENV=production).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { startStandaloneServer } from '../../dist/standalone.js';
import { ensureDatabase, createTestPool, resetDatabase } from '../../../data-access/test/test-helper.ts';
import { closeDatabasePool } from '@shn/data-access';

describe('Operational Truth & Zero-Trust State Enforcement', () => {
  it('guarantees clean operational baseline with zero fabricated records on startup', async () => {
    // Ensure demo fixtures flag is NOT set
    delete process.env.SHN_LOAD_DEMO_FIXTURES;
    const testDbName = 'shn_test_operational_truth';
    await ensureDatabase(testDbName);
    const setupPool = createTestPool(testDbName);
    await resetDatabase(setupPool);
    await closeDatabasePool(setupPool);

    const prevDbName = process.env.SHN_DB_NAME;
    process.env.SHN_DB_NAME = testDbName;

    const { server, url } = await startStandaloneServer(8097);

    try {
      const adminEmail = process.env.SHN_INITIAL_ADMIN_EMAIL || 'operator@shn.sovereign';
      const adminPassword = process.env.SHN_INITIAL_ADMIN_PASSWORD || 'Password123!';

      // 1. Authenticate as initial operator
      const loginRes = await fetch(`${url}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: adminEmail,
          password: adminPassword,
        }),
      });
      assert.equal(loginRes.status, 200, 'Operator login must succeed');
      const auth = await loginRes.json();
      assert.ok(auth.token, 'Must receive auth token');

      const headers = {
        'Authorization': `Bearer ${auth.token}`,
        'Content-Type': 'application/json',
      };

      // 2. Verify Workspaces: Only authoritative workspaces (at least primary)
      const wksRes = await fetch(`${url}/api/v1/workspaces`, { headers });
      assert.equal(wksRes.status, 200);
      const workspaces = await wksRes.json();
      assert.ok(Array.isArray(workspaces) && workspaces.length >= 1);
      const wsId = workspaces[0].id;

      // 3. Verify Operational Truth: 0 assets, 0 scopes, 0 findings, 0 executions
      const assetsRes = await fetch(`${url}/api/v1/workspaces/${wsId}/assets`, { headers });
      assert.equal(assetsRes.status, 200);
      const assets = await assetsRes.json();
      assert.equal(assets.length, 0, 'Initial assets must be 0 (no fabricated assets)');

      const scopesRes = await fetch(`${url}/api/v1/workspaces/${wsId}/scopes`, { headers });
      assert.equal(scopesRes.status, 200);
      const scopes = await scopesRes.json();
      assert.equal(scopes.length, 0, 'Initial scopes must be 0 (no fabricated scopes)');

      const findingsRes = await fetch(`${url}/api/v1/workspaces/${wsId}/findings`, { headers });
      assert.equal(findingsRes.status, 200);
      const findings = await findingsRes.json();
      assert.equal(findings.length, 0, 'Initial findings must be 0 (no fabricated findings)');

      const execsRes = await fetch(`${url}/api/v1/workspaces/${wsId}/executions`, { headers });
      assert.equal(execsRes.status, 200);
      const execs = await execsRes.json();
      assert.equal(execs.length, 0, 'Initial executions must be 0 (no fabricated executions)');

      // 4. Verify Zero-Trust Default Deny: Dispatching execution without scope must fail
      const dispatchRes = await fetch(`${url}/api/v1/workspaces/${wsId}/executions`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          capabilityId: 'shn://capabilities/network/port-scan',
          target: '192.168.1.1',
          action: 'network:scan',
        }),
      });
      assert.ok(
        dispatchRes.status === 400 || dispatchRes.status === 403,
        `Execution without active authorized scope must be rejected, got HTTP ${dispatchRes.status}`
      );
    } finally {
      await server.stop();
      if (prevDbName !== undefined) {
        process.env.SHN_DB_NAME = prevDbName;
      } else {
        delete process.env.SHN_DB_NAME;
      }
    }
  });

  it('strictly rejects SHN_LOAD_DEMO_FIXTURES in production mode', async () => {
    const origEnv = process.env.NODE_ENV;
    const origDemo = process.env.SHN_LOAD_DEMO_FIXTURES;
    const origSecret = process.env.SHN_SIGNER_SECRET;

    try {
      process.env.NODE_ENV = 'production';
      process.env.SHN_LOAD_DEMO_FIXTURES = 'true';
      process.env.SHN_SIGNER_SECRET = 'production-super-secure-key-32b-length-ok!!';

      await assert.rejects(
        async () => {
          await startStandaloneServer(8096);
        },
        {
          name: 'Error',
          message: /Production Security Invariant Violation: Demonstration fixtures cannot be loaded in production/,
        }
      );
    } finally {
      process.env.NODE_ENV = origEnv;
      if (origDemo !== undefined) {
        process.env.SHN_LOAD_DEMO_FIXTURES = origDemo;
      } else {
        delete process.env.SHN_LOAD_DEMO_FIXTURES;
      }
      if (origSecret !== undefined) {
        process.env.SHN_SIGNER_SECRET = origSecret;
      } else {
        delete process.env.SHN_SIGNER_SECRET;
      }
    }
  });

  it('strictly rejects in-memory fallback in production mode when PostgreSQL is unreachable', async () => {
    const origEnv = process.env.NODE_ENV;
    const origSecret = process.env.SHN_SIGNER_SECRET;
    const origDbPort = process.env.SHN_DB_PORT;
    const origTimeout = process.env.SHN_DB_CONNECTION_TIMEOUT_MS;

    try {
      process.env.NODE_ENV = 'production';
      process.env.SHN_SIGNER_SECRET = 'production-super-secure-key-32b-length-ok!!';
      process.env.SHN_DB_PORT = '54399';
      process.env.SHN_DB_CONNECTION_TIMEOUT_MS = '500';

      await assert.rejects(
        async () => {
          await startStandaloneServer(8094);
        },
        {
          name: 'Error',
          message: /Production Security Invariant Violation: PostgreSQL persistence is mandatory in production/,
        }
      );
    } finally {
      process.env.NODE_ENV = origEnv;
      if (origSecret !== undefined) {
        process.env.SHN_SIGNER_SECRET = origSecret;
      } else {
        delete process.env.SHN_SIGNER_SECRET;
      }
      if (origDbPort !== undefined) {
        process.env.SHN_DB_PORT = origDbPort;
      } else {
        delete process.env.SHN_DB_PORT;
      }
      if (origTimeout !== undefined) {
        process.env.SHN_DB_CONNECTION_TIMEOUT_MS = origTimeout;
      } else {
        delete process.env.SHN_DB_CONNECTION_TIMEOUT_MS;
      }
    }
  });

  it('strictly rejects in-memory fallback when SHN_REQUIRE_POSTGRES=true and database is unreachable', async () => {
    const origReq = process.env.SHN_REQUIRE_POSTGRES;
    const origDbPort = process.env.SHN_DB_PORT;
    const origTimeout = process.env.SHN_DB_CONNECTION_TIMEOUT_MS;

    try {
      process.env.SHN_REQUIRE_POSTGRES = 'true';
      process.env.SHN_DB_PORT = '54399';
      process.env.SHN_DB_CONNECTION_TIMEOUT_MS = '500';

      await assert.rejects(
        async () => {
          await startStandaloneServer(8093);
        },
        {
          name: 'Error',
          message: /Persistence Configuration Error: PostgreSQL persistence is required/,
        }
      );
    } finally {
      if (origReq !== undefined) {
        process.env.SHN_REQUIRE_POSTGRES = origReq;
      } else {
        delete process.env.SHN_REQUIRE_POSTGRES;
      }
      if (origDbPort !== undefined) {
        process.env.SHN_DB_PORT = origDbPort;
      } else {
        delete process.env.SHN_DB_PORT;
      }
      if (origTimeout !== undefined) {
        process.env.SHN_DB_CONNECTION_TIMEOUT_MS = origTimeout;
      } else {
        delete process.env.SHN_DB_CONNECTION_TIMEOUT_MS;
      }
    }
  });

  it('strictly rejects in-memory fallback when SHN_PERSISTENCE_ENGINE=postgres and database is unreachable', async () => {
    const origEngine = process.env.SHN_PERSISTENCE_ENGINE;
    const origDbPort = process.env.SHN_DB_PORT;
    const origTimeout = process.env.SHN_DB_CONNECTION_TIMEOUT_MS;

    try {
      process.env.SHN_PERSISTENCE_ENGINE = 'postgres';
      process.env.SHN_DB_PORT = '54399';
      process.env.SHN_DB_CONNECTION_TIMEOUT_MS = '500';

      await assert.rejects(
        async () => {
          await startStandaloneServer(8092);
        },
        {
          name: 'Error',
          message: /Persistence Configuration Error: PostgreSQL persistence is required/,
        }
      );
    } finally {
      if (origEngine !== undefined) {
        process.env.SHN_PERSISTENCE_ENGINE = origEngine;
      } else {
        delete process.env.SHN_PERSISTENCE_ENGINE;
      }
      if (origDbPort !== undefined) {
        process.env.SHN_DB_PORT = origDbPort;
      } else {
        delete process.env.SHN_DB_PORT;
      }
      if (origTimeout !== undefined) {
        process.env.SHN_DB_CONNECTION_TIMEOUT_MS = origTimeout;
      } else {
        delete process.env.SHN_DB_CONNECTION_TIMEOUT_MS;
      }
    }
  });

  it('preserves intentional in-memory execution when SHN_PERSISTENCE_ENGINE=memory', async () => {
    const origEngine = process.env.SHN_PERSISTENCE_ENGINE;

    try {
      process.env.SHN_PERSISTENCE_ENGINE = 'memory';

      const res = await startStandaloneServer(8091);
      try {
        assert.equal(res.isPostgres, false, 'Explicit in-memory persistence must report isPostgres: false');
      } finally {
        await res.server.stop();
      }
    } finally {
      if (origEngine !== undefined) {
        process.env.SHN_PERSISTENCE_ENGINE = origEngine;
      } else {
        delete process.env.SHN_PERSISTENCE_ENGINE;
      }
    }
  });
});
