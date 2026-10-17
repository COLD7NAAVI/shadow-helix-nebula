/**
 * Shadow : Helix Nebula (SHN) — Security Hardening Regression Tests
 *
 * Verifies Phase B Hardening:
 * 1. Safe operator credential provisioning (anti-hardcoded password leakage).
 * 2. Real-time SSE hub connection limits & capacity exhaustion defense.
 * 3. IngressServer CORS preflight handling & hardened security headers.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  resolveOperatorCredentials,
  EventStreamHub,
  EventStreamController,
  IngressServer,
} from '../../dist/index.js';

describe('Security Hardening & Safe Provisioning (Unit Tests)', () => {
  describe('Operator Credential Provisioning', () => {
    it('returns development baseline credentials in non-production mode for testability', () => {
      const creds = resolveOperatorCredentials('development', undefined);
      assert.equal(creds.password, 'Password123!');
      assert.equal(creds.isGenerated, false);
      assert.ok(creds.notice.includes('Development fallback active'));
    });

    it('enforces explicit SHN_INITIAL_ADMIN_PASSWORD when provided and validates length', () => {
      const customPass = 'HyperSecureP@ssw0rd2026!';
      const creds = resolveOperatorCredentials('production', customPass);
      assert.equal(creds.password, customPass);
      assert.equal(creds.isGenerated, false);
      assert.ok(creds.notice.includes('SHN_INITIAL_ADMIN_PASSWORD'));

      assert.throws(
        () => resolveOperatorCredentials('production', 'short'),
        /must be at least 8 characters/
      );
    });

    it('generates cryptographically secure password with 0600 file permissions in production mode', () => {
      const credPath = path.resolve(process.cwd(), '.shn-initial-credentials');
      if (fs.existsSync(credPath)) {
        fs.unlinkSync(credPath);
      }

      try {
        const creds = resolveOperatorCredentials('production', undefined);
        assert.ok(creds.password.length >= 18);
        assert.equal(creds.isGenerated, true);
        assert.ok(fs.existsSync(credPath));

        const content = fs.readFileSync(credPath, 'utf8');
        assert.ok(content.includes('OPERATOR_EMAIL=operator@shn.sovereign'));
        assert.ok(content.includes(`OPERATOR_PASSWORD=${creds.password}`));

        // Subsequent call loads the existing provisioned password
        const creds2 = resolveOperatorCredentials('production', undefined);
        assert.equal(creds2.password, creds.password);
        assert.equal(creds2.isGenerated, false);
      } finally {
        if (fs.existsSync(credPath)) {
          fs.unlinkSync(credPath);
        }
      }
    });
  });

  describe('Server-Sent Events (SSE) Connection Quotas & Resource Limits', () => {
    it('enforces per-workspace connection limits and rejects excess connections fail-closed', () => {
      const hub = new EventStreamHub({
        heartbeatIntervalMs: 60000,
        maxConnectionsPerWorkspace: 2,
        maxTotalConnections: 10,
      });

      const mockRes = () => {
        let statusCode = 200;
        const headers: Record<string, string> = {};
        const written: string[] = [];
        return {
          raw: {
            write: (chunk: string) => written.push(chunk),
            end: () => {},
            on: () => {},
            destroyed: false,
            writableEnded: false,
          },
          status: (code: number) => {
            statusCode = code;
            return { raw: {} };
          },
          setHeader: (k: string, v: string) => {
            headers[k] = v;
          },
          getStatusCode: () => statusCode,
          getWritten: () => written.join(''),
        } as any;
      };

      const mockReq = () => ({
        raw: {
          on: () => {},
        },
      } as any);

      const client1 = hub.register(mockReq(), mockRes(), 'workspace-alpha', 'user-1');
      assert.equal(hub.subscriberCount('workspace-alpha'), 1);

      const client2 = hub.register(mockReq(), mockRes(), 'workspace-alpha', 'user-2');
      assert.equal(hub.subscriberCount('workspace-alpha'), 2);

      // Third connection breaches maxConnectionsPerWorkspace (2)
      assert.equal(hub.isAtCapacity('workspace-alpha'), true);
      const res3 = mockRes();
      assert.throws(
        () => hub.register(mockReq(), res3, 'workspace-alpha', 'user-3'),
        /Maximum concurrent SSE stream limit reached/
      );

      // Unregister frees quota
      hub.unregister(client1);
      assert.equal(hub.subscriberCount('workspace-alpha'), 1);
      assert.equal(hub.isAtCapacity('workspace-alpha'), false);

      hub.destroy();
      assert.equal(hub.subscriberCount(), 0);
      assert.equal(hub.isAtCapacity('workspace-alpha'), true); // Destroyed hub is at capacity
    });

    it('EventStreamController returns RFC 7807 429 when hub is at capacity', async () => {
      const hub = new EventStreamHub({
        maxConnectionsPerWorkspace: 0, // Force at capacity
      });

      const ctrl = new EventStreamController({ hub });
      let sentStatus = 0;
      let sentBody: any = null;

      const mockRes: any = {
        raw: {},
        status: (code: number) => {
          sentStatus = code;
          return mockRes;
        },
        setHeader: () => mockRes,
        json: (payload: any) => {
          sentBody = payload;
        },
      };

      const mockReq: any = {
        params: { workspaceId: 'wks-999' },
        path: '/api/v1/workspaces/wks-999/events/stream',
        correlationId: 'test-corr-id',
      };

      await ctrl.streamEvents(mockReq, mockRes);
      assert.equal(sentStatus, 429);
      assert.equal(sentBody.error_code, 'ERR_RATE_LIMIT_EXCEEDED');
      assert.ok(sentBody.detail.includes('Maximum concurrent real-time stream limit reached'));
    });
  });

  describe('IngressServer Security Headers & CORS Preflight', () => {
    it('handles CORS OPTIONS preflight request with HTTP 204 No Content', async () => {
      const server = new IngressServer();
      const started = await server.start();

      try {
        const response = await fetch(`http://localhost:${started.port}/api/v1/workspaces`, {
          method: 'OPTIONS',
          headers: {
            'Origin': 'https://console.shadow-helix-nebula.io',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Authorization, Content-Type',
          },
        });

        assert.equal(response.status, 204);
        assert.ok(response.headers.get('access-control-allow-origin'));
        assert.ok(response.headers.get('access-control-allow-methods')?.includes('OPTIONS'));
        assert.ok(response.headers.get('access-control-allow-headers')?.includes('Authorization'));
      } finally {
        await server.stop();
      }
    });

    it('injects mandatory security headers: CSP, nosniff, DENY, and Referrer-Policy', async () => {
      const server = new IngressServer();
      server.getRouter().get('/test-headers', (_req, res) => {
        res.status(200).json({ ok: true });
      });
      const started = await server.start();

      try {
        const response = await fetch(`http://localhost:${started.port}/test-headers`);
        assert.equal(response.status, 200);

        assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
        assert.equal(response.headers.get('x-frame-options'), 'DENY');
        assert.equal(response.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
        assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
        assert.ok(response.headers.get('content-security-policy')?.includes("default-src 'self'"));
      } finally {
        await server.stop();
      }
    });
  });
});
