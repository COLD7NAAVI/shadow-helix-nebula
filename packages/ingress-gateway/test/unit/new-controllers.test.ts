/**
 * Shadow : Helix Nebula (SHN) — Unit Tests for AI, Reports, Preferences, Graph & Threat Intel Controllers
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  AiController,
  ReportController,
  PreferencesController,
  GraphController,
  ThreatIntelController,
} from '../../dist/index.js';
import type { IngressRequest, IngressResponse } from '../../dist/index.js';

function createMockResponse(): { res: IngressResponse; getStatus: () => number; getBody: () => any; getHeaders: () => Record<string, string> } {
  let statusCode = 200;
  let bodyData: any = null;
  const headers: Record<string, string> = {};

  const res: IngressResponse = {
    raw: {} as any,
    status(code: number) {
      statusCode = code;
      return this;
    },
    setHeader(name: string, value: string | number | readonly string[]) {
      headers[name.toLowerCase()] = String(value);
      return this;
    },
    json(payload: unknown) {
      bodyData = payload;
    },
    text(payload: string, contentType = 'text/plain') {
      bodyData = payload;
      headers['content-type'] = contentType;
    },
    problem(pd: any) {
      bodyData = pd;
    },
    empty(code = 204) {
      statusCode = code;
    },
  };

  return {
    res,
    getStatus: () => statusCode,
    getBody: () => bodyData,
    getHeaders: () => headers,
  };
}

function createMockRequest(overrides: Partial<IngressRequest> = {}): IngressRequest {
  return {
    raw: {} as any,
    method: 'GET',
    url: '/test',
    path: '/test',
    query: {},
    params: {},
    headers: {},
    body: {},
    correlationId: 'corr-123',
    requestId: 'req-123',
    traceId: 'trace-123',
    clientIp: '127.0.0.1',
    workspaceId: '01a139c6-0daa-743e-b94e-062286674386' as any,
    actor: {
      id: '01a139c6-0daa-743e-b94e-062286674387' as any,
      organizationId: '01a139c6-0daa-743e-b94e-062286674388' as any,
      email: 'operator@shn.sovereign',
      roles: ['ORG_ADMIN'],
      permissionMask: 0xffffffff,
    },
    ...overrides,
  };
}

describe('AI Controller (Unit Tests)', () => {
  it('tests connection for LOCAL_HEURISTIC provider successfully', async () => {
    const ctrl = new AiController({});
    const req = createMockRequest({
      body: { providerType: 'LOCAL_HEURISTIC' },
    });
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.testConnection(req, res);
    assert.strictEqual(getStatus(), 200);
    const body = getBody();
    assert.strictEqual(body.success, true);
    assert.match(body.message, /heuristic/i);
  });

  it('generates chat responses with security context and action recommendations', async () => {
    const ctrl = new AiController({});
    const req = createMockRequest({
      body: { prompt: 'Can you help me run a port scan on our target?' },
    });
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.chat(req, res);
    assert.strictEqual(getStatus(), 200);
    const body = getBody();
    assert.ok(body.reply);
    assert.ok(Array.isArray(body.proposedActions));
    assert.ok(body.proposedActions.length > 0);
  });
});

describe('Report Controller (Unit Tests)', () => {
  it('generates an assessment report snapshot and computes SHA-256 digest', async () => {
    const ctrl = new ReportController({});
    const req = createMockRequest({
      body: { title: 'Q4 Sovereign Penetration Test' },
    });
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.generate(req, res);
    assert.strictEqual(getStatus(), 201);
    const body = getBody();
    assert.strictEqual(body.title, 'Q4 Sovereign Penetration Test');
    assert.ok(body.contentSha256);
    assert.strictEqual(body.contentSha256.length, 64);
  });
});

describe('Preferences Controller (Unit Tests)', () => {
  it('returns default signature settings when repository is empty', async () => {
    const ctrl = new PreferencesController({});
    const req = createMockRequest();
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.get(req, res);
    assert.strictEqual(getStatus(), 200);
    const body = getBody();
    assert.strictEqual(body.theme, 'cyber-operations');
    assert.strictEqual(body.accentColor, 'cyan');
  });
});

describe('Graph Controller (Unit Tests)', () => {
  it('returns valid graph nodes and edges for workspace exploration', async () => {
    const ctrl = new GraphController({});
    const req = createMockRequest();
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.get(req, res);
    assert.strictEqual(getStatus(), 200);
    const body = getBody();
    assert.ok(Array.isArray(body.nodes));
    assert.ok(Array.isArray(body.edges));
    assert.ok(body.nodes.some((n: any) => n.type === 'WORKSPACE'));
  });
});

describe('Threat Intel Controller (Unit Tests)', () => {
  it('retrieves known CVE details and EPSS scores', async () => {
    const ctrl = new ThreatIntelController({});
    const req = createMockRequest({
      params: { cveId: 'CVE-2023-4863' },
    });
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.getCve(req, res);
    assert.strictEqual(getStatus(), 200);
    const body = getBody();
    assert.strictEqual(body.cveId, 'CVE-2023-4863');
    assert.ok(body.cvssScore > 9.0);
    assert.ok(body.epssScore > 0.9);
  });

  it('delivers threat intelligence feed with provenance', async () => {
    const ctrl = new ThreatIntelController({});
    const req = createMockRequest();
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.getFeed(req, res);
    assert.strictEqual(getStatus(), 200);
    const body = getBody();
    assert.ok(Array.isArray(body.feed));
    assert.ok(body.provider);
  });

  it('provides geographic threat intelligence with assessment and external datasets', async () => {
    const ctrl = new ThreatIntelController({});
    const req = createMockRequest();
    const { res, getStatus, getBody } = createMockResponse();

    await ctrl.getGeoIntel(req, res);
    assert.strictEqual(getStatus(), 200);
    const body = getBody();
    assert.ok(Array.isArray(body.assessmentMarkers));
    assert.ok(Array.isArray(body.externalThreatPoints));
    assert.ok(body.metadata?.legend);
  });
});
