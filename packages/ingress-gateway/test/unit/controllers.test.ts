/**
 * Shadow : Helix Nebula (SHN) — Ingress Gateway Controller Unit Tests
 *
 * Tests for ExecutionController (list), ScopeController, and AuditController.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateUUIDv7,
  createWorkspaceId,
  createOrganizationId,
  createUserId,
  type WorkspaceId,
  type OrganizationId,
  type UserId,
} from '@shn/shared-kernel';
import {
  ExecutionController,
  ScopeController,
  AuditController,
} from '../../dist/index.js';
import type { IngressRequest, IngressResponse } from '../../dist/index.js';

function createMockResponse(): { res: IngressResponse; getStatus: () => number; getBody: () => unknown } {
  let statusCode = 200;
  let bodyPayload: unknown = null;

  const res: IngressResponse = {
    raw: {} as any,
    status(code: number) {
      statusCode = code;
      return this;
    },
    setHeader() {
      return this;
    },
    json(payload: unknown) {
      bodyPayload = payload;
    },
    text(payload: string) {
      bodyPayload = payload;
    },
    problem(pd) {
      statusCode = pd.status;
      bodyPayload = pd;
    },
    empty(code) {
      statusCode = code ?? statusCode;
    },
  };

  return {
    res,
    getStatus: () => statusCode,
    getBody: () => bodyPayload,
  };
}

describe('Ingress Gateway Controllers (Pure Unit Tests)', () => {
  const wIdRes = createWorkspaceId(generateUUIDv7());
  const workspaceId: WorkspaceId = wIdRes.isOk ? wIdRes.value : (generateUUIDv7() as any);
  const oIdRes = createOrganizationId(generateUUIDv7());
  const orgId: OrganizationId = oIdRes.isOk ? oIdRes.value : (generateUUIDv7() as any);
  const uIdRes = createUserId(generateUUIDv7());
  const userId: UserId = uIdRes.isOk ? uIdRes.value : (generateUUIDv7() as any);


  describe('ExecutionController.list', () => {
    it('should list executions for authorized workspace', async () => {
      const mockRecords = [
        {
          id: generateUUIDv7(),
          workspace_id: workspaceId,
          action: 'PORT_SCAN',
          target: '192.168.1.1',
          state: 'COMPLETED',
        },
      ];

      const mockRepo: any = {
        listByWorkspace: async (wId: string, limit: number, offset: number) => {
          assert.equal(wId, workspaceId);
          assert.equal(limit, 10);
          assert.equal(offset, 0);
          return mockRecords;
        },
      };

      const ctrl = new ExecutionController({
        dispatcher: {} as any,
        executionRepo: mockRepo,
      });

      const { res, getStatus, getBody } = createMockResponse();
      const req: IngressRequest = {
        raw: {} as any,
        method: 'GET',
        url: `/api/v1/workspaces/${workspaceId}/executions?limit=10&offset=0`,
        path: `/api/v1/workspaces/${workspaceId}/executions`,
        query: { limit: '10', offset: '0' },
        params: { workspaceId },
        headers: {},
        workspaceId,
        correlationId: 'test-corr-1',
        requestId: 'test-req-1',
        traceId: 'test-trace-1',
        clientIp: '127.0.0.1',
      };

      await ctrl.list(req, res);
      assert.equal(getStatus(), 200);
      assert.deepEqual(getBody(), mockRecords);
    });

    it('should return 501 problem details if execution repo not configured', async () => {
      const ctrl = new ExecutionController({
        dispatcher: {} as any,
      });

      const { res, getStatus, getBody } = createMockResponse();
      const req: IngressRequest = {
        raw: {} as any,
        method: 'GET',
        url: `/api/v1/workspaces/${workspaceId}/executions`,
        path: `/api/v1/workspaces/${workspaceId}/executions`,
        query: {},
        params: { workspaceId },
        headers: {},
        workspaceId,
        correlationId: 'test-corr-2',
        requestId: 'test-req-2',
        traceId: 'test-trace-2',
        clientIp: '127.0.0.1',
      };

      await ctrl.list(req, res);
      assert.equal(getStatus(), 501);
      const body = getBody() as any;
      assert.equal(body.status, 501);
      assert.equal(body.title, 'Requested Resource Not Found');
    });

  });

  describe('ScopeController', () => {
    it('should list scopes for workspace', async () => {
      const mockScopes = [
        {
          id: generateUUIDv7(),
          workspace_id: workspaceId,
          name: 'Primary Scope',
          status: 'ACTIVE',
        },
      ];

      const mockScopeRepo: any = {
        listByWorkspace: async (wId: string) => {
          assert.equal(wId, workspaceId);
          return mockScopes;
        },
      };

      const ctrl = new ScopeController({ scopeRepo: mockScopeRepo });
      const { res, getStatus, getBody } = createMockResponse();
      const req: IngressRequest = {
        raw: {} as any,
        method: 'GET',
        url: `/api/v1/workspaces/${workspaceId}/scopes`,
        path: `/api/v1/workspaces/${workspaceId}/scopes`,
        query: {},
        params: { workspaceId },
        headers: {},
        workspaceId,
        correlationId: 'test-corr-3',
        requestId: 'test-req-3',
        traceId: 'test-trace-3',
        clientIp: '127.0.0.1',
      };

      await ctrl.list(req, res);
      assert.equal(getStatus(), 200);
      assert.deepEqual(getBody(), mockScopes);
    });

    it('should create new scope boundary', async () => {
      const mockCreated = {
        id: generateUUIDv7(),
        workspace_id: workspaceId,
        name: 'Target Network Range',
        status: 'ACTIVE',
      };

      const mockScopeRepo: any = {
        createScope: async (input: any) => {
          assert.equal(input.name, 'Target Network Range');
          assert.equal(input.workspace_id, workspaceId);
          return mockCreated;
        },
      };

      const ctrl = new ScopeController({ scopeRepo: mockScopeRepo });
      const { res, getStatus, getBody } = createMockResponse();
      const req: IngressRequest = {
        raw: {} as any,
        method: 'POST',
        url: `/api/v1/workspaces/${workspaceId}/scopes`,
        path: `/api/v1/workspaces/${workspaceId}/scopes`,
        query: {},
        params: { workspaceId },
        headers: {},
        body: {
          name: 'Target Network Range',
          description: 'Authorized test range',
          inclusions: [{ type: 'CIDR', value: '10.0.0.0/24' }],
        },
        workspaceId,
        actor: {
          id: userId,
          organizationId: orgId,
          roles: ['ORG_ADMIN'],
        },
        correlationId: 'test-corr-4',
        requestId: 'test-req-4',
        traceId: 'test-trace-4',
        clientIp: '127.0.0.1',
      };

      await ctrl.create(req, res);
      assert.equal(getStatus(), 201);
      assert.deepEqual(getBody(), mockCreated);
    });
  });

  describe('AuditController', () => {
    it('should list audit events for workspace', async () => {
      const mockEvents = [
        {
          event_id: generateUUIDv7(),
          event_type: 'execution.completed',
          workspace_id: workspaceId,
          occurred_at: new Date().toISOString(),
        },
      ];

      const mockAuditRepo: any = {
        listByWorkspace: async (wId: string, limit: number) => {
          assert.equal(wId, workspaceId);
          assert.equal(limit, 25);
          return mockEvents;
        },
      };

      const ctrl = new AuditController({ auditRepo: mockAuditRepo });
      const { res, getStatus, getBody } = createMockResponse();
      const req: IngressRequest = {
        raw: {} as any,
        method: 'GET',
        url: `/api/v1/workspaces/${workspaceId}/audit?limit=25`,
        path: `/api/v1/workspaces/${workspaceId}/audit`,
        query: { limit: '25' },
        params: { workspaceId },
        headers: {},
        workspaceId,
        correlationId: 'test-corr-5',
        requestId: 'test-req-5',
        traceId: 'test-trace-5',
        clientIp: '127.0.0.1',
      };

      await ctrl.list(req, res);
      assert.equal(getStatus(), 200);
      assert.deepEqual(getBody(), mockEvents);
    });
  });
});
