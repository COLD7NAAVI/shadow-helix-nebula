/**
 * Shadow : Helix Nebula (SHN) — OpenAPI 3.1 Unit Test Suite
 *
 * Verifies that OpenAPI 3.1 specification conforms to API-FST-001,
 * incorporates RFC 7807 schemas, nominal identifiers, and endpoint definitions.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { OPENAPI_3_1_SPEC, OpenApiController } from '../../dist/index.js';
import type { IngressRequest, IngressResponse } from '../../dist/index.js';

describe('OpenAPI 3.1 Specification & Controller (Unit Tests)', () => {
  it('should define a valid OpenAPI 3.1.0 document structure', () => {
    assert.equal(OPENAPI_3_1_SPEC.openapi, '3.1.0');
    assert.ok(OPENAPI_3_1_SPEC.info.title.includes('Shadow : Helix Nebula'));
    assert.equal(OPENAPI_3_1_SPEC.info.version, '1.0.0');
    assert.ok(Array.isArray(OPENAPI_3_1_SPEC.tags) && OPENAPI_3_1_SPEC.tags.length >= 8);
  });

  it('should specify all canonical Phase 1 REST endpoints', () => {
    const paths = OPENAPI_3_1_SPEC.paths as Record<string, any>;
    assert.ok(paths['/health/live'], 'Must include /health/live');
    assert.ok(paths['/health/ready'], 'Must include /health/ready');
    assert.ok(paths['/metrics'], 'Must include /metrics');
    assert.ok(paths['/api/v1/auth/register'], 'Must include /api/v1/auth/register');
    assert.ok(paths['/api/v1/auth/login'], 'Must include /api/v1/auth/login');
    assert.ok(paths['/api/v1/auth/me'], 'Must include /api/v1/auth/me');
    assert.ok(paths['/api/v1/workspaces'], 'Must include /api/v1/workspaces');
    assert.ok(paths['/api/v1/workspaces/{workspaceId}'], 'Must include /api/v1/workspaces/{workspaceId}');
    assert.ok(paths['/api/v1/workspaces/{workspaceId}/scopes'], 'Must include scopes endpoint');
    assert.ok(paths['/api/v1/workspaces/{workspaceId}/assets'], 'Must include assets endpoint');
    assert.ok(paths['/api/v1/workspaces/{workspaceId}/findings'], 'Must include findings endpoint');
    assert.ok(paths['/api/v1/capabilities'], 'Must include capabilities catalog');
    assert.ok(paths['/api/v1/workspaces/{workspaceId}/executions'], 'Must include executions endpoint');
    assert.ok(paths['/api/v1/workspaces/{workspaceId}/audit'], 'Must include audit endpoint');
    assert.ok(paths['/api/v1/workspaces/{workspaceId}/events/stream'], 'Must include SSE stream endpoint');
  });

  it('should define RFC 7807 Problem Details and Security Schemes in components', () => {
    const components = OPENAPI_3_1_SPEC.components;
    assert.ok(components.securitySchemes.bearerAuth, 'Must define bearerAuth');
    assert.ok(components.schemas.ProblemDetails, 'Must define ProblemDetails');
    assert.ok(components.responses.UnauthorizedProblem, 'Must define UnauthorizedProblem');
    assert.ok(components.responses.ForbiddenProblem, 'Must define ForbiddenProblem');
    assert.ok(components.responses.NotFoundProblem, 'Must define NotFoundProblem');
  });

  it('OpenApiController should serialize OpenAPI JSON spec with correct headers', async () => {
    const ctrl = new OpenApiController();
    let setHeaders: Record<string, string> = {};
    let statusCode = 0;
    let jsonPayload: any = null;

    const mockRes = {
      setHeader(k: string, v: string) {
        setHeaders[k.toLowerCase()] = v;
        return this;
      },
      status(c: number) {
        statusCode = c;
        return this;
      },
      json(p: any) {
        jsonPayload = p;
      },
    } as unknown as IngressResponse;

    const mockReq = {} as IngressRequest;

    await ctrl.getSpec(mockReq, mockRes);

    assert.equal(statusCode, 200);
    assert.ok(setHeaders['content-type'].includes('application/json'));
    assert.equal(jsonPayload.openapi, '3.1.0');
    assert.ok(jsonPayload.paths['/api/v1/workspaces']);
  });
});
