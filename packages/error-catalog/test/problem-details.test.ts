import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorCode, createProblemDetails } from '../dist/index.js';

describe('Error Catalog & RFC 7807 Problem Details', () => {
  it('should construct compliant ProblemDetails with correct status and title', () => {
    const problem = createProblemDetails({
      errorCode: ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS,
      detail: 'Target IP 10.0.0.1 is not in authorized scope whitelist.',
      instance: '/api/v1/workspaces/wks-1/runs',
      correlationId: 'c-123456',
    });

    assert.equal(problem.status, 403);
    assert.equal(problem.title, 'Target Scope Violation');
    assert.equal(problem.error_code, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
    assert.equal(problem.type, 'https://api.shadow-helix-nebula.io/errors/ERR_SCOPE_VIOLATION_OUT_OF_BOUNDS');
    assert.equal(problem.correlation_id, 'c-123456');
    assert.ok(problem.timestamp);
    assert.equal(problem.invalid_params, undefined);
  });

  it('should include invalid_params when validation errors are provided', () => {
    const problem = createProblemDetails({
      errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
      detail: 'Validation failed for CIDR input.',
      instance: '/api/v1/workspaces/wks-1/scopes',
      correlationId: 'c-7890',
      invalidParams: [
        { name: 'target', reason: 'Invalid CIDR mask /33', value: '192.168.1.1/33' },
      ],
    });

    assert.equal(problem.status, 400);
    assert.equal(problem.invalid_params?.length, 1);
    assert.equal(problem.invalid_params?.[0]?.name, 'target');
  });

  it('should allow custom HTTP status override when explicitly needed', () => {
    const problem = createProblemDetails({
      errorCode: ErrorCode.INTERNAL_FAULT,
      detail: 'Upstream gateway unresponsive',
      instance: '/api/v1/runs',
      correlationId: 'c-999',
      customStatus: 503,
    });

    assert.equal(problem.status, 503);
  });
});
