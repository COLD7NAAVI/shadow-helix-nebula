import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createCanonicalEventEnvelope,
  createEventId,
  createWorkspaceId,
  createCorrelationId,
  createCausationId,
  nowIso,
  isSecurityContextExpired,
  isScopeWindowActive,
  type TraceId,
  type ScopeEnvelope,
} from '../dist/index.js';

describe('Canonical Event Envelope & Security Contracts', () => {
  it('should assemble a complete frozen Canonical Event Envelope (API-INV-06)', () => {
    const eventId = createEventId().unwrapOr('' as any);
    const workspaceId = createWorkspaceId().unwrapOr('' as any);
    const correlationId = createCorrelationId().unwrapOr('' as any);
    const causationId = createCausationId().unwrapOr('' as any);
    const occurredAt = nowIso();

    const envelope = createCanonicalEventEnvelope({
      eventId,
      eventType: 'scan.host.discovered',
      schemaVersion: '1.0.0',
      occurredAt,
      producer: {
        module_name: 'mod_workflow',
        node_id: 'node-alpha-1',
        environment: 'testing',
        build_version: '0.1.0',
      },
      workspaceId,
      correlationId,
      causationId,
      traceId: 'trace-9876543210' as TraceId,
      authorizationContext: {
        subject_id: 'usr-001',
        subject_type: 'OPERATOR',
        workspace_id: workspaceId,
        roles: ['OPERATOR_ADMIN'],
        permission_mask: 0b1111,
        issued_at: occurredAt,
        expires_at: occurredAt,
        signature: 'sig-hmac-sha256-demo',
      },
      scopeReference: {
        scope_id: 'scp-001',
        scope_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      payload: {
        host: '192.168.1.100',
        open_ports: [80, 443],
      },
      integrity: {
        algorithm: 'HMAC-SHA256',
        signature: 'envelope-sig-hash',
        key_id: 'key-2026-09',
      },
    });

    assert.equal(envelope.event_type, 'scan.host.discovered');
    assert.equal(envelope.workspace_id, workspaceId);
    assert.equal(envelope.payload.host, '192.168.1.100');
    assert.equal(Object.isFrozen(envelope), true);
    assert.equal(Object.isFrozen(envelope.producer), true);
  });

  it('should correctly evaluate SecurityContext expiration', () => {
    const pastTime = new Date(Date.now() - 60000).toISOString() as any;
    const futureTime = new Date(Date.now() + 60000).toISOString() as any;

    const expiredToken = {
      expires_at: pastTime,
    } as any;
    assert.equal(isSecurityContextExpired(expiredToken), true);

    const activeToken = {
      expires_at: futureTime,
    } as any;
    assert.equal(isSecurityContextExpired(activeToken), false);
  });

  it('should evaluate ScopeEnvelope active operational window', () => {
    const scope: ScopeEnvelope = {
      scope_id: 'scp-1',
      workspace_id: 'wks-1' as any,
      target_inclusions: [],
      target_exclusions: [],
      port_ranges: [],
      valid_from: new Date(Date.now() - 10000).toISOString() as any,
      valid_until: new Date(Date.now() + 10000).toISOString() as any,
      scope_sha256: 'abc123hash',
    };

    assert.equal(isScopeWindowActive(scope), true);

    const expiredScope: ScopeEnvelope = {
      ...scope,
      valid_until: new Date(Date.now() - 5000).toISOString() as any,
    };
    assert.equal(isScopeWindowActive(expiredScope), false);
  });
});
