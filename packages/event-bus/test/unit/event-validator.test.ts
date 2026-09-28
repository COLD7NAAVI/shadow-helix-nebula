/**
 * Shadow : Helix Nebula (SHN) — Canonical Event Envelope Validator Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateUUIDv7,
  nowIso,
} from '@shn/shared-kernel';
import { validateCanonicalEventEnvelope } from '../../dist/index.js';

function createValidEnvelopeFixture(): any {
  return {
    event_id: generateUUIDv7(),
    event_type: 'scan.host.discovered',
    schema_version: '1.2.0',
    occurred_at: nowIso(),
    producer: {
      module_name: 'mod_scanner',
      node_id: 'scanner-node-1',
      environment: 'production',
      build_version: '0.1.0',
    },
    workspace_id: generateUUIDv7(),
    correlation_id: generateUUIDv7(),
    causation_id: generateUUIDv7(),
    trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
    authorization_context: {
      principal_id: 'usr-1',
      token_id: generateUUIDv7(),
      roles: ['operator'],
      signature: 'valid-sig',
      expires_at: nowIso(),
    },
    scope_reference: {
      scope_id: 'scope-1',
      scope_sha256: 'a'.repeat(64),
    },
    payload: {
      target_ip: '10.0.0.1',
      ports: [80, 443],
    },
    integrity: {
      algorithm: 'HMAC-SHA256',
      signature: 'sig-1234',
      key_id: 'key-1',
    },
  };
}

describe('Canonical Event Envelope Validator (Pure Unit Tests)', () => {
  it('should validate a compliant CanonicalEventEnvelope successfully (API-INV-06)', () => {
    const fixture = createValidEnvelopeFixture();
    const result = validateCanonicalEventEnvelope(fixture);

    assert.equal(result.isValid, true);
    if (result.isValid) {
      assert.equal(result.value.event_id, fixture.event_id);
      assert.equal(result.value.event_type, 'scan.host.discovered');
      assert.equal(result.value.schema_version, '1.2.0');
    }
  });

  it('should reject non-object or null envelopes fail-closed', () => {
    assert.equal(validateCanonicalEventEnvelope(null).isValid, false);
    assert.equal(validateCanonicalEventEnvelope(undefined).isValid, false);
    assert.equal(validateCanonicalEventEnvelope('string-event').isValid, false);
    assert.equal(validateCanonicalEventEnvelope(12345).isValid, false);
  });

  it('should reject malformed or non-UUID event_id, workspace_id, correlation_id, and causation_id', () => {
    const fixture = createValidEnvelopeFixture();
    fixture.event_id = 'not-a-uuid';
    fixture.workspace_id = 'invalid-workspace';
    fixture.correlation_id = '12345';
    fixture.causation_id = 'invalid-causation';

    const result = validateCanonicalEventEnvelope(fixture);
    assert.equal(result.isValid, false);
    if (!result.isValid) {
      assert.equal(result.problem.error_code, 'ERR_INVALID_PAYLOAD_SCHEMA');
      assert.ok(result.problem.invalid_params && result.problem.invalid_params.length >= 4);
    }
  });

  it('should reject non-dot-notated event_type', () => {
    const fixture = createValidEnvelopeFixture();
    fixture.event_type = 'singleword';

    const result = validateCanonicalEventEnvelope(fixture);
    assert.equal(result.isValid, false);
    if (!result.isValid) {
      assert.ok(result.problem.invalid_params?.some(p => p.name === 'event_type'));
    }
  });

  it('should reject invalid SemVer schema_version', () => {
    const fixture = createValidEnvelopeFixture();
    fixture.schema_version = 'v1';

    const result = validateCanonicalEventEnvelope(fixture);
    assert.equal(result.isValid, false);
    if (!result.isValid) {
      assert.ok(result.problem.invalid_params?.some(p => p.name === 'schema_version'));
    }
  });

  it('should reject malformed or missing scope_reference SHA-256 hash', () => {
    const fixture = createValidEnvelopeFixture();
    fixture.scope_reference = {
      scope_id: 'scp-1',
      scope_sha256: 'short-invalid-hash',
    };

    const result = validateCanonicalEventEnvelope(fixture);
    assert.equal(result.isValid, false);
    if (!result.isValid) {
      assert.ok(result.problem.invalid_params?.some(p => p.name === 'scope_reference.scope_sha256'));
    }
  });
});
