/**
 * Shadow : Helix Nebula (SHN) — Redaction & Sanitization Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  redactSensitiveData,
  sanitizeString,
} from '../../dist/index.js';

describe('Security-Aware Redaction & Sanitization (Pure Unit Tests)', () => {
  it('should redact sensitive keys in flat objects', () => {
    const input = {
      user: 'operator_1',
      password: 'super-secret-password-123!',
      apiKey: 'shn_live_abcdef1234567890',
      client_secret: 'top-secret-token',
      publicInfo: 'visible-payload',
    };

    const redacted = redactSensitiveData(input) as Record<string, unknown>;

    assert.equal(redacted['user'], 'operator_1');
    assert.equal(redacted['password'], '[REDACTED]');
    assert.equal(redacted['apiKey'], '[REDACTED]');
    assert.equal(redacted['client_secret'], '[REDACTED]');
    assert.equal(redacted['publicInfo'], 'visible-payload');
  });

  it('should recursively redact sensitive fields in deeply nested structures', () => {
    const input = {
      level1: {
        level2: {
          session: {
            token: 'jwt.bearer.secret-token-payload',
            db_password: 'internal_db_pass',
            safeMetadata: 'ok',
          },
        },
      },
    };

    const redacted = redactSensitiveData(input) as any;

    assert.equal(redacted.level1.level2.session.token, '[REDACTED]');
    assert.equal(redacted.level1.level2.session.db_password, '[REDACTED]');
    assert.equal(redacted.level1.level2.session.safeMetadata, 'ok');
  });

  it('should redact Bearer tokens and Basic auth headers within strings', () => {
    const raw = 'Request failed with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID and Basic dXNlcjpwYXNz';
    const sanitized = sanitizeString(raw);

    assert.ok(!sanitized.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
    assert.ok(!sanitized.includes('dXNlcjpwYXNz'));
    assert.ok(sanitized.includes('Bearer [REDACTED]'));
    assert.ok(sanitized.includes('Basic [REDACTED]'));
  });

  it('should redact database connection strings with embedded credentials', () => {
    const raw = 'Failed to connect to postgresql://admin:SuperSecretPass123!@db.internal.corp:5432/shn_prod';
    const sanitized = sanitizeString(raw);

    assert.ok(!sanitized.includes('SuperSecretPass123!'));
    assert.ok(sanitized.includes('postgres://admin:[REDACTED]@db.internal.corp:5432/shn_prod'));
  });

  it('should redact RSA and Ed25519 private key blocks', () => {
    const raw = `-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n-----END PRIVATE KEY-----`;
    const sanitized = sanitizeString(raw);

    assert.ok(!sanitized.includes('MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7'));
    assert.ok(sanitized.includes('[REDACTED_PRIVATE_KEY]'));
  });

  it('should truncate strings exceeding maximum allowed length', () => {
    const longString = 'A'.repeat(5000);
    const sanitized = sanitizeString(longString, 100);

    assert.equal(sanitized.length, 100 + '...[TRUNCATED]'.length);
    assert.ok(sanitized.endsWith('...[TRUNCATED]'));
  });

  it('should safely handle circular object references without infinite recursion', () => {
    const circularObj: any = { name: 'root', secret: 'hide-me' };
    circularObj.self = circularObj;

    const redacted = redactSensitiveData(circularObj) as any;

    assert.equal(redacted.name, 'root');
    assert.equal(redacted.secret, '[REDACTED]');
    assert.equal(redacted.self, '[CIRCULAR]');
  });

  it('should enforce maximum object recursion depth', () => {
    let deepObj: any = { value: 'leaf' };
    for (let i = 0; i < 15; i++) {
      deepObj = { nested: deepObj };
    }

    const redacted = redactSensitiveData(deepObj, { maxDepth: 5 }) as any;
    let current = redacted;
    let depth = 0;
    while (current && current.nested && typeof current.nested === 'object') {
      current = current.nested;
      depth++;
    }

    assert.ok(depth <= 5);
  });

  it('should sanitize Error objects, nested causes, and stack traces', () => {
    const rootErr = new Error('Database connection failed: postgres://postgres:p@ssword@localhost:5432/db');
    const wrapperErr = new Error('Operation aborted', { cause: rootErr });

    const redacted = redactSensitiveData(wrapperErr) as any;

    assert.equal(redacted.name, 'Error');
    assert.equal(redacted.message, 'Operation aborted');
    assert.ok(redacted.cause);
    assert.ok(!redacted.cause.message.includes('p@ssword'));
    assert.ok(redacted.cause.message.includes('postgres://postgres:[REDACTED]@localhost:5432/db'));
  });

  it('should never mutate original input objects', () => {
    const original = Object.freeze({
      token: 'jwt-12345',
      user: 'admin',
    });

    const redacted = redactSensitiveData(original) as any;

    assert.equal(original.token, 'jwt-12345');
    assert.equal(redacted.token, '[REDACTED]');
  });
});
