/**
 * Shadow : Helix Nebula (SHN) — Telemetry Configuration Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseTelemetryConfig,
  loadTelemetryConfigFromEnv,
} from '../../dist/index.js';

describe('Telemetry Configuration (Pure Unit Tests)', () => {
  it('should parse valid telemetry configuration with default values', () => {
    const result = parseTelemetryConfig({
      serviceName: 'shn-scanner',
      environment: 'production',
      logLevel: 'debug',
      logFormat: 'json',
    });

    assert.ok(result.isOk);
    const cfg = result.value;
    assert.equal(cfg.serviceName, 'shn-scanner');
    assert.equal(cfg.environment, 'production');
    assert.equal(cfg.logLevel, 'debug');
    assert.equal(cfg.logFormat, 'json');
    assert.equal(cfg.enableRedaction, true);
    assert.equal(cfg.traceSamplingRatio, 1.0);
    assert.equal(cfg.shutdownTimeoutMs, 5000);
  });

  it('should reject invalid configuration fields fail-closed', () => {
    const result = parseTelemetryConfig({
      environment: 'invalid-env',
      logFormat: 'xml',
      traceSamplingRatio: 2.5, // > 1.0
      shutdownTimeoutMs: 50,   // < 100
    });

    assert.ok(result.isErr);
    const err = result.error;
    assert.equal(err.error_code, 'ERR_INVALID_PAYLOAD_SCHEMA');
    assert.ok(err.invalid_params && err.invalid_params.length >= 3);
  });

  it('should load telemetry configuration from environment variables with proper precedence', () => {
    const env = {
      SHN_SERVICE_NAME: 'shn-worker-node',
      NODE_ENV: 'staging',
      SHN_LOG_LEVEL: 'warn',
      SHN_LOG_FORMAT: 'pretty',
      SHN_TRACE_SAMPLING_RATIO: '0.5',
      SHN_SHUTDOWN_TIMEOUT_MS: '8000',
    };

    const result = loadTelemetryConfigFromEnv(env);
    assert.ok(result.isOk);
    const cfg = result.value;
    assert.equal(cfg.serviceName, 'shn-worker-node');
    assert.equal(cfg.environment, 'staging');
    assert.equal(cfg.logLevel, 'warn');
    assert.equal(cfg.logFormat, 'pretty');
    assert.equal(cfg.traceSamplingRatio, 0.5);
    assert.equal(cfg.shutdownTimeoutMs, 8000);
  });
});
