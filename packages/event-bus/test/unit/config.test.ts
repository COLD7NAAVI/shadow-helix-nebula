/**
 * Shadow : Helix Nebula (SHN) — Event Bus Configuration Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseEventBusConfig,
  loadEventBusConfigFromEnv,
} from '../../dist/index.js';

describe('Event Bus Configuration (Pure Unit Tests)', () => {
  it('should parse valid event bus configuration with default values', () => {
    const result = parseEventBusConfig({});
    assert.ok(result.isOk);
    const config = result.value;
    assert.equal(config.pollingIntervalMs, 100);
    assert.equal(config.batchSize, 25);
    assert.equal(config.maxConcurrency, 10);
    assert.equal(config.leaseDurationMs, 30000);
    assert.equal(config.maxAttempts, 5);
    assert.equal(config.initialRetryDelayMs, 1000);
    assert.equal(config.maxRetryDelayMs, 60000);
    assert.equal(config.retryMultiplier, 2.0);
    assert.equal(config.retryJitter, true);
    assert.equal(config.deduplicationTtlHours, 24);
    assert.equal(config.gracefulShutdownTimeoutMs, 5000);
  });

  it('should accept valid custom configuration values', () => {
    const result = parseEventBusConfig({
      pollingIntervalMs: 250,
      batchSize: 50,
      maxConcurrency: 20,
      leaseDurationMs: 45000,
      maxAttempts: 3,
      initialRetryDelayMs: 500,
      maxRetryDelayMs: 30000,
      retryMultiplier: 1.5,
      retryJitter: false,
      deduplicationTtlHours: 48,
      gracefulShutdownTimeoutMs: 10000,
    });

    assert.ok(result.isOk);
    const config = result.value;
    assert.equal(config.pollingIntervalMs, 250);
    assert.equal(config.batchSize, 50);
    assert.equal(config.maxConcurrency, 20);
    assert.equal(config.leaseDurationMs, 45000);
    assert.equal(config.maxAttempts, 3);
    assert.equal(config.initialRetryDelayMs, 500);
    assert.equal(config.maxRetryDelayMs, 30000);
    assert.equal(config.retryMultiplier, 1.5);
    assert.equal(config.retryJitter, false);
    assert.equal(config.deduplicationTtlHours, 48);
    assert.equal(config.gracefulShutdownTimeoutMs, 10000);
  });

  it('should reject invalid configuration bounds fail-closed', () => {
    // Non-object
    assert.ok(parseEventBusConfig(null).isErr);
    assert.ok(parseEventBusConfig('not an object').isErr);

    // Out of bounds values
    const result = parseEventBusConfig({
      pollingIntervalMs: 5, // min is 10
      batchSize: 1000, // max is 500
      maxConcurrency: 0, // min is 1
      maxAttempts: 50, // max is 20
      retryMultiplier: 0.5, // min is 1.1
    });

    assert.ok(result.isErr);
    assert.equal(result.error.error_code, 'ERR_INVALID_PAYLOAD_SCHEMA');
    const paramNames = result.error.invalid_params?.map((p) => p.name) ?? [];
    assert.ok(paramNames.includes('pollingIntervalMs'));
    assert.ok(paramNames.includes('batchSize'));
    assert.ok(paramNames.includes('maxConcurrency'));
    assert.ok(paramNames.includes('maxAttempts'));
    assert.ok(paramNames.includes('retryMultiplier'));
  });

  it('should load event bus configuration from environment variables with proper precedence', () => {
    const customEnv = {
      SHN_EVENT_POLL_INTERVAL_MS: '300',
      SHN_EVENT_BATCH_SIZE: '100',
      SHN_EVENT_MAX_CONCURRENCY: '15',
      SHN_EVENT_LEASE_DURATION_MS: '60000',
      SHN_EVENT_MAX_ATTEMPTS: '4',
      SHN_EVENT_INITIAL_RETRY_DELAY_MS: '2000',
      SHN_EVENT_MAX_RETRY_DELAY_MS: '120000',
      SHN_EVENT_RETRY_MULTIPLIER: '2.5',
      SHN_EVENT_RETRY_JITTER: 'false',
      SHN_EVENT_DEDUP_TTL_HOURS: '72',
      SHN_EVENT_SHUTDOWN_TIMEOUT_MS: '8000',
    };

    const result = loadEventBusConfigFromEnv(customEnv);
    assert.ok(result.isOk);
    const config = result.value;
    assert.equal(config.pollingIntervalMs, 300);
    assert.equal(config.batchSize, 100);
    assert.equal(config.maxConcurrency, 15);
    assert.equal(config.leaseDurationMs, 60000);
    assert.equal(config.maxAttempts, 4);
    assert.equal(config.initialRetryDelayMs, 2000);
    assert.equal(config.maxRetryDelayMs, 120000);
    assert.equal(config.retryMultiplier, 2.5);
    assert.equal(config.retryJitter, false);
    assert.equal(config.deduplicationTtlHours, 72);
    assert.equal(config.gracefulShutdownTimeoutMs, 8000);
  });
});
