/**
 * Shadow : Helix Nebula (SHN) — Event Substrate Configuration
 *
 * Implements strict, fail-closed configuration parsing for polling,
 * backpressure, retry policy, and idempotency retention (0.14 Section 16, 17).
 */

import {
  type Result,
  ok,
  err,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
  type InvalidParam,
} from '@shn/error-catalog';

export interface EventBusConfig {
  readonly pollingIntervalMs: number;
  readonly batchSize: number;
  readonly maxConcurrency: number;
  readonly leaseDurationMs: number;
  readonly maxAttempts: number;
  readonly initialRetryDelayMs: number;
  readonly maxRetryDelayMs: number;
  readonly retryMultiplier: number;
  readonly retryJitter: boolean;
  readonly deduplicationTtlHours: number;
  readonly gracefulShutdownTimeoutMs: number;
}

export function parseEventBusConfig(input: unknown): Result<EventBusConfig, ProblemDetails> {
  const invalidParams: InvalidParam[] = [];

  if (!input || typeof input !== 'object') {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Event bus configuration must be a non-null object',
        instance: '/config/event-bus',
        correlationId: 'config.eventbus.parser',
        customStatus: 400,
      })
    );
  }

  const raw = input as Record<string, unknown>;

  let pollingIntervalMs = 100;
  if (raw['pollingIntervalMs'] !== undefined) {
    const val = Number(raw['pollingIntervalMs']);
    if (isNaN(val) || val < 10 || val > 60000) {
      invalidParams.push({ name: 'pollingIntervalMs', reason: 'Must be between 10ms and 60000ms' });
    } else {
      pollingIntervalMs = val;
    }
  }

  let batchSize = 25;
  if (raw['batchSize'] !== undefined) {
    const val = Number(raw['batchSize']);
    if (isNaN(val) || val < 1 || val > 500) {
      invalidParams.push({ name: 'batchSize', reason: 'Must be between 1 and 500' });
    } else {
      batchSize = val;
    }
  }

  let maxConcurrency = 10;
  if (raw['maxConcurrency'] !== undefined) {
    const val = Number(raw['maxConcurrency']);
    if (isNaN(val) || val < 1 || val > 100) {
      invalidParams.push({ name: 'maxConcurrency', reason: 'Must be between 1 and 100' });
    } else {
      maxConcurrency = val;
    }
  }

  let leaseDurationMs = 30000;
  if (raw['leaseDurationMs'] !== undefined) {
    const val = Number(raw['leaseDurationMs']);
    if (isNaN(val) || val < 1000 || val > 3600000) {
      invalidParams.push({ name: 'leaseDurationMs', reason: 'Must be between 1000ms and 3600000ms' });
    } else {
      leaseDurationMs = val;
    }
  }

  let maxAttempts = 5;
  if (raw['maxAttempts'] !== undefined) {
    const val = Number(raw['maxAttempts']);
    if (isNaN(val) || val < 1 || val > 20) {
      invalidParams.push({ name: 'maxAttempts', reason: 'Must be between 1 and 20' });
    } else {
      maxAttempts = val;
    }
  }

  let initialRetryDelayMs = 1000;
  if (raw['initialRetryDelayMs'] !== undefined) {
    const val = Number(raw['initialRetryDelayMs']);
    if (isNaN(val) || val < 100 || val > 60000) {
      invalidParams.push({ name: 'initialRetryDelayMs', reason: 'Must be between 100ms and 60000ms' });
    } else {
      initialRetryDelayMs = val;
    }
  }

  let maxRetryDelayMs = 60000;
  if (raw['maxRetryDelayMs'] !== undefined) {
    const val = Number(raw['maxRetryDelayMs']);
    if (isNaN(val) || val < 1000 || val > 3600000) {
      invalidParams.push({ name: 'maxRetryDelayMs', reason: 'Must be between 1000ms and 3600000ms' });
    } else {
      maxRetryDelayMs = val;
    }
  }

  let retryMultiplier = 2.0;
  if (raw['retryMultiplier'] !== undefined) {
    const val = Number(raw['retryMultiplier']);
    if (isNaN(val) || val < 1.1 || val > 10.0) {
      invalidParams.push({ name: 'retryMultiplier', reason: 'Must be between 1.1 and 10.0' });
    } else {
      retryMultiplier = val;
    }
  }

  const retryJitter = raw['retryJitter'] !== undefined ? Boolean(raw['retryJitter']) : true;

  let deduplicationTtlHours = 24;
  if (raw['deduplicationTtlHours'] !== undefined) {
    const val = Number(raw['deduplicationTtlHours']);
    if (isNaN(val) || val < 1 || val > 720) {
      invalidParams.push({ name: 'deduplicationTtlHours', reason: 'Must be between 1 and 720 hours' });
    } else {
      deduplicationTtlHours = val;
    }
  }

  let gracefulShutdownTimeoutMs = 5000;
  if (raw['gracefulShutdownTimeoutMs'] !== undefined) {
    const val = Number(raw['gracefulShutdownTimeoutMs']);
    if (isNaN(val) || val < 100 || val > 60000) {
      invalidParams.push({ name: 'gracefulShutdownTimeoutMs', reason: 'Must be between 100ms and 60000ms' });
    } else {
      gracefulShutdownTimeoutMs = val;
    }
  }

  if (invalidParams.length > 0) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Event bus configuration validation failed',
        instance: '/config/event-bus',
        correlationId: 'config.eventbus.parser',
        customStatus: 400,
        invalidParams,
      })
    );
  }

  return ok({
    pollingIntervalMs,
    batchSize,
    maxConcurrency,
    leaseDurationMs,
    maxAttempts,
    initialRetryDelayMs,
    maxRetryDelayMs,
    retryMultiplier,
    retryJitter,
    deduplicationTtlHours,
    gracefulShutdownTimeoutMs,
  });
}

export function loadEventBusConfigFromEnv(env: Record<string, string | undefined> = process.env): Result<EventBusConfig, ProblemDetails> {
  const map: Record<string, unknown> = {};

  if (env['SHN_EVENT_POLL_INTERVAL_MS']) map['pollingIntervalMs'] = parseInt(env['SHN_EVENT_POLL_INTERVAL_MS'], 10);
  if (env['SHN_EVENT_BATCH_SIZE']) map['batchSize'] = parseInt(env['SHN_EVENT_BATCH_SIZE'], 10);
  if (env['SHN_EVENT_MAX_CONCURRENCY']) map['maxConcurrency'] = parseInt(env['SHN_EVENT_MAX_CONCURRENCY'], 10);
  if (env['SHN_EVENT_LEASE_DURATION_MS']) map['leaseDurationMs'] = parseInt(env['SHN_EVENT_LEASE_DURATION_MS'], 10);
  if (env['SHN_EVENT_MAX_ATTEMPTS']) map['maxAttempts'] = parseInt(env['SHN_EVENT_MAX_ATTEMPTS'], 10);
  if (env['SHN_EVENT_INITIAL_RETRY_DELAY_MS']) map['initialRetryDelayMs'] = parseInt(env['SHN_EVENT_INITIAL_RETRY_DELAY_MS'], 10);
  if (env['SHN_EVENT_MAX_RETRY_DELAY_MS']) map['maxRetryDelayMs'] = parseInt(env['SHN_EVENT_MAX_RETRY_DELAY_MS'], 10);
  if (env['SHN_EVENT_RETRY_MULTIPLIER']) map['retryMultiplier'] = parseFloat(env['SHN_EVENT_RETRY_MULTIPLIER']);
  if (env['SHN_EVENT_RETRY_JITTER']) map['retryJitter'] = env['SHN_EVENT_RETRY_JITTER'] !== 'false';
  if (env['SHN_EVENT_DEDUP_TTL_HOURS']) map['deduplicationTtlHours'] = parseInt(env['SHN_EVENT_DEDUP_TTL_HOURS'], 10);
  if (env['SHN_EVENT_SHUTDOWN_TIMEOUT_MS']) map['gracefulShutdownTimeoutMs'] = parseInt(env['SHN_EVENT_SHUTDOWN_TIMEOUT_MS'], 10);

  return parseEventBusConfig(map);
}
