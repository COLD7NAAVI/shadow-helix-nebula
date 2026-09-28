/**
 * Shadow : Helix Nebula (SHN) — Telemetry Configuration Substrate
 *
 * Strict, typed, fail-closed configuration parsing for observability (0.14 Section 25).
 */

import os from 'node:os';
import crypto from 'node:crypto';
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
import { type LogLevel, parseLogLevel } from '../logger/log-level.js';

export interface TelemetryConfig {
  readonly serviceName: string;
  readonly nodeId: string;
  readonly environment: 'development' | 'staging' | 'production' | 'test';
  readonly logLevel: LogLevel;
  readonly logFormat: 'json' | 'pretty';
  readonly enableRedaction: boolean;
  readonly traceSamplingRatio: number;
  readonly metricsEnabled: boolean;
  readonly shutdownTimeoutMs: number;
}

const VALID_ENVIRONMENTS = new Set(['development', 'staging', 'production', 'test']);

export function parseTelemetryConfig(input: unknown): Result<TelemetryConfig, ProblemDetails> {
  const invalidParams: InvalidParam[] = [];

  if (!input || typeof input !== 'object') {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Telemetry configuration must be a non-null object',
        instance: '/config/telemetry',
        correlationId: 'config.telemetry.parser',
        customStatus: 400,
      })
    );
  }

  const raw = input as Record<string, unknown>;

  const serviceName = typeof raw['serviceName'] === 'string' && raw['serviceName'].trim().length > 0
    ? raw['serviceName'].trim()
    : 'shn-node';

  const nodeId = typeof raw['nodeId'] === 'string' && raw['nodeId'].trim().length > 0
    ? raw['nodeId'].trim()
    : `${os.hostname()}-${crypto.randomBytes(4).toString('hex')}`;

  let environment: 'development' | 'staging' | 'production' | 'test' = 'development';
  if (raw['environment'] !== undefined) {
    if (typeof raw['environment'] !== 'string' || !VALID_ENVIRONMENTS.has(raw['environment'])) {
      invalidParams.push({
        name: 'environment',
        reason: `Must be one of: ${Array.from(VALID_ENVIRONMENTS).join(', ')}`,
      });
    } else {
      environment = raw['environment'] as 'development' | 'staging' | 'production' | 'test';
    }
  }

  const logLevel = parseLogLevel(raw['logLevel'], 'info');

  let logFormat: 'json' | 'pretty' = 'json';
  if (raw['logFormat'] !== undefined) {
    if (raw['logFormat'] === 'pretty' || raw['logFormat'] === 'json') {
      logFormat = raw['logFormat'];
    } else {
      invalidParams.push({
        name: 'logFormat',
        reason: 'Must be either "json" or "pretty"',
      });
    }
  }

  const enableRedaction = raw['enableRedaction'] !== undefined ? Boolean(raw['enableRedaction']) : true;

  let traceSamplingRatio = 1.0;
  if (raw['traceSamplingRatio'] !== undefined) {
    const ratio = Number(raw['traceSamplingRatio']);
    if (isNaN(ratio) || ratio < 0 || ratio > 1) {
      invalidParams.push({
        name: 'traceSamplingRatio',
        reason: 'Must be a number between 0.0 and 1.0',
      });
    } else {
      traceSamplingRatio = ratio;
    }
  }

  const metricsEnabled = raw['metricsEnabled'] !== undefined ? Boolean(raw['metricsEnabled']) : true;

  let shutdownTimeoutMs = 5000;
  if (raw['shutdownTimeoutMs'] !== undefined) {
    const timeout = Number(raw['shutdownTimeoutMs']);
    if (isNaN(timeout) || timeout < 100 || timeout > 60000) {
      invalidParams.push({
        name: 'shutdownTimeoutMs',
        reason: 'Must be between 100ms and 60000ms',
      });
    } else {
      shutdownTimeoutMs = timeout;
    }
  }

  if (invalidParams.length > 0) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Telemetry configuration validation failed',
        instance: '/config/telemetry',
        correlationId: 'config.telemetry.parser',
        customStatus: 400,
        invalidParams,
      })
    );
  }

  return ok({
    serviceName,
    nodeId,
    environment,
    logLevel,
    logFormat,
    enableRedaction,
    traceSamplingRatio,
    metricsEnabled,
    shutdownTimeoutMs,
  });
}

export function loadTelemetryConfigFromEnv(env: Record<string, string | undefined> = process.env): Result<TelemetryConfig, ProblemDetails> {
  const envMap: Record<string, unknown> = {};

  if (env['SHN_SERVICE_NAME']) envMap['serviceName'] = env['SHN_SERVICE_NAME'];
  if (env['SHN_NODE_ID']) envMap['nodeId'] = env['SHN_NODE_ID'];
  if (env['NODE_ENV']) envMap['environment'] = env['NODE_ENV'];
  if (env['SHN_LOG_LEVEL']) envMap['logLevel'] = env['SHN_LOG_LEVEL'];
  if (env['SHN_LOG_FORMAT']) envMap['logFormat'] = env['SHN_LOG_FORMAT'];
  if (env['SHN_ENABLE_REDACTION']) envMap['enableRedaction'] = env['SHN_ENABLE_REDACTION'] !== 'false';
  if (env['SHN_TRACE_SAMPLING_RATIO']) envMap['traceSamplingRatio'] = parseFloat(env['SHN_TRACE_SAMPLING_RATIO']);
  if (env['SHN_METRICS_ENABLED']) envMap['metricsEnabled'] = env['SHN_METRICS_ENABLED'] !== 'false';
  if (env['SHN_SHUTDOWN_TIMEOUT_MS']) envMap['shutdownTimeoutMs'] = parseInt(env['SHN_SHUTDOWN_TIMEOUT_MS'], 10);

  return parseTelemetryConfig(envMap);
}
