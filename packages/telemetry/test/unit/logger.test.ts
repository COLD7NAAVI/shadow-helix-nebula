/**
 * Shadow : Helix Nebula (SHN) — Structured Logger Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createLogger,
  BufferedLogSink,
  runWithTelemetryContext,
} from '../../dist/index.js';

describe('Structured Logger (Pure Unit Tests)', () => {
  it('should emit structured JSON entries with correct severity and metadata', () => {
    const sink = new BufferedLogSink();
    const logger = createLogger({
      component: 'test-service',
      minLevel: 'info',
      sink,
    });

    logger.info('System initialized successfully', { port: 8080 });

    const entries = sink.getEntries();
    assert.equal(entries.length, 1);

    const entry = entries[0]!;
    assert.equal(entry.component, 'test-service');
    assert.equal(entry.level, 'info');
    assert.equal(entry.message, 'System initialized successfully');
    assert.equal(entry.attributes?.['port'], 8080);
    assert.ok(entry.timestamp);
  });

  it('should filter log entries below the configured minimum level', () => {
    const sink = new BufferedLogSink();
    const logger = createLogger({
      component: 'filter-test',
      minLevel: 'warn',
      sink,
    });

    logger.trace('trace detail');
    logger.debug('debug detail');
    logger.info('info detail');
    logger.warn('warning condition');
    logger.error('error condition');

    const entries = sink.getEntries();
    assert.equal(entries.length, 2);
    assert.equal(entries[0]!.level, 'warn');
    assert.equal(entries[1]!.level, 'error');
  });

  it('should automatically inject telemetry context from AsyncLocalStorage', () => {
    const sink = new BufferedLogSink();
    const logger = createLogger({
      component: 'context-test',
      minLevel: 'info',
      sink,
    });

    runWithTelemetryContext(
      {
        correlationId: 'c73a9821-4f10-482a-9e11-d09214b73201',
        causationId: 'd84b0932-5a21-493b-af22-e19325c84312',
        traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        spanId: '00f067aa0ba902b7',
        workspaceId: 'e95c1043-6b32-4a4c-bf33-f2a436d95423',
      },
      () => {
        logger.info('Processing task step', { step: 3 });
      }
    );

    const entries = sink.getEntries();
    assert.equal(entries.length, 1);
    const entry = entries[0]!;

    assert.equal(entry.correlation_id, 'c73a9821-4f10-482a-9e11-d09214b73201');
    assert.equal(entry.causation_id, 'd84b0932-5a21-493b-af22-e19325c84312');
    assert.equal(entry.trace_id, '4bf92f3577b34da6a3ce929d0e0e4736');
    assert.equal(entry.span_id, '00f067aa0ba902b7');
    assert.equal(entry.workspace_id, 'e95c1043-6b32-4a4c-bf33-f2a436d95423');
    assert.equal(entry.attributes?.['step'], 3);
  });

  it('should automatically redact sensitive data passed in attributes and errors', () => {
    const sink = new BufferedLogSink();
    const logger = createLogger({
      component: 'redact-logger',
      minLevel: 'info',
      sink,
    });

    logger.error(
      'Authentication failure for user',
      {
        username: 'alice',
        password: 'plain-text-secret',
        token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      },
      new Error('Failed login on postgresql://postgres:password123@db:5432/app')
    );

    const entry = sink.getEntries()[0]!;
    assert.equal(entry.attributes?.['username'], 'alice');
    assert.equal(entry.attributes?.['password'], '[REDACTED]');
    assert.equal(entry.attributes?.['token'], '[REDACTED]');

    const err = entry.error as any;
    assert.ok(!err.message.includes('password123'));
    assert.ok(err.message.includes('[REDACTED]'));
  });

  it('should create child loggers with hierarchical component names and default attributes', () => {
    const sink = new BufferedLogSink();
    const parentLogger = createLogger({
      component: 'parent',
      minLevel: 'info',
      sink,
      defaultAttributes: { region: 'us-east' },
    });

    const childLogger = parentLogger.child({ workerId: 'worker-42' });
    childLogger.info('Worker processing batch');

    const entry = sink.getEntries()[0]!;
    assert.equal(entry.component, 'parent');
    assert.equal(entry.attributes?.['region'], 'us-east');
    assert.equal(entry.attributes?.['workerId'], 'worker-42');

    const namedChild = parentLogger.child('subsystem');
    namedChild.info('Subsystem event');
    const namedEntry = sink.getEntries()[1]!;
    assert.equal(namedEntry.component, 'parent:subsystem');
  });
});
