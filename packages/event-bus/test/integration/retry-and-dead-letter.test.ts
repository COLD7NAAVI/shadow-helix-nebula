/**
 * Shadow : Helix Nebula (SHN) — Retry, Backoff, Dead-Letter & Replay Integration Tests
 *
 * Verifies retry backoff calculations, dead-letter quarantine upon exhaustion,
 * administrative replay, loop prevention, and unauthorized access rejection (0.14 Section 35.7).
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  type DatabasePool,
  closeDatabasePool,
  OutboxRepository,
  DeadLetterRepository,
} from '@shn/data-access';
import {
  createEventPublisher,
  createEventDispatcher,
  createEventRegistry,
  createReplayManager,
} from '../../dist/index.js';
import {
  ensureDatabase,
  createEventTestPool,
  setupEventTestDatabase,
  cleanEventTables,
  createValidEnvelope,
  createTestWorkspaceFixture,
} from './event-test-helper.ts';
import { err } from '@shn/shared-kernel';
import { ErrorCode, createProblemDetails } from '@shn/error-catalog';

describe('Retry Policy, Dead-Letter Quarantine & Administrative Replay (Integration)', () => {
  let pool: DatabasePool;
  let outboxRepo: OutboxRepository;
  let deadLetterRepo: DeadLetterRepository;

  before(async () => {
    await ensureDatabase('shn_test_dlq');
    pool = createEventTestPool('shn_test_dlq');
    await setupEventTestDatabase(pool, 'shn_test_dlq');
    outboxRepo = new OutboxRepository(pool);
    deadLetterRepo = new DeadLetterRepository(pool);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  beforeEach(async () => {
    await cleanEventTables(pool);
  });

  it('should schedule retry with exponential backoff on transient handler failure', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const registry = createEventRegistry();

    // Failing handler
    registry.registerHandler(
      'notification.email.send',
      async () => {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.DEPENDENCY_UNAVAILABLE,
            detail: 'SMTP server connection refused',
            instance: '/smtp/send',
            correlationId: 'test.corr',
            customStatus: 503,
          })
        );
      },
      { handlerName: 'smtp-notification-handler', schemaVersion: '1.0.0' }
    );

    const dispatcher = createEventDispatcher({
      db: pool,
      registry,
      retryPolicy: {
        maxAttempts: 3,
        initialDelayMs: 500,
        multiplier: 2.0,
        maxDelayMs: 10000,
        jitter: false,
      },
    });

    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'notification.email.send',
      payload: { to: 'operator@shadow-helix.io' },
    });
    await publisher.publish(envelope);

    // Initial dispatch (attempt 0 -> attempt 1 fails)
    const result = await dispatcher.dispatch(envelope, 0);
    assert.ok(result.isOk);
    assert.equal(result.value.status, 'SCHEDULED_RETRY');
    assert.equal(result.value.attemptCount, 1);

    // Inspect outbox row in database
    const outboxRow = await outboxRepo.findByEventId(envelope.event_id);
    assert.ok(outboxRow);
    assert.equal(outboxRow?.status, 'PENDING');
    assert.equal(outboxRow?.attempt_count, 1);
    assert.ok(outboxRow?.last_error?.includes('SMTP server connection refused'));
    assert.ok(outboxRow?.next_attempt_at !== null);

    // Verify next_attempt_at is in the future (~500ms from now)
    const nextAttemptTime = new Date(outboxRow!.next_attempt_at!).getTime();
    assert.ok(nextAttemptTime >= Date.now() - 50);
  });

  it('should quarantine exhausted event into Dead-Letter store when maxAttempts exceeded', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const registry = createEventRegistry();

    registry.registerHandler(
      'vuln.ingest.report',
      async () => {
        throw new Error('Unparseable CVSS schema payload');
      },
      { handlerName: 'cvss-ingester', schemaVersion: '1.0.0' }
    );

    const dispatcher = createEventDispatcher({
      db: pool,
      registry,
      retryPolicy: {
        maxAttempts: 2,
        initialDelayMs: 100,
      },
    });

    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'vuln.ingest.report',
      payload: { rawReport: 'corrupt-cve-format' },
    });
    await publisher.publish(envelope);

    // Attempt 1 -> fails and schedules retry
    const res1 = await dispatcher.dispatch(envelope, 0);
    assert.ok(res1.isOk);
    assert.equal(res1.value.status, 'SCHEDULED_RETRY');

    // Attempt 2 (exhaustion) -> terminal failure and DLQ quarantine
    const res2 = await dispatcher.dispatch(envelope, 1);
    assert.ok(res2.isOk);
    assert.equal(res2.value.status, 'DEAD_LETTERED');

    // Verify outbox row transitioned to DEAD_LETTER
    const outboxRow = await outboxRepo.findByEventId(envelope.event_id);
    assert.ok(outboxRow);
    assert.equal(outboxRow?.status, 'DEAD_LETTER');
    assert.equal(outboxRow?.attempt_count, 2);

    // Verify record in events.dead_letter
    const dlqRecord = await deadLetterRepo.findByEventId(envelope.event_id);
    assert.ok(dlqRecord, 'Dead-letter record must exist');
    assert.equal(dlqRecord?.event_id, envelope.event_id);
    assert.equal(dlqRecord?.event_type, 'vuln.ingest.report');
    assert.equal(dlqRecord?.workspace_id, workspace.id);
    assert.equal(dlqRecord?.attempt_count, 2);
    assert.ok(dlqRecord?.last_error.includes('Unparseable CVSS schema payload'));
    assert.equal(dlqRecord?.replay_count, 0);
    assert.equal(dlqRecord?.replayed_at, null);
  });

  it('should allow authorized operator to replay quarantined dead-letter event and reset outbox', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const replayManager = createReplayManager(pool);

    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'threat.feed.alert',
      payload: { feedId: 'misp-1' },
    });
    await publisher.publish(envelope);

    // Manually quarantine
    const dlq = await deadLetterRepo.quarantine({
      eventId: envelope.event_id,
      eventType: envelope.event_type,
      schemaVersion: envelope.schema_version,
      workspaceId: envelope.workspace_id,
      correlationId: envelope.correlation_id,
      causationId: envelope.causation_id,
      traceId: envelope.trace_id,
      envelope,
      attemptCount: 3,
      lastError: 'Simulated permanent failure',
    });

    // Replay with authorized operator
    const replayResult = await replayManager.replay(dlq.id, {
      authorizedOperator: 'usr-admin-secops-99',
      maxReplayAttempts: 3,
    });
    assert.ok(replayResult.isOk, 'Replay should succeed');

    // Verify dead letter row marked replayed
    const updatedDlq = await deadLetterRepo.findById(dlq.id);
    assert.ok(updatedDlq);
    assert.equal(updatedDlq?.replayed_by, 'usr-admin-secops-99');
    assert.equal(updatedDlq?.replay_count, 1);
    assert.ok(updatedDlq?.replayed_at !== null);

    // Verify outbox event is back in PENDING
    const outboxRow = await outboxRepo.findByEventId(envelope.event_id);
    assert.ok(outboxRow);
    assert.equal(outboxRow?.status, 'PENDING');
  });

  it('should enforce replay loop prevention when replay count reaches maximum allowed limit', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const replayManager = createReplayManager(pool);

    const envelope = createValidEnvelope({ workspace_id: workspace.id });
    const dlq = await deadLetterRepo.quarantine({
      eventId: envelope.event_id,
      eventType: envelope.event_type,
      schemaVersion: envelope.schema_version,
      workspaceId: envelope.workspace_id,
      correlationId: envelope.correlation_id,
      causationId: envelope.causation_id,
      traceId: envelope.trace_id,
      envelope,
      attemptCount: 3,
      lastError: 'Repeated poison pill',
    });

    // Replay 1 succeeds
    const r1 = await replayManager.replay(dlq.id, {
      authorizedOperator: 'op-1',
      maxReplayAttempts: 2,
    });
    assert.ok(r1.isOk);

    // Replay 2 succeeds
    const r2 = await replayManager.replay(dlq.id, {
      authorizedOperator: 'op-1',
      maxReplayAttempts: 2,
    });
    assert.ok(r2.isOk);

    // Replay 3 should be rejected to prevent infinite loop
    const r3 = await replayManager.replay(dlq.id, {
      authorizedOperator: 'op-1',
      maxReplayAttempts: 2,
    });
    assert.ok(r3.isErr);
    assert.equal(r3.error.error_code, ErrorCode.RATE_LIMIT_EXCEEDED);
    assert.ok(r3.error.detail.includes('Replay loop prevented'));
  });

  it('should reject replay request fail-closed if operator identity is missing', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const replayManager = createReplayManager(pool);

    const envelope = createValidEnvelope({ workspace_id: workspace.id });
    const dlq = await deadLetterRepo.quarantine({
      eventId: envelope.event_id,
      eventType: envelope.event_type,
      schemaVersion: envelope.schema_version,
      workspaceId: envelope.workspace_id,
      correlationId: envelope.correlation_id,
      causationId: envelope.causation_id,
      traceId: envelope.trace_id,
      envelope,
      attemptCount: 3,
      lastError: 'Fail',
    });

    const result = await replayManager.replay(dlq.id, {
      authorizedOperator: '',
    });
    assert.ok(result.isErr);
    assert.equal(result.error.error_code, ErrorCode.AUTH_FORBIDDEN);
  });
});
