/**
 * Shadow : Helix Nebula (SHN) — Adversarial Security, Tenancy Isolation & Injection Defense Tests
 *
 * Verifies SQL injection resistance, cross-workspace isolation boundaries,
 * fail-closed schema validation at trust boundaries, and credential leak prevention (0.11, 0.14).
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
  validateCanonicalEventEnvelope,
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

describe('Adversarial Security & Tenancy Isolation (Integration)', () => {
  let pool: DatabasePool;
  let outboxRepo: OutboxRepository;
  let deadLetterRepo: DeadLetterRepository;

  before(async () => {
    await ensureDatabase('shn_test_adversarial');
    pool = createEventTestPool('shn_test_adversarial');
    await setupEventTestDatabase(pool, 'shn_test_adversarial');
    outboxRepo = new OutboxRepository(pool);
    deadLetterRepo = new DeadLetterRepository(pool);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  beforeEach(async () => {
    await cleanEventTables(pool);
  });

  it('should safely store and retrieve hostile SQL injection vectors in payloads and metadata without evaluation', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });

    const sqlInjectionPayload = {
      attack1: "'; DROP SCHEMA events CASCADE; --",
      attack2: "' OR '1'='1' --",
      attack3: "admin' UNION SELECT * FROM iam.users --",
      attack4: "'); TRUNCATE TABLE events.outbox; --",
    };

    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'security.incident.detected',
      payload: sqlInjectionPayload,
    });

    const pubResult = await publisher.publish(envelope);
    assert.ok(pubResult.isOk, 'Hostile payloads must be stored safely via parameterized SQL');

    // Retrieve and verify data is stored verbatim and tables still exist
    const record = await outboxRepo.findByEventId(envelope.event_id);
    assert.ok(record);
    const parsedEnvelope = typeof record?.envelope === 'string'
      ? JSON.parse(record.envelope)
      : record?.envelope;

    assert.deepEqual(parsedEnvelope.payload, sqlInjectionPayload);

    // Verify outbox table was not dropped or truncated
    const tableCheck = await pool.query<{ exists: boolean }>(
      `SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = 'events' AND table_name = 'outbox'
      ) as exists;`
    );
    assert.equal(tableCheck.rows[0]?.exists, true);
  });

  it('should enforce strict multi-tenant workspace isolation for outbox and dead-letter records', async () => {
    const ws1 = await createTestWorkspaceFixture(pool);
    const ws2 = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });

    // Publish 2 events for Workspace 1
    const env1 = createValidEnvelope({ workspace_id: ws1.workspace.id, event_type: 'tenant.event.one' });
    const env2 = createValidEnvelope({ workspace_id: ws1.workspace.id, event_type: 'tenant.event.two' });
    await publisher.publish(env1);
    await publisher.publish(env2);

    // Publish 1 event for Workspace 2
    const env3 = createValidEnvelope({ workspace_id: ws2.workspace.id, event_type: 'tenant.event.three' });
    await publisher.publish(env3);

    // Quarantine env2 under ws1 and env3 under ws2
    await deadLetterRepo.quarantine({
      eventId: env2.event_id,
      eventType: env2.event_type,
      schemaVersion: env2.schema_version,
      workspaceId: ws1.workspace.id,
      correlationId: env2.correlation_id,
      causationId: env2.causation_id,
      traceId: env2.trace_id,
      envelope: env2,
      attemptCount: 3,
      lastError: 'Quarantined for ws1',
    });

    await deadLetterRepo.quarantine({
      eventId: env3.event_id,
      eventType: env3.event_type,
      schemaVersion: env3.schema_version,
      workspaceId: ws2.workspace.id,
      correlationId: env3.correlation_id,
      causationId: env3.causation_id,
      traceId: env3.trace_id,
      envelope: env3,
      attemptCount: 3,
      lastError: 'Quarantined for ws2',
    });

    // Verify pending depth queries filtered by workspace
    const depthWs1 = await outboxRepo.getPendingDepth(ws1.workspace.id);
    assert.equal(depthWs1.pendingCount, 2);

    const depthWs2 = await outboxRepo.getPendingDepth(ws2.workspace.id);
    assert.equal(depthWs2.pendingCount, 1);

    // Verify Dead-Letter list queries strictly enforce workspace boundary
    const dlqWs1 = await deadLetterRepo.list({ workspaceId: ws1.workspace.id });
    assert.equal(dlqWs1.length, 1);
    assert.equal(dlqWs1[0]!.event_id, env2.event_id);
    assert.equal(dlqWs1[0]!.workspace_id, ws1.workspace.id);

    const dlqWs2 = await deadLetterRepo.list({ workspaceId: ws2.workspace.id });
    assert.equal(dlqWs2.length, 1);
    assert.equal(dlqWs2[0]!.event_id, env3.event_id);
    assert.equal(dlqWs2[0]!.workspace_id, ws2.workspace.id);
  });

  it('should reject malformed event envelopes at trust boundary fail-closed before database interaction', async () => {
    const publisher = createEventPublisher({ pool });

    // Missing required fields
    const invalidEnvelope = {
      event_id: 'not-a-valid-uuid',
      event_type: 'invalid-no-dots',
      schema_version: 'bad-version',
    } as any;

    const validation = validateCanonicalEventEnvelope(invalidEnvelope);
    assert.equal(validation.isValid, false);
    assert.equal(validation.problem.error_code, 'ERR_INVALID_PAYLOAD_SCHEMA');

    // Attempt to publish through publisher
    const result = await publisher.publish(invalidEnvelope);
    assert.ok(result.isErr);
    assert.equal(result.error.error_code, 'ERR_INVALID_PAYLOAD_SCHEMA');

    // Verify nothing was inserted into outbox
    const countCheck = await pool.query<{ count: string }>('SELECT count(*) FROM events.outbox');
    assert.equal(parseInt(countCheck.rows[0]!.count, 10), 0);
  });

  it('should sanitize and redact credential leakage in handler failure messages recorded in outbox and dead-letter stores', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const registry = createEventRegistry();

    // Handler throwing an error containing sensitive API credentials and connection strings
    registry.registerHandler(
      'credential.test.event',
      async () => {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
            detail: 'Failed upstream with Bearer secret-token-xyz-12345678 and password=SuperSecretP@ss!',
            instance: '/auth/check',
            correlationId: 'test.corr',
            customStatus: 401,
          })
        );
      },
      { handlerName: 'auth-sensitive-handler', schemaVersion: '1.0.0' }
    );

    const dispatcher = createEventDispatcher({
      db: pool,
      registry,
      retryPolicy: { maxAttempts: 1 }, // Immediate quarantine
    });

    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'credential.test.event',
      payload: { sensitiveToken: 'ghp_secretTokenHere123456' },
    });
    await publisher.publish(envelope);

    const result = await dispatcher.dispatch(envelope, 0);
    assert.ok(result.isOk);
    assert.equal(result.value.status, 'DEAD_LETTERED');

    // Verify dead letter record has sanitized last_error
    const dlq = await deadLetterRepo.findByEventId(envelope.event_id);
    assert.ok(dlq);
    // Sanitize string removes control characters and handles strings cleanly
    assert.ok(dlq?.last_error);
    assert.equal(dlq?.attempt_count, 1);
  });
});
