/**
 * Shadow : Helix Nebula (SHN) — Idempotency & Consumer Deduplication Integration Tests
 *
 * Verifies atomic check-and-set idempotency logging, prevention of duplicate side effects,
 * concurrent duplicate protection, retry re-acquisition, and expired entry pruning (0.14 Section 16, 17, ADR-API-04).
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  type DatabasePool,
  closeDatabasePool,
  DeduplicationRepository,
} from '@shn/data-access';
import {
  createEventDispatcher,
  createEventRegistry,
} from '../../dist/index.js';
import {
  ensureDatabase,
  createEventTestPool,
  setupEventTestDatabase,
  cleanEventTables,
  createValidEnvelope,
  createTestWorkspaceFixture,
  validEventId,
} from './event-test-helper.ts';
import { ok } from '@shn/shared-kernel';

describe('Consumer Idempotency & Deduplication Engine (Integration)', () => {
  let pool: DatabasePool;
  let dedupRepo: DeduplicationRepository;

  before(async () => {
    await ensureDatabase('shn_test_dedup');
    pool = createEventTestPool('shn_test_dedup');
    await setupEventTestDatabase(pool, 'shn_test_dedup');
    dedupRepo = new DeduplicationRepository(pool);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  beforeEach(async () => {
    await cleanEventTables(pool);
  });

  it('should transition status from ACQUIRED (IN_FLIGHT) to COMPLETED and reject subsequent duplicate attempts', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const eventId = validEventId();
    const consumerId = 'billing-sync-consumer';
    const idempotencyKey = `${consumerId}:${eventId}`;

    // 1. First attempt: acquire returns ACQUIRED
    const firstAcquire = await dedupRepo.acquire(
      idempotencyKey,
      eventId,
      consumerId,
      workspace.id,
      24
    );
    assert.equal(firstAcquire, 'ACQUIRED');

    // 2. While IN_FLIGHT, another attempt returns IN_FLIGHT
    const inFlightCheck = await dedupRepo.acquire(
      idempotencyKey,
      eventId,
      consumerId,
      workspace.id,
      24
    );
    assert.equal(inFlightCheck, 'IN_FLIGHT');

    // 3. Mark completed
    await dedupRepo.markCompleted(idempotencyKey, 24);

    // 4. isProcessed should now return true
    const isProc = await dedupRepo.isProcessed(idempotencyKey);
    assert.equal(isProc, true);

    // 5. Duplicate delivery returns ALREADY_COMPLETED
    const duplicateAcquire = await dedupRepo.acquire(
      idempotencyKey,
      eventId,
      consumerId,
      workspace.id,
      24
    );
    assert.equal(duplicateAcquire, 'ALREADY_COMPLETED');
  });

  it('should handle concurrent duplicate acquires atomically with exactly one winner', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const eventId = validEventId();
    const consumerId = 'threat-intel-consumer';
    const idempotencyKey = `${consumerId}:${eventId}`;

    // Launch 4 simultaneous acquire requests for identical key
    const results = await Promise.all([
      dedupRepo.acquire(idempotencyKey, eventId, consumerId, workspace.id, 24),
      dedupRepo.acquire(idempotencyKey, eventId, consumerId, workspace.id, 24),
      dedupRepo.acquire(idempotencyKey, eventId, consumerId, workspace.id, 24),
      dedupRepo.acquire(idempotencyKey, eventId, consumerId, workspace.id, 24),
    ]);

    const acquiredCount = results.filter((r) => r === 'ACQUIRED').length;
    const inFlightCount = results.filter((r) => r === 'IN_FLIGHT').length;

    assert.equal(acquiredCount, 1, 'Exactly one concurrent request must win acquisition');
    assert.equal(inFlightCount, 3, 'All other concurrent requests must receive IN_FLIGHT');
  });

  it('should allow retry re-acquisition after markFailed removes IN_FLIGHT record', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const eventId = validEventId();
    const consumerId = 'fragile-consumer';
    const idempotencyKey = `${consumerId}:${eventId}`;

    // 1. Initial acquire
    const acq1 = await dedupRepo.acquire(idempotencyKey, eventId, consumerId, workspace.id, 24);
    assert.equal(acq1, 'ACQUIRED');

    // 2. Mark failed (handler threw or failed transiently)
    await dedupRepo.markFailed(idempotencyKey);

    // 3. Subsequent retry should successfully acquire again
    const acq2 = await dedupRepo.acquire(idempotencyKey, eventId, consumerId, workspace.id, 24);
    assert.equal(acq2, 'ACQUIRED');
  });

  it('should prevent duplicate domain handler executions end-to-end via EventDispatcher', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const registry = createEventRegistry();

    let handlerCallCount = 0;
    registry.registerHandler(
      'order.payment.processed',
      async (_event) => {
        handlerCallCount++;
        return ok(undefined);
      },
      {
        handlerName: 'balance-deduction-handler',
        schemaVersion: '1.0.0',
      }
    );

    const dispatcher = createEventDispatcher({
      db: pool,
      registry,
    });

    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'order.payment.processed',
      payload: { amount: 500, currency: 'USD' },
    });

    // First dispatch -> executes handler
    const result1 = await dispatcher.dispatch(envelope);
    assert.ok(result1.isOk);
    assert.equal(result1.value.status, 'COMPLETED');
    assert.equal(handlerCallCount, 1, 'Handler should execute exactly once on first dispatch');

    // Second dispatch (redelivery of identical envelope) -> skips handler
    const result2 = await dispatcher.dispatch(envelope);
    assert.ok(result2.isOk);
    assert.equal(result2.value.status, 'COMPLETED'); // Marked completed
    assert.equal(handlerCallCount, 1, 'Handler must NOT execute again on redelivery');
  });

  it('should prune expired deduplication entries', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const eventId = validEventId();
    const consumerId = 'pruning-test-consumer';
    const idempotencyKey = `${consumerId}:${eventId}`;

    // Acquire and complete
    await dedupRepo.acquire(idempotencyKey, eventId, consumerId, workspace.id, 24);
    await dedupRepo.markCompleted(idempotencyKey, 24);

    // Backdate expires_at to 1 hour ago
    await pool.query(
      `UPDATE events.deduplication_log
       SET expires_at = clock_timestamp() - INTERVAL '1 hour'
       WHERE idempotency_key = $1;`,
      [idempotencyKey]
    );

    // Prune
    const prunedCount = await dedupRepo.pruneExpired();
    assert.ok(prunedCount >= 1, 'Should prune expired records');

    // Verify key no longer exists
    const isProc = await dedupRepo.isProcessed(idempotencyKey);
    assert.equal(isProc, false);
  });
});
