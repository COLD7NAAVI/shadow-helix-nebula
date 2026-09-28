/**
 * Shadow : Helix Nebula (SHN) — Concurrent Outbox Claiming & Lease Recovery Integration Tests
 *
 * Verifies non-blocking SKIP LOCKED concurrency across workers,
 * lease expiry detection and recovery, and poller graceful draining (0.10, 0.14).
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  type DatabasePool,
  closeDatabasePool,
  OutboxRepository,
} from '@shn/data-access';
import {
  createEventPublisher,
  createOutboxPoller,
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
} from './event-test-helper.ts';
import { ok } from '@shn/shared-kernel';

describe('Concurrent Claiming & Lease Recovery (Integration)', () => {
  let pool: DatabasePool;
  let outboxRepo: OutboxRepository;

  before(async () => {
    await ensureDatabase('shn_test_concurrency');
    pool = createEventTestPool('shn_test_concurrency');
    await setupEventTestDatabase(pool, 'shn_test_concurrency');
    outboxRepo = new OutboxRepository(pool);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  beforeEach(async () => {
    await cleanEventTables(pool);
  });

  it('should allow concurrent workers to claim distinct batches via SKIP LOCKED without overlap or deadlock', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });

    // Seed 20 outbox events
    const eventIds: string[] = [];
    for (let i = 0; i < 20; i++) {
      const env = createValidEnvelope({
        workspace_id: workspace.id,
        event_type: 'worker.task.enqueued',
        payload: { taskIndex: i },
      });
      eventIds.push(env.event_id);
      await publisher.publish(env);
    }

    // 4 concurrent workers claiming 5 events each simultaneously
    const workerIds = ['worker-alpha', 'worker-beta', 'worker-gamma', 'worker-delta'];
    const claimPromises = workerIds.map((workerId) =>
      outboxRepo.claimBatch({
        workerId,
        batchSize: 5,
        leaseDurationMs: 15000,
      })
    );

    const results = await Promise.all(claimPromises);

    // Verify each worker got a batch of events
    const allClaimedIds = new Set<string>();
    let totalClaimed = 0;

    for (let i = 0; i < results.length; i++) {
      const batch = results[i]!;
      const workerId = workerIds[i]!;

      for (const record of batch) {
        totalClaimed++;
        // Verify no duplicate claim across workers
        assert.equal(
          allClaimedIds.has(record.event_id),
          false,
          `Event ${record.event_id} was claimed by multiple workers!`
        );
        allClaimedIds.add(record.event_id);

        assert.equal(record.status, 'PROCESSING');
        assert.equal(record.claimed_by, workerId);
      }
    }

    assert.equal(totalClaimed, 20, 'All 20 events should be claimed across the 4 workers');
    assert.equal(allClaimedIds.size, 20, 'All 20 event IDs must be unique');

    // A 5th worker attempting to claim should get 0 events (all locked / processing)
    const emptyBatch = await outboxRepo.claimBatch({
      workerId: 'worker-extra',
      batchSize: 5,
      leaseDurationMs: 15000,
    });
    assert.equal(emptyBatch.length, 0, 'No pending events should remain for claiming');
  });

  it('should detect and recover expired processing leases back to PENDING for retry', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });

    const env = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'lease.timeout.test',
      payload: { value: 42 },
    });
    await publisher.publish(env);

    // Worker 1 claims event with a lease
    const batch1 = await outboxRepo.claimBatch({
      workerId: 'crashed-worker-1',
      batchSize: 1,
      leaseDurationMs: 5000,
    });
    assert.equal(batch1.length, 1);
    assert.equal(batch1[0]!.event_id, env.event_id);

    // Simulate worker crash / lease expiration by backdating lease_expires_at to 10 seconds ago
    await pool.query(
      `UPDATE events.outbox
       SET lease_expires_at = clock_timestamp() - INTERVAL '10 seconds'
       WHERE event_id = $1`,
      [env.event_id]
    );

    // Recover expired leases
    const recoveredCount = await outboxRepo.recoverExpiredLeases(10);
    assert.equal(recoveredCount, 1, 'Should recover 1 expired lease');

    // Verify outbox record is back in PENDING with attempt_count incremented
    const checkRow = await pool.query<{ status: string; attempt_count: number; claimed_by: string | null }>(
      `SELECT status, attempt_count, claimed_by FROM events.outbox WHERE event_id = $1`,
      [env.event_id]
    );
    assert.equal(checkRow.rows[0]?.status, 'PENDING');
    assert.equal(checkRow.rows[0]?.attempt_count, 1);
    assert.equal(checkRow.rows[0]?.claimed_by, null);

    // Worker 2 can now claim the recovered event
    const batch2 = await outboxRepo.claimBatch({
      workerId: 'healthy-worker-2',
      batchSize: 1,
      leaseDurationMs: 5000,
    });
    assert.equal(batch2.length, 1);
    assert.equal(batch2[0]!.event_id, env.event_id);
    assert.equal(batch2[0]!.claimed_by, 'healthy-worker-2');
  });

  it('should run outbox poller background worker and drain gracefully on shutdown', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const registry = createEventRegistry();

    let processedCount = 0;
    const regResult = registry.registerHandler(
      'poller.test.event',
      async (_event) => {
        processedCount++;
        return ok(undefined);
      },
      {
        handlerName: 'poller-test-handler',
        schemaVersion: '1.0.0',
      }
    );
    assert.ok(regResult.isOk, 'Handler registration must succeed');

    const dispatcher = createEventDispatcher({
      db: pool,
      registry,
    });

    const poller = createOutboxPoller({
      pool,
      dispatcher,
      workerId: 'integration-poller-1',
      pollIntervalMs: 50,
      batchSize: 5,
      leaseDurationMs: 10000,
      maxConcurrency: 5,
    });

    // Publish 5 events
    for (let i = 0; i < 5; i++) {
      await publisher.publish(
        createValidEnvelope({
          workspace_id: workspace.id,
          event_type: 'poller.test.event',
          payload: { count: i },
        })
      );
    }

    // Start poller
    poller.start();

    // Poll until all 5 events processed or timeout (max 3 seconds)
    const startTime = Date.now();
    while (processedCount < 5 && Date.now() - startTime < 3000) {
      await new Promise((r) => setTimeout(r, 50));
    }

    assert.equal(processedCount, 5, 'Poller should have processed all 5 events');

    // Gracefully drain poller in-flight tasks
    await poller.drain(5000);
    assert.equal(poller.isRunning(), false);

    // Verify all 5 events in DB are now marked as PUBLISHED
    const rows = await pool.query<{ count: string }>(
      `SELECT count(*) FROM events.outbox WHERE status = 'PUBLISHED'`
    );
    assert.equal(parseInt(rows.rows[0]!.count, 10), 5);
  });
});
