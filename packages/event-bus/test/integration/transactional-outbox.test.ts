/**
 * Shadow : Helix Nebula (SHN) — Transactional Outbox Integration Tests
 *
 * Verifies atomicity between business operations and outbox insertion,
 * transactional rollbacks, pending depth tracking, and delivery receipts (0.10, 0.14).
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  type DatabasePool,
  closeDatabasePool,
  runInTransaction,
  OrganizationRepository,
  OutboxRepository,
} from '@shn/data-access';
import {
  createEventPublisher,
} from '../../dist/index.js';
import {
  ensureDatabase,
  createEventTestPool,
  setupEventTestDatabase,
  cleanEventTables,
  createValidEnvelope,
  createTestWorkspaceFixture,
  validOrgId,
  validWorkspaceId,
} from './event-test-helper.ts';

describe('Transactional Outbox Persistence & Atomicity (Integration)', () => {
  let pool: DatabasePool;
  let outboxRepo: OutboxRepository;
  let orgRepo: OrganizationRepository;

  before(async () => {
    await ensureDatabase('shn_test_outbox');
    pool = createEventTestPool('shn_test_outbox');
    await setupEventTestDatabase(pool, 'shn_test_outbox');
    outboxRepo = new OutboxRepository(pool);
    orgRepo = new OrganizationRepository(pool);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  beforeEach(async () => {
    await cleanEventTables(pool);
  });

  it('should publish an event directly to outbox with PENDING status and correct fields', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'scan.target.created',
      payload: { host: '10.0.0.50', ports: [22, 80] },
    });

    const receiptResult = await publisher.publish(envelope);
    assert.ok(receiptResult.isOk, 'Publication should succeed');
    const receipt = receiptResult.value;

    assert.equal(receipt.eventId, envelope.event_id);
    assert.equal(receipt.deliveryMode, 'NON_TRANSACTIONAL_OUTBOX');
    assert.ok(receipt.publishedAt);

    // Verify outbox row directly in database
    const outboxRows = await pool.query<{
      event_id: string;
      event_type: string;
      status: string;
      attempt_count: number;
      correlation_id: string;
    }>(
      `SELECT event_id, event_type, status, attempt_count, correlation_id
       FROM events.outbox WHERE event_id = $1`,
      [envelope.event_id]
    );

    assert.equal(outboxRows.rows.length, 1);
    const row = outboxRows.rows[0]!;
    assert.equal(row.event_id, envelope.event_id);
    assert.equal(row.event_type, 'scan.target.created');
    assert.equal(row.status, 'PENDING');
    assert.equal(row.attempt_count, 0);
    assert.equal(row.correlation_id, envelope.correlation_id);
  });

  it('should atomically commit domain entity and outbox event in the same transaction', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const orgId = validOrgId();
    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'iam.organization.created',
      payload: { org_id: orgId, name: 'Sovereign Sec Ops' },
    });

    const txResult = await runInTransaction(pool, async (client) => {
      // 1. Create domain entity using transaction client
      const txOrgRepo = new OrganizationRepository(client);
      const org = await txOrgRepo.create({
        id: orgId,
        name: 'Sovereign Sec Ops',
        slug: `sovereign-sec-${Date.now()}`,
      });

      // 2. Publish outbox event within the exact same transaction
      const pubReceipt = await publisher.publishTransactional(client, envelope);
      assert.ok(pubReceipt.isOk);
      assert.equal(pubReceipt.value.deliveryMode, 'TRANSACTIONAL_OUTBOX');

      return { org, receipt: pubReceipt.value };
    });

    assert.ok(txResult.org);
    assert.equal(txResult.receipt.deliveryMode, 'TRANSACTIONAL_OUTBOX');

    // Verify domain entity was persisted
    const orgFound = await orgRepo.findById(orgId);
    assert.ok(orgFound);
    assert.equal(orgFound?.name, 'Sovereign Sec Ops');

    // Verify outbox row was persisted
    const outboxRows = await pool.query<{ event_id: string; status: string }>(
      `SELECT event_id, status FROM events.outbox WHERE event_id = $1`,
      [envelope.event_id]
    );
    assert.equal(outboxRows.rows.length, 1);
    assert.equal(outboxRows.rows[0]?.status, 'PENDING');
  });

  it('should atomically roll back BOTH domain entity and outbox event when transaction fails', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });
    const orgId = validOrgId();
    const envelope = createValidEnvelope({
      workspace_id: workspace.id,
      event_type: 'iam.organization.created',
      payload: { org_id: orgId, name: 'Aborted Org' },
    });

    await assert.rejects(
      async () => {
        await runInTransaction(pool, async (client) => {
          // 1. Create domain entity using transaction client
          const txOrgRepo = new OrganizationRepository(client);
          await txOrgRepo.create({
            id: orgId,
            name: 'Aborted Org',
            slug: `aborted-org-${Date.now()}`,
          });

          // 2. Publish outbox event
          const pubReceipt = await publisher.publishTransactional(client, envelope);
          assert.ok(pubReceipt.isOk);

          // 3. Deliberately abort transaction
          throw new Error('Simulated domain failure forcing rollback');
        });
      },
      /Simulated domain failure forcing rollback/
    );

    // Verify domain entity was ROLLED BACK
    const orgFound = await orgRepo.findById(orgId);
    assert.equal(orgFound, null, 'Domain entity must not exist after rollback');

    // Verify outbox event was ROLLED BACK (No phantom events)
    const outboxRows = await pool.query<{ event_id: string }>(
      `SELECT event_id FROM events.outbox WHERE event_id = $1`,
      [envelope.event_id]
    );
    assert.equal(outboxRows.rows.length, 0, 'Outbox event must not exist after rollback');
  });

  it('should accurately track pending outbox depth and mark events as published', async () => {
    const { workspace } = await createTestWorkspaceFixture(pool);
    const publisher = createEventPublisher({ pool });

    const initialDepth = await outboxRepo.getPendingDepth();
    assert.equal(initialDepth.pendingCount, 0);

    // Publish 3 events
    const e1 = createValidEnvelope({ workspace_id: workspace.id });
    const e2 = createValidEnvelope({ workspace_id: workspace.id });
    const e3 = createValidEnvelope({ workspace_id: workspace.id });

    await publisher.publish(e1);
    await publisher.publish(e2);
    await publisher.publish(e3);

    const depthAfterPub = await outboxRepo.getPendingDepth();
    assert.equal(depthAfterPub.pendingCount, 3);

    // Mark 1 as published
    await outboxRepo.markPublished(e1.event_id);

    const depthAfterOnePublished = await outboxRepo.getPendingDepth();
    assert.equal(depthAfterOnePublished.pendingCount, 2);

    // Verify status in DB
    const checkRow = await pool.query<{ status: string; published_at: string | null }>(
      `SELECT status, published_at FROM events.outbox WHERE event_id = $1`,
      [e1.event_id]
    );
    assert.equal(checkRow.rows[0]?.status, 'PUBLISHED');
    assert.ok(checkRow.rows[0]?.published_at !== null);
  });
});
