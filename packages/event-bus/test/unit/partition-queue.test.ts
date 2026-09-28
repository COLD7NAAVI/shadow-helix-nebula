/**
 * Shadow : Helix Nebula (SHN) — Partition Queue Ordering Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PartitionQueue } from '../../dist/index.js';

describe('Partition Queue & Sequencing (Pure Unit Tests)', () => {
  it('should execute tasks in strict FIFO order within the same partition', async () => {
    const queue = new PartitionQueue();
    const order: number[] = [];

    const task1 = queue.enqueue({
      partitionKey: 'partition-A',
      execute: async () => {
        await new Promise((r) => setTimeout(r, 40));
        order.push(1);
        return 'first';
      },
    });

    const task2 = queue.enqueue({
      partitionKey: 'partition-A',
      execute: async () => {
        await new Promise((r) => setTimeout(r, 10));
        order.push(2);
        return 'second';
      },
    });

    const task3 = queue.enqueue({
      partitionKey: 'partition-A',
      execute: async () => {
        order.push(3);
        return 'third';
      },
    });

    const [res1, res2, res3] = await Promise.all([task1, task2, task3]);

    assert.equal(res1, 'first');
    assert.equal(res2, 'second');
    assert.equal(res3, 'third');
    assert.deepEqual(order, [1, 2, 3], 'Tasks in partition-A must execute in FIFO order despite different task durations');
  });

  it('should execute independent partitions concurrently without cross-partition head-of-line blocking', async () => {
    const queue = new PartitionQueue();
    const timestamps: Record<string, number> = {};

    const taskA = queue.enqueue({
      partitionKey: 'partition-slow',
      execute: async () => {
        await new Promise((r) => setTimeout(r, 60));
        timestamps['slow'] = Date.now();
        return 'slow-done';
      },
    });

    const taskB = queue.enqueue({
      partitionKey: 'partition-fast',
      execute: async () => {
        await new Promise((r) => setTimeout(r, 10));
        timestamps['fast'] = Date.now();
        return 'fast-done';
      },
    });

    await Promise.all([taskA, taskB]);

    assert.ok(
      timestamps['fast']! < timestamps['slow']!,
      'Fast partition should finish before slow partition without waiting for it'
    );
  });

  it('should enforce monotonically increasing sequence numbers when supplied', async () => {
    const queue = new PartitionQueue();

    // Sequence 1 succeeds
    await queue.enqueue({
      partitionKey: 'seq-partition',
      sequenceNumber: 1,
      execute: async () => 'seq-1',
    });

    // Sequence 2 succeeds
    await queue.enqueue({
      partitionKey: 'seq-partition',
      sequenceNumber: 2,
      execute: async () => 'seq-2',
    });

    // Sequence 1 again (stale / duplicate) must throw fail-closed
    await assert.rejects(
      async () => {
        await queue.enqueue({
          partitionKey: 'seq-partition',
          sequenceNumber: 1,
          execute: async () => 'stale',
        });
      },
      /Stale or out-of-order event rejected in partition "seq-partition": received sequence 1, current is 2/
    );

    // Sequence 2 (equal / duplicate) must also throw
    await assert.rejects(
      async () => {
        await queue.enqueue({
          partitionKey: 'seq-partition',
          sequenceNumber: 2,
          execute: async () => 'duplicate',
        });
      },
      /Stale or out-of-order event rejected in partition "seq-partition": received sequence 2, current is 2/
    );
  });

  it('should continue processing partition tasks even after an earlier task in the partition fails', async () => {
    const queue = new PartitionQueue();

    // First task fails
    const failingTask = queue.enqueue({
      partitionKey: 'recovery-partition',
      execute: async () => {
        throw new Error('Task 1 deliberate failure');
      },
    });

    // Second task in same partition
    const succeedingTask = queue.enqueue({
      partitionKey: 'recovery-partition',
      execute: async () => 'Task 2 success',
    });

    await assert.rejects(async () => failingTask, /Task 1 deliberate failure/);
    const result2 = await succeedingTask;
    assert.equal(result2, 'Task 2 success');
  });
});
