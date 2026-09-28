/**
 * Shadow : Helix Nebula (SHN) — Per-Partition Ordering & Serialization Engine
 *
 * Guarantees per-aggregate / per-workspace FIFO ordering across concurrent workers
 * while permitting full concurrency across independent partitions (0.14 Section 16).
 */

export interface SequencedTask<T> {
  readonly partitionKey: string;
  readonly sequenceNumber?: number | undefined;
  readonly execute: () => Promise<T>;
}

export class PartitionQueue {
  private readonly queues = new Map<string, Promise<unknown>>();
  private readonly lastSequences = new Map<string, number>();

  /**
   * Enqueues a task for serial execution within its specific partitionKey.
   * Tasks with different partitionKeys execute concurrently.
   * If sequenceNumber is supplied, validates that it is monotonically increasing.
   */
  async enqueue<T>(task: SequencedTask<T>): Promise<T> {
    const { partitionKey, sequenceNumber, execute } = task;

    if (sequenceNumber !== undefined) {
      const lastSeq = this.lastSequences.get(partitionKey);
      if (lastSeq !== undefined && sequenceNumber <= lastSeq) {
        throw new Error(
          `Stale or out-of-order event rejected in partition "${partitionKey}": received sequence ${sequenceNumber}, current is ${lastSeq}`
        );
      }
      this.lastSequences.set(partitionKey, sequenceNumber);
    }

    const previousPromise = this.queues.get(partitionKey) ?? Promise.resolve();

    const currentPromise = previousPromise.then(
      async () => execute(),
      async () => execute() // continue partition processing even if previous failed
    );

    // Keep queue chain alive
    this.queues.set(
      partitionKey,
      currentPromise.catch(() => {})
    );

    try {
      return await currentPromise;
    } finally {
      if (this.queues.get(partitionKey) === currentPromise) {
        this.queues.delete(partitionKey);
      }
    }
  }

  getActivePartitionCount(): number {
    return this.queues.size;
  }
}
