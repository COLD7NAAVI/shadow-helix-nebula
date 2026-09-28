/**
 * Shadow : Helix Nebula (SHN) — Metric Instruments Contracts
 */

export interface ICounter {
  readonly name: string;
  readonly description: string;
  readonly unit: string;
  add(value: number, labels?: Readonly<Record<string, string>>): void;
  inc(labels?: Readonly<Record<string, string>>): void;
  getValue(labels?: Readonly<Record<string, string>>): number;
}

export interface IGauge {
  readonly name: string;
  readonly description: string;
  readonly unit: string;
  set(value: number, labels?: Readonly<Record<string, string>>): void;
  inc(value?: number, labels?: Readonly<Record<string, string>>): void;
  dec(value?: number, labels?: Readonly<Record<string, string>>): void;
  getValue(labels?: Readonly<Record<string, string>>): number;
}

export interface IHistogram {
  readonly name: string;
  readonly description: string;
  readonly unit: string;
  readonly boundaries: readonly number[];
  record(value: number, labels?: Readonly<Record<string, string>>): void;
  getSnapshot(labels?: Readonly<Record<string, string>>): HistogramSnapshot;
}

export interface HistogramSnapshot {
  readonly count: number;
  readonly sum: number;
  readonly buckets: ReadonlyMap<number, number>;
}
