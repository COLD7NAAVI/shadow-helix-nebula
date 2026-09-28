/**
 * Shadow : Helix Nebula (SHN) — Prometheus-Compatible Metrics Meter
 *
 * Implements thread-safe in-process metrics recording with strict label-cardinality
 * bounds and Prometheus exposition format serialization (OBS-MET-001, 0.14 Section 25).
 */

import type {
  ICounter,
  IGauge,
  IHistogram,
  HistogramSnapshot,
} from './metric-instruments.js';

const VALID_LABEL_REGEX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const MAX_UNIQUE_LABEL_VALUES = 50;
const DEFAULT_HISTOGRAM_BOUNDARIES = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

/**
 * Sanitizes labels and enforces cardinality bounds.
 */
class CardinalityGuard {
  private readonly labelValueSets = new Map<string, Set<string>>();

  sanitizeLabels(labels?: Readonly<Record<string, string>>): Record<string, string> {
    if (!labels) return {};
    const sanitized: Record<string, string> = {};

    for (const [k, v] of Object.entries(labels)) {
      if (!VALID_LABEL_REGEX.test(k)) {
        continue;
      }

      // Bound value length
      let cleanVal = String(v).slice(0, 128);

      let valueSet = this.labelValueSets.get(k);
      if (!valueSet) {
        valueSet = new Set<string>();
        this.labelValueSets.set(k, valueSet);
      }

      if (valueSet.size >= MAX_UNIQUE_LABEL_VALUES && !valueSet.has(cleanVal)) {
        cleanVal = 'other';
      } else {
        valueSet.add(cleanVal);
      }

      sanitized[k] = cleanVal;
    }

    return sanitized;
  }
}

function serializeLabelKey(labels: Record<string, string>): string {
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return '';
  return keys.map(k => `${k}="${labels[k]?.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(',');
}

class Counter implements ICounter {
  readonly name: string;
  readonly description: string;
  readonly unit: string;
  private readonly values = new Map<string, number>();
  private readonly cardinalityGuard: CardinalityGuard;

  constructor(name: string, description: string = '', unit: string = '', guard: CardinalityGuard) {
    this.name = name;
    this.description = description;
    this.unit = unit;
    this.cardinalityGuard = guard;
  }

  add(value: number, labels?: Readonly<Record<string, string>>): void {
    if (value < 0 || isNaN(value)) return;
    const sanitized = this.cardinalityGuard.sanitizeLabels(labels);
    const key = serializeLabelKey(sanitized);
    const current = this.values.get(key) ?? 0;
    this.values.set(key, current + value);
  }

  inc(labels?: Readonly<Record<string, string>>): void {
    this.add(1, labels);
  }

  getValue(labels?: Readonly<Record<string, string>>): number {
    const sanitized = this.cardinalityGuard.sanitizeLabels(labels);
    const key = serializeLabelKey(sanitized);
    return this.values.get(key) ?? 0;
  }

  getSeries(): Array<{ labels: string; value: number }> {
    return Array.from(this.values.entries()).map(([labels, value]) => ({ labels, value }));
  }
}

class Gauge implements IGauge {
  readonly name: string;
  readonly description: string;
  readonly unit: string;
  private readonly values = new Map<string, number>();
  private readonly cardinalityGuard: CardinalityGuard;

  constructor(name: string, description: string = '', unit: string = '', guard: CardinalityGuard) {
    this.name = name;
    this.description = description;
    this.unit = unit;
    this.cardinalityGuard = guard;
  }

  set(value: number, labels?: Readonly<Record<string, string>>): void {
    if (isNaN(value)) return;
    const sanitized = this.cardinalityGuard.sanitizeLabels(labels);
    const key = serializeLabelKey(sanitized);
    this.values.set(key, value);
  }

  inc(value: number = 1, labels?: Readonly<Record<string, string>>): void {
    const current = this.getValue(labels);
    this.set(current + value, labels);
  }

  dec(value: number = 1, labels?: Readonly<Record<string, string>>): void {
    const current = this.getValue(labels);
    this.set(current - value, labels);
  }

  getValue(labels?: Readonly<Record<string, string>>): number {
    const sanitized = this.cardinalityGuard.sanitizeLabels(labels);
    const key = serializeLabelKey(sanitized);
    return this.values.get(key) ?? 0;
  }

  getSeries(): Array<{ labels: string; value: number }> {
    return Array.from(this.values.entries()).map(([labels, value]) => ({ labels, value }));
  }
}

interface HistogramData {
  count: number;
  sum: number;
  bucketCounts: number[];
}

class Histogram implements IHistogram {
  readonly name: string;
  readonly description: string;
  readonly unit: string;
  readonly boundaries: readonly number[];
  private readonly series = new Map<string, HistogramData>();
  private readonly cardinalityGuard: CardinalityGuard;

  constructor(
    name: string,
    boundaries: number[] = DEFAULT_HISTOGRAM_BOUNDARIES,
    description: string = '',
    unit: string = '',
    guard: CardinalityGuard
  ) {
    this.name = name;
    this.description = description;
    this.unit = unit;
    this.boundaries = [...boundaries].sort((a, b) => a - b);
    this.cardinalityGuard = guard;
  }

  record(value: number, labels?: Readonly<Record<string, string>>): void {
    if (isNaN(value) || value < 0) return;
    const sanitized = this.cardinalityGuard.sanitizeLabels(labels);
    const key = serializeLabelKey(sanitized);

    let data = this.series.get(key);
    if (!data) {
      data = {
        count: 0,
        sum: 0,
        bucketCounts: new Array(this.boundaries.length).fill(0),
      };
      this.series.set(key, data);
    }

    data.count += 1;
    data.sum = Math.round((data.sum + value) * 1e9) / 1e9;

    for (let i = 0; i < this.boundaries.length; i++) {
      if (value <= this.boundaries[i]!) {
        data.bucketCounts[i] = (data.bucketCounts[i] ?? 0) + 1;
      }
    }
  }

  getSnapshot(labels?: Readonly<Record<string, string>>): HistogramSnapshot {
    const sanitized = this.cardinalityGuard.sanitizeLabels(labels);
    const key = serializeLabelKey(sanitized);
    const data = this.series.get(key);

    const buckets = new Map<number, number>();
    for (let i = 0; i < this.boundaries.length; i++) {
      buckets.set(this.boundaries[i]!, data?.bucketCounts[i] ?? 0);
    }

    return {
      count: data?.count ?? 0,
      sum: data?.sum ?? 0,
      buckets,
    };
  }

  getSeries(): Array<{ labels: string; data: HistogramData }> {
    return Array.from(this.series.entries()).map(([labels, data]) => ({ labels, data }));
  }
}

export interface IMeter {
  createCounter(name: string, description?: string, unit?: string): ICounter;
  createGauge(name: string, description?: string, unit?: string): IGauge;
  createHistogram(name: string, boundaries?: number[], description?: string, unit?: string): IHistogram;
  exportPrometheus(): string;
  reset(): void;
}

export class PrometheusMeter implements IMeter {
  private readonly counters = new Map<string, Counter>();
  private readonly gauges = new Map<string, Gauge>();
  private readonly histograms = new Map<string, Histogram>();
  private readonly guard = new CardinalityGuard();

  createCounter(name: string, description: string = '', unit: string = ''): ICounter {
    let counter = this.counters.get(name);
    if (!counter) {
      counter = new Counter(name, description, unit, this.guard);
      this.counters.set(name, counter);
    }
    return counter;
  }

  createGauge(name: string, description: string = '', unit: string = ''): IGauge {
    let gauge = this.gauges.get(name);
    if (!gauge) {
      gauge = new Gauge(name, description, unit, this.guard);
      this.gauges.set(name, gauge);
    }
    return gauge;
  }

  createHistogram(
    name: string,
    boundaries: number[] = DEFAULT_HISTOGRAM_BOUNDARIES,
    description: string = '',
    unit: string = ''
  ): IHistogram {
    let histogram = this.histograms.get(name);
    if (!histogram) {
      histogram = new Histogram(name, boundaries, description, unit, this.guard);
      this.histograms.set(name, histogram);
    }
    return histogram;
  }

  exportPrometheus(): string {
    const lines: string[] = [];

    // Export Counters
    for (const [name, counter] of this.counters.entries()) {
      if (counter.description) lines.push(`# HELP ${name} ${counter.description}`);
      lines.push(`# TYPE ${name} counter`);
      const series = counter.getSeries();
      if (series.length === 0) {
        lines.push(`${name} 0`);
      } else {
        for (const s of series) {
          const l = s.labels ? `{${s.labels}}` : '';
          lines.push(`${name}${l} ${s.value}`);
        }
      }
    }

    // Export Gauges
    for (const [name, gauge] of this.gauges.entries()) {
      if (gauge.description) lines.push(`# HELP ${name} ${gauge.description}`);
      lines.push(`# TYPE ${name} gauge`);
      const series = gauge.getSeries();
      if (series.length === 0) {
        lines.push(`${name} 0`);
      } else {
        for (const s of series) {
          const l = s.labels ? `{${s.labels}}` : '';
          lines.push(`${name}${l} ${s.value}`);
        }
      }
    }

    // Export Histograms
    for (const [name, histogram] of this.histograms.entries()) {
      if (histogram.description) lines.push(`# HELP ${name} ${histogram.description}`);
      lines.push(`# TYPE ${name} histogram`);
      const series = histogram.getSeries();
      for (const s of series) {
        const prefix = s.labels ? `${s.labels},` : '';
        for (let i = 0; i < histogram.boundaries.length; i++) {
          const b = histogram.boundaries[i]!;
          lines.push(`${name}_bucket{${prefix}le="${b}"} ${s.data.bucketCounts[i] ?? 0}`);
        }
        lines.push(`${name}_bucket{${prefix}le="+Inf"} ${s.data.count}`);
        const labelStr = s.labels ? `{${s.labels}}` : '';
        lines.push(`${name}_sum${labelStr} ${s.data.sum}`);
        lines.push(`${name}_count${labelStr} ${s.data.count}`);
      }
    }

    return lines.join('\n') + '\n';
  }

  reset(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
  }
}

export function createMeter(): IMeter {
  return new PrometheusMeter();
}

/**
 * Creates the standard platform metrics suite required by the frozen architecture.
 */
export function createStandardPlatformMetrics(meter: IMeter) {
  return {
    eventsPublishedTotal: meter.createCounter(
      'shn_events_published_total',
      'Total number of domain events published to the event substrate'
    ),
    eventsClaimedTotal: meter.createCounter(
      'shn_events_claimed_total',
      'Total number of outbox events claimed by workers'
    ),
    eventsDispatchedTotal: meter.createCounter(
      'shn_events_dispatched_total',
      'Total number of events dispatched to handlers'
    ),
    eventsRetriedTotal: meter.createCounter(
      'shn_events_retried_total',
      'Total number of event delivery attempts scheduled for retry'
    ),
    eventsDeadLetterTotal: meter.createCounter(
      'shn_events_dead_letter_total',
      'Total number of events quarantined to the dead-letter queue'
    ),
    outboxPendingDepth: meter.createGauge(
      'shn_outbox_pending_depth',
      'Current number of pending outbox events awaiting dispatch'
    ),
    outboxOldestAgeSeconds: meter.createGauge(
      'shn_outbox_oldest_age_seconds',
      'Age in seconds of the oldest pending outbox event'
    ),
    dispatchDurationSeconds: meter.createHistogram(
      'shn_dispatch_duration_seconds',
      [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5],
      'Duration in seconds of event dispatch cycles'
    ),
    handlerDurationSeconds: meter.createHistogram(
      'shn_handler_duration_seconds',
      [0.001, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30],
      'Duration in seconds of domain event handler execution'
    ),
    workerConcurrencyActive: meter.createGauge(
      'shn_worker_concurrency_active',
      'Number of worker tasks currently executing event handlers'
    ),
    databaseHealthStatus: meter.createGauge(
      'shn_database_health_status',
      'Database health probe status (1 = UP, 0 = DOWN)'
    ),
  };
}
