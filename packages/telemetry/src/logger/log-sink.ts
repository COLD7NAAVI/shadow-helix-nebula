/**
 * Shadow : Helix Nebula (SHN) — Structured Log Sinks
 *
 * Implements standard JSON log output and test buffering sinks (OBS-TEL-001).
 */

import type { LogLevel } from './log-level.js';

export interface StructuredLogEntry {
  readonly timestamp: string;
  readonly level: LogLevel;
  readonly component: string;
  readonly message: string;
  readonly correlation_id?: string | undefined;
  readonly causation_id?: string | undefined;
  readonly trace_id?: string | undefined;
  readonly span_id?: string | undefined;
  readonly workspace_id?: string | undefined;
  readonly attributes?: Readonly<Record<string, unknown>> | undefined;
  readonly error?: unknown | undefined;
}

export interface ILogSink {
  write(entry: StructuredLogEntry): void;
}

export class ConsoleLogSink implements ILogSink {
  constructor(private readonly format: 'json' | 'pretty' = 'json') {}

  write(entry: StructuredLogEntry): void {
    if (this.format === 'pretty') {
      const time = entry.timestamp.slice(11, 23);
      const levelUpper = entry.level.toUpperCase().padEnd(5);
      const corr = entry.correlation_id ? ` [${entry.correlation_id}]` : '';
      const attrs = entry.attributes && Object.keys(entry.attributes).length > 0
        ? ` ${JSON.stringify(entry.attributes)}`
        : '';
      const err = entry.error ? `\n  Error: ${JSON.stringify(entry.error)}` : '';
      const output = `${time} ${levelUpper} [${entry.component}]${corr} ${entry.message}${attrs}${err}\n`;
      if (entry.level === 'error') {
        process.stderr.write(output);
      } else {
        process.stdout.write(output);
      }
    } else {
      const line = JSON.stringify(entry) + '\n';
      if (entry.level === 'error') {
        process.stderr.write(line);
      } else {
        process.stdout.write(line);
      }
    }
  }
}

export class BufferedLogSink implements ILogSink {
  private readonly buffer: StructuredLogEntry[] = [];
  private readonly maxCapacity: number;

  constructor(maxCapacity: number = 1000) {
    this.maxCapacity = maxCapacity;
  }

  write(entry: StructuredLogEntry): void {
    if (this.buffer.length >= this.maxCapacity) {
      this.buffer.shift();
    }
    this.buffer.push(entry);
  }

  getEntries(): readonly StructuredLogEntry[] {
    return [...this.buffer];
  }

  clear(): void {
    this.buffer.length = 0;
  }

  find(predicate: (entry: StructuredLogEntry) => boolean): StructuredLogEntry | undefined {
    return this.buffer.find(predicate);
  }

  filter(predicate: (entry: StructuredLogEntry) => boolean): StructuredLogEntry[] {
    return this.buffer.filter(predicate);
  }
}
