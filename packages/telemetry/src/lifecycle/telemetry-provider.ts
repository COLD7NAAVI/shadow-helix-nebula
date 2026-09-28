/**
 * Shadow : Helix Nebula (SHN) — Telemetry Provider & Unified Substrate
 *
 * Coordinates Logger, Tracer, Meter, and HealthRegistry lifecycles (0.7 mod_telemetry_observability).
 */

import { type TelemetryConfig } from '../config/telemetry-config.js';
import { type ILogger, createLogger } from '../logger/logger.js';
import { type ILogSink, ConsoleLogSink } from '../logger/log-sink.js';
import { type ITracer, createTracer } from '../tracing/tracer.js';
import {
  type IMeter,
  createMeter,
  createStandardPlatformMetrics,
} from '../metrics/meter.js';
import { type IHealthRegistry, createHealthRegistry } from '../health/health.js';

export interface TelemetryProviderOptions {
  readonly config: TelemetryConfig;
  readonly logSink?: ILogSink | undefined;
}

export interface ITelemetryProvider {
  readonly config: TelemetryConfig;
  readonly logger: ILogger;
  readonly tracer: ITracer;
  readonly meter: IMeter;
  readonly health: IHealthRegistry;
  readonly standardMetrics: ReturnType<typeof createStandardPlatformMetrics>;
  start(): void;
  shutdown(): Promise<void>;
  isStarted(): boolean;
}

export class TelemetryProvider implements ITelemetryProvider {
  readonly config: TelemetryConfig;
  readonly logger: ILogger;
  readonly tracer: ITracer;
  readonly meter: IMeter;
  readonly health: IHealthRegistry;
  readonly standardMetrics: ReturnType<typeof createStandardPlatformMetrics>;
  private started: boolean = false;
  private isShutdown: boolean = false;

  constructor(options: TelemetryProviderOptions) {
    this.config = options.config;

    const logSink = options.logSink ?? new ConsoleLogSink(this.config.logFormat);

    this.logger = createLogger({
      component: this.config.serviceName,
      minLevel: this.config.logLevel,
      sink: logSink,
      enableRedaction: this.config.enableRedaction,
      defaultAttributes: {
        node_id: this.config.nodeId,
        environment: this.config.environment,
      },
    });

    this.tracer = createTracer(this.config.serviceName);
    this.meter = createMeter();
    this.standardMetrics = createStandardPlatformMetrics(this.meter);
    this.health = createHealthRegistry();
  }

  isStarted(): boolean {
    return this.started && !this.isShutdown;
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    this.logger.debug('Telemetry provider started', {
      service: this.config.serviceName,
      node_id: this.config.nodeId,
      environment: this.config.environment,
    });
  }

  async shutdown(): Promise<void> {
    if (this.isShutdown) return;
    this.isShutdown = true;
    this.started = false;
    this.logger.debug('Telemetry provider shut down gracefully');
  }
}

export function createTelemetryProvider(options: TelemetryProviderOptions): ITelemetryProvider {
  return new TelemetryProvider(options);
}
