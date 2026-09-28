/**
 * @shn/telemetry — Public Facade
 *
 * Observability, structured logging, distributed tracing, metrics,
 * and operational health contracts.
 * Enforces MOD-INV-01: Explicit exported contracts only.
 */

// Security-Aware Redaction
export {
  type RedactionOptions,
  redactSensitiveData,
  sanitizeString,
} from './redaction/redactor.js';

// Asynchronous Context Propagation
export {
  type TelemetryContextData,
  getTelemetryContext,
  runWithTelemetryContext,
  bindTelemetryContext,
} from './context/telemetry-context.js';

// Structured Logging
export {
  type LogLevel,
  isLogLevelEnabled,
  parseLogLevel,
} from './logger/log-level.js';

export {
  type ILogSink,
  type StructuredLogEntry,
  ConsoleLogSink,
  BufferedLogSink,
} from './logger/log-sink.js';

export {
  type ILogger,
  type LoggerOptions,
  createLogger,
} from './logger/logger.js';

// W3C Distributed Tracing
export {
  type SpanContext,
  isValidTraceId,
  isValidSpanId,
  generateTraceId,
  generateSpanId,
  parseW3CTraceparent,
  formatW3CTraceparent,
} from './tracing/trace-context.js';

export {
  type ITracer,
  type ISpan,
  type SpanKind,
  type SpanStatus,
  type SpanEvent,
  type SpanOptions,
  createTracer,
} from './tracing/tracer.js';

// Prometheus Metrics
export {
  type ICounter,
  type IGauge,
  type IHistogram,
  type HistogramSnapshot,
} from './metrics/metric-instruments.js';

export {
  type IMeter,
  createMeter,
  createStandardPlatformMetrics,
} from './metrics/meter.js';

// Operational Health & Diagnostics
export {
  type HealthStatus,
  type ComponentHealth,
  type CompositeHealthReport,
  type HealthCheckFn,
  type IHealthRegistry,
  createHealthRegistry,
} from './health/health.js';

// Telemetry Configuration
export {
  type TelemetryConfig,
  parseTelemetryConfig,
  loadTelemetryConfigFromEnv,
} from './config/telemetry-config.js';

// Unified Telemetry Provider Lifecycle
export {
  type ITelemetryProvider,
  type TelemetryProviderOptions,
  createTelemetryProvider,
} from './lifecycle/telemetry-provider.js';
