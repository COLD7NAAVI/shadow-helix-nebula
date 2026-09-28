/**
 * @shn/event-bus — Public Facade
 *
 * Event substrate, strongly typed contracts, transactional outbox,
 * at-least-once durable dispatch, idempotency, retries, and dead-letter handling.
 * Enforces MOD-INV-01: Explicit exported contracts only.
 */

// Event Envelope Validation
export {
  validateCanonicalEventEnvelope,
} from './registry/event-validator.js';

// Event Handler Registry & Compatibility
export {
  type EventHandler,
  type HandlerRegistrationOptions,
  type RegisteredHandler,
  type IEventRegistry,
  isSchemaVersionCompatible,
  createEventRegistry,
} from './registry/event-registry.js';

// Transactional & Non-Transactional Publication
export {
  type DeliveryMode,
  type PublishReceipt,
  type EventPublisherOptions,
  type IEventPublisher,
  createEventPublisher,
} from './publisher/event-publisher.js';

// In-Process Event Bus
export {
  type IInProcessEventBus,
  createInProcessEventBus,
} from './in-process/in-process-bus.js';

// Event Dispatcher & Retry Pipeline
export {
  type RetryPolicyConfig,
  type DispatcherMetrics,
  type EventDispatcherOptions,
  type DispatchResult,
  type IEventDispatcher,
  createEventDispatcher,
} from './dispatcher/event-dispatcher.js';

// Outbox Poller & Background Worker
export {
  type OutboxPollerOptions,
  type IOutboxPoller,
  createOutboxPoller,
} from './outbox/outbox-poller.js';

// Dead-Letter Quarantine & Replay Manager
export {
  type ReplayOptions,
  type IReplayManager,
  createReplayManager,
} from './dead-letter/replay-manager.js';

// Per-Aggregate Ordering & Partition Serialization
export {
  type SequencedTask,
  PartitionQueue,
} from './ordering/partition-queue.js';

// Configuration
export {
  type EventBusConfig,
  parseEventBusConfig,
  loadEventBusConfigFromEnv,
} from './config/event-bus-config.js';

// Unified Event Bus Substrate Lifecycle
export {
  type EventBusSubstrateOptions,
  type IEventBusSubstrate,
  createEventBusSubstrate,
} from './lifecycle/event-bus-substrate.js';
