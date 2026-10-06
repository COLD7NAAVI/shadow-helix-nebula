/**
 * Shadow : Helix Nebula (SHN) — Execution Supervisor & Sandboxed Worker
 *
 * Public facade conforming to MOD-INV-01.
 */

export {
  type ExecutionState,
  type ExecutionTerminationReason,
  type ResourceLimits,
  type ExecutionRequest,
  type ExecutionResult,
  type ExecutionFailure,
  type ExecutionArtifactReference,
  type ExecutionEvidence,
  type ExecutionTelemetry,
  type CancellationRequest,
  type IExecutionSupervisor,
  DEFAULT_RESOURCE_LIMITS,
  TERMINAL_STATES,
  LEGAL_TRANSITIONS,
  isValidStateTransition,
  isTerminalState,
} from './contracts.js';

export { makeExecutionProblem } from './errors.js';

export {
  PROTOCOL_VERSION,
  MAX_MESSAGE_BYTES,
  type WorkerToSupervisorMessage,
  type SupervisorToWorkerMessage,
  type WorkerStartupMessage,
  type WorkerHeartbeatMessage,
  type WorkerOutputMessage,
  type WorkerCompletedMessage,
  type WorkerFailedMessage,
  type SupervisorInitMessage,
  type SupervisorCancelMessage,
  type SupervisorTerminateMessage,
} from './protocol/messages.js';

export {
  encodeProtocolMessage,
  decodeWorkerMessage,
  decodeSupervisorMessage,
} from './protocol/codec.js';

export {
  spawnSandboxedWorker,
  buildSanitizedEnvironment,
  validateCommandArguments,
  type SpawnWorkerOptions,
  type SpawnedWorker,
} from './sandbox/process-spawner.js';

export { killProcessTree } from './sandbox/process-killer.js';

export { OutputTap, type OutputTapOptions } from './sandbox/output-tap.js';

export {
  SandboxedWorkerRunner,
  type WorkerTaskHandler,
} from './worker/worker-runner.js';

export {
  ExecutionSupervisor,
  type ExecutionSupervisorOptions,
} from './supervisor/execution-supervisor.js';
