/**
 * Shadow : Helix Nebula (SHN) — Execution Supervisor & Sandboxed Worker Contracts
 *
 * Authoritative Spec: Phase 0.3 (BC-EXE, BC-WFO), Phase 0.4 (INV-01, INV-14),
 *                    Phase 0.7 Section 4.2.5 (mod_execution_supervisor),
 *                    Phase 0.9 Sections 7 & 8 (Tool Integration & Sandboxing),
 *                    Phase 0.10 Sections 4 & 5, Phase 0.14 Section 19.
 */

import type {
  ExecutionId,
  WorkerId,
  WorkspaceId,
  OrganizationId,
  UserId,
  ScopeId,
  IsoTimestamp,
  SecurityContextToken,
  Result,
} from '@shn/shared-kernel';
import type { ProblemDetails } from '@shn/error-catalog';
import type { ScopeDefinition, ScopeToken } from '@shn/scope-gatekeeper';

// ----------------------------------------------------------------------------
// 1. Execution State Machine & Lifecycle
// ----------------------------------------------------------------------------

export type ExecutionState =
  | 'CREATED'
  | 'VALIDATING'
  | 'AUTHORIZED'
  | 'QUEUED'
  | 'STARTING'
  | 'RUNNING'
  | 'CANCELLING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'TIMED_OUT'
  | 'CANCELLED'
  | 'TERMINATED'
  | 'REJECTED';

export const TERMINAL_STATES: ReadonlySet<ExecutionState> = new Set([
  'SUCCEEDED',
  'FAILED',
  'TIMED_OUT',
  'CANCELLED',
  'TERMINATED',
  'REJECTED',
]);

export function isTerminalState(state: ExecutionState): boolean {
  return TERMINAL_STATES.has(state);
}

export const LEGAL_TRANSITIONS: ReadonlyMap<ExecutionState, ReadonlySet<ExecutionState>> = new Map([
  ['CREATED', new Set(['VALIDATING', 'REJECTED', 'CANCELLED'])],
  ['VALIDATING', new Set(['AUTHORIZED', 'REJECTED', 'CANCELLED'])],
  ['AUTHORIZED', new Set(['QUEUED', 'STARTING', 'REJECTED', 'CANCELLED'])],
  ['QUEUED', new Set(['STARTING', 'CANCELLED', 'TIMED_OUT'])],
  ['STARTING', new Set(['RUNNING', 'FAILED', 'TIMED_OUT', 'CANCELLING', 'TERMINATED'])],
  ['RUNNING', new Set(['SUCCEEDED', 'FAILED', 'TIMED_OUT', 'CANCELLING', 'TERMINATED'])],
  ['CANCELLING', new Set(['CANCELLED', 'TERMINATED', 'FAILED', 'TIMED_OUT'])],
  ['SUCCEEDED', new Set()],
  ['FAILED', new Set()],
  ['TIMED_OUT', new Set()],
  ['CANCELLED', new Set()],
  ['TERMINATED', new Set()],
  ['REJECTED', new Set()],
]);

export function isValidStateTransition(from: ExecutionState, to: ExecutionState): boolean {
  const allowed = LEGAL_TRANSITIONS.get(from);
  return allowed ? allowed.has(to) : false;
}

// ----------------------------------------------------------------------------
// 2. Termination Reason
// ----------------------------------------------------------------------------

export type ExecutionTerminationReason =
  | 'NORMAL_EXIT'
  | 'PROCESS_CRASH'
  | 'TIMEOUT_WALL_CLOCK'
  | 'TIMEOUT_STARTUP'
  | 'OPERATOR_CANCELLED'
  | 'RESOURCE_LIMIT_EXCEEDED'
  | 'OUTPUT_LIMIT_EXCEEDED'
  | 'PROTOCOL_VIOLATION'
  | 'SUPERVISOR_TERMINATION'
  | 'SANDBOX_BREACH'
  | 'SCOPE_VIOLATION';

// ----------------------------------------------------------------------------
// 3. Resource Policy & Limits
// ----------------------------------------------------------------------------

export interface ResourceLimits {
  readonly timeoutMs: number;
  readonly startupTimeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
  readonly maxCombinedOutputBytes: number;
  readonly cancellationGracePeriodMs: number;
  readonly maxArtifactSizeBytes: number;
  readonly maxEnvironmentBytes: number;
}

export const DEFAULT_RESOURCE_LIMITS: ResourceLimits = {
  timeoutMs: 30_000,
  startupTimeoutMs: 5_000,
  maxStdoutBytes: 1024 * 1024, // 1 MB
  maxStderrBytes: 1024 * 1024, // 1 MB
  maxCombinedOutputBytes: 2 * 1024 * 1024, // 2 MB
  cancellationGracePeriodMs: 2_000,
  maxArtifactSizeBytes: 10 * 1024 * 1024, // 10 MB
  maxEnvironmentBytes: 32 * 1024, // 32 KB
};

// ----------------------------------------------------------------------------
// 4. Execution Request & Specification
// ----------------------------------------------------------------------------

export interface ExecutionIdentity {
  readonly actorId: UserId;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
}

export interface ExecutionAuthorizationContext {
  readonly securityContext: SecurityContextToken;
  readonly requiredPermission: number;
  readonly action: string;
}

export interface ExecutionScope {
  readonly target: string;
  readonly port?: number | undefined;
  readonly scopeId?: ScopeId | undefined;
  readonly scopeToken?: ScopeToken | undefined;
  readonly scopeOverride?: ScopeDefinition | undefined;
  readonly allowMetadata?: boolean | undefined;
}

export interface ExecutionPolicy {
  readonly retryOnCrash?: boolean | undefined;
  readonly maxRetries?: number | undefined;
  readonly failOnNonZeroExit?: boolean | undefined;
  readonly failOnOutputLimit?: boolean | undefined;
}

export interface WorkerSpecification {
  readonly workerId: WorkerId;
  readonly executable: string;
  readonly args: readonly string[];
  readonly workingDirectory: string;
  readonly env: Record<string, string>;
  readonly resourceLimits: ResourceLimits;
}

export interface WorkerLifecycle {
  readonly workerId: WorkerId;
  readonly executionId: ExecutionId;
  readonly pid?: number | undefined;
  readonly status: 'PENDING' | 'RUNNING' | 'EXITED' | 'KILLED';
  readonly startedAt: IsoTimestamp;
  readonly heartbeatAt: IsoTimestamp;
  readonly exitedAt?: IsoTimestamp | undefined;
  readonly exitCode?: number | null | undefined;
}

export interface ExecutionRequest {
  readonly id?: ExecutionId | undefined;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly requestedBy: UserId;
  readonly securityContext: SecurityContextToken;
  readonly action: string;
  readonly target: string;
  readonly port?: number | undefined;
  readonly capabilityUri: string;
  readonly scopeId?: ScopeId | undefined;
  readonly scopeToken?: ScopeToken | undefined;
  readonly scopeOverride?: ScopeDefinition | undefined;
  readonly command: {
    readonly executable: string;
    readonly args: readonly string[];
  };
  readonly environment?: Record<string, string> | undefined;
  readonly inputPayload?: unknown | undefined;
  readonly resourceLimits?: Partial<ResourceLimits> | undefined;
  readonly executionPolicy?: ExecutionPolicy | undefined;
  readonly allowMetadata?: boolean | undefined;
}

// ----------------------------------------------------------------------------
// 5. Artifacts, Evidence & Result
// ----------------------------------------------------------------------------

export interface ExecutionArtifactReference {
  readonly name: string;
  readonly contentSha256: string;
  readonly storageUri: string;
  readonly byteSize: number;
  readonly mimeType: string;
}

export interface ExecutionEvidence {
  readonly rawOutputSha256: string;
  readonly stdoutBlobUri?: string | undefined;
  readonly stderrBlobUri?: string | undefined;
  readonly artifacts: readonly ExecutionArtifactReference[];
}

export interface ExecutionTelemetry {
  readonly durationMs: number;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly peakMemoryRssBytes?: number | undefined;
  readonly peakCpuPercent?: number | undefined;
}

export interface ExecutionFailure {
  readonly code: string;
  readonly message: string;
  readonly terminationReason: ExecutionTerminationReason;
  readonly details?: unknown | undefined;
}

export interface ExecutionResult {
  readonly executionId: ExecutionId;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly state: ExecutionState;
  readonly exitCode: number | null;
  readonly terminationReason: ExecutionTerminationReason;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly outputSha256: string;
  readonly payload?: unknown | undefined;
  readonly artifacts: readonly ExecutionArtifactReference[];
  readonly telemetry: ExecutionTelemetry;
  readonly failure?: ExecutionFailure | undefined;
  readonly startedAt?: IsoTimestamp | undefined;
  readonly completedAt: IsoTimestamp;
}

export interface CancellationRequest {
  readonly executionId: ExecutionId;
  readonly workspaceId: WorkspaceId;
  readonly reason: string;
  readonly requestedBy: UserId;
}

// ----------------------------------------------------------------------------
// 6. Execution Supervisor Interface
// ----------------------------------------------------------------------------

export interface IExecutionSupervisor {
  /**
   * Submits an execution request, validates authorization and scope,
   * persists control plane record, and executes the sandboxed worker.
   */
  execute(request: ExecutionRequest): Promise<Result<ExecutionResult, ProblemDetails>>;

  /**
   * Retrieves status and result of a previously submitted execution.
   */
  getExecution(
    id: ExecutionId,
    workspaceId: WorkspaceId
  ): Promise<Result<ExecutionResult, ProblemDetails>>;

  /**
   * Requests cancellation of an in-flight execution.
   */
  cancelExecution(request: CancellationRequest): Promise<Result<void, ProblemDetails>>;
}
