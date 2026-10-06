/**
 * Shadow : Helix Nebula (SHN) — Centralized Execution Supervisor
 *
 * Implements Phase 0.3 (BC-EXE), Phase 0.4 (INV-01, INV-14),
 * Phase 0.7 Section 4.2.5 (mod_execution_supervisor),
 * Phase 0.9 (Tool Integration & Sandboxing), Phase 0.11 Section 4,
 * and Phase 0.14 Section 19.
 *
 * Authoritative control-plane orchestrator:
 * - Request validation & fail-closed authorization
 * - Tenant & workspace boundary enforcement
 * - Pre-dispatch scope evaluation via Stage 5 ScopeGatekeeper
 * - Deterministic state machine management
 * - Ephemeral scratch isolation and environment allowlisting
 * - Bounded output capture and cryptographic evidence sealing
 * - Process tree termination, timeout, and cancellation handling
 * - Audit event publishing and telemetry redaction
 */

import readline from 'node:readline';
import {
  type ExecutionId,
  type WorkerId,
  type WorkspaceId,
  type IsoTimestamp,
  type SecurityContextToken,
  type TraceId,
  createExecutionId,
  createWorkerId,
  createEventId,
  createCorrelationId,
  createCausationId,
  createCanonicalEventEnvelope,
  generateUUIDv7,
  generateUUIDv4,
  nowIso,
  ok,
  err,
  type Result,
} from '@shn/shared-kernel';
import { ErrorCode, type ErrorCodeType, type ProblemDetails } from '@shn/error-catalog';
import {
  PermissionBit,
  SecurityContextSigner,
} from '@shn/auth-rbac';
import {
  type IScopeGatekeeper,
  TenancyValidator,
} from '@shn/scope-gatekeeper';
import type { ExecutionRepository } from '@shn/data-access';
import type { IEventPublisher } from '@shn/event-bus';
import type { ILogger, IMeter, IHistogram } from '@shn/telemetry';

import {
  type IExecutionSupervisor,
  type ExecutionRequest,
  type ExecutionResult,
  type ExecutionState,
  type ResourceLimits,
  type CancellationRequest,
  type ExecutionArtifactReference,
  type ExecutionTerminationReason,
  DEFAULT_RESOURCE_LIMITS,
  isValidStateTransition,
  isTerminalState,
} from '../contracts.js';
import { makeExecutionProblem } from '../errors.js';
import {
  spawnSandboxedWorker,
  type SpawnedWorker,
} from '../sandbox/process-spawner.js';
import { killProcessTree } from '../sandbox/process-killer.js';
import { OutputTap } from '../sandbox/output-tap.js';
import {
  decodeWorkerMessage,
  encodeProtocolMessage,
} from '../protocol/codec.js';

export interface ExecutionSupervisorOptions {
  readonly gatekeeper: IScopeGatekeeper;
  readonly executionRepo?: ExecutionRepository | undefined;
  readonly authSigner?: SecurityContextSigner | undefined;
  readonly tenancyValidator?: TenancyValidator | undefined;
  readonly eventPublisher?: IEventPublisher | undefined;
  readonly logger?: ILogger | undefined;
  readonly meter?: IMeter | undefined;
  readonly baseScratchDir?: string | undefined;
  readonly maxConcurrentExecutions?: number | undefined;
}

interface ActiveExecutionHandle {
  readonly executionId: ExecutionId;
  readonly workspaceId: WorkspaceId;
  readonly worker: SpawnedWorker;
  readonly workerId: WorkerId;
  readonly outputTapStdout: OutputTap;
  readonly outputTapStderr: OutputTap;
  cancellationRequested: boolean;
  abortGraceTimeout: NodeJS.Timeout | null;
  lastHeartbeat: number;
}

export class ExecutionSupervisor implements IExecutionSupervisor {
  private readonly gatekeeper: IScopeGatekeeper;
  private readonly executionRepo?: ExecutionRepository | undefined;
  private readonly authSigner: SecurityContextSigner;
  private readonly tenancyValidator: TenancyValidator;
  private readonly eventPublisher?: IEventPublisher | undefined;
  private readonly logger?: ILogger | undefined;
  private readonly meter?: IMeter | undefined;
  private readonly durationHistogram?: IHistogram | undefined;
  private readonly baseScratchDir?: string | undefined;
  private readonly maxConcurrentExecutions: number;

  private readonly activeExecutions = new Map<string, ActiveExecutionHandle>();

  constructor(options: ExecutionSupervisorOptions) {
    this.gatekeeper = options.gatekeeper;
    this.executionRepo = options.executionRepo;
    this.authSigner =
      options.authSigner ??
      new SecurityContextSigner(
        process.env.SHN_AUTH_SIGNING_KEY || 'default-insecure-shn-auth-secret-key-32b'
      );
    this.tenancyValidator =
      options.tenancyValidator ?? new TenancyValidator();
    this.eventPublisher = options.eventPublisher;
    this.logger = options.logger;
    this.meter = options.meter;
    if (this.meter) {
      this.durationHistogram = this.meter.createHistogram(
        'execution_duration_ms',
        [10, 50, 100, 250, 500, 1000, 5000, 15000, 30000, 60000, 300000],
        'Execution duration in milliseconds'
      );
    }
    this.baseScratchDir = options.baseScratchDir;
    this.maxConcurrentExecutions = options.maxConcurrentExecutions ?? 10;
  }

  /**
   * Executes a requested capability or tool in a sandboxed worker.
   */
  async execute(request: ExecutionRequest): Promise<Result<ExecutionResult, ProblemDetails>> {
    const startedAtTime = Date.now();
    const startedAt = new Date(startedAtTime).toISOString() as IsoTimestamp;

    // 0. Concurrency boundary check
    if (this.activeExecutions.size >= this.maxConcurrentExecutions) {
      return err(
        makeExecutionProblem(
          ErrorCode.EXEC_RESOURCE_EXHAUSTED,
          `Maximum active sandboxed executions limit reached (${this.maxConcurrentExecutions})`
        )
      );
    }

    // 1. Resolve and validate execution ID
    const executionId =
      request.id ??
      (createExecutionId().unwrapOr(generateUUIDv7() as ExecutionId));

    // 2. Validate request parameters
    const paramValidation = this.validateRequestParameters(request);
    if (paramValidation.isErr) {
      return err(paramValidation.error);
    }

    // 3. Verify SecurityContext & Authenticated Identity
    const authRes = this.authSigner.verifyToken(request.securityContext, startedAtTime);
    if (authRes.isErr) {
      return err(
        makeExecutionProblem(
          (authRes.error.error_code as ErrorCodeType) || ErrorCode.AUTH_UNAUTHENTICATED,
          `Security context verification failed: ${authRes.error.detail}`
        )
      );
    }
    const context = authRes.value;

    // 4. Tenancy & Workspace Boundary Assertion
    const tenancyRes = this.tenancyValidator.assertWorkspaceMatch(
      context,
      request.workspaceId
    );
    if (tenancyRes.isErr) {
      return err(tenancyRes.error);
    }
    if (context.subject_id !== request.requestedBy) {
      return err(
        makeExecutionProblem(
          ErrorCode.AUTH_FORBIDDEN,
          `Context subject '${context.subject_id}' does not match requestedBy '${request.requestedBy}'`
        )
      );
    }

    const orgTenancyRes = await this.tenancyValidator.verifyWorkspaceBelongsToOrg(
      request.workspaceId,
      request.organizationId
    );
    if (orgTenancyRes.isErr) {
      return err(orgTenancyRes.error);
    }

    // 5. Action RBAC Permission Verification
    const requiredBit = this.mapActionToPermissionBit(request.action);
    if (requiredBit !== undefined) {
      if ((context.permission_mask & requiredBit) !== requiredBit) {
        return err(
          makeExecutionProblem(
            ErrorCode.AUTH_FORBIDDEN,
            `Actor '${request.requestedBy}' lacks required permission bit for action '${request.action}'`
          )
        );
      }
    }

    // 6. Pre-dispatch Scope Evaluation via Stage 5 ScopeGatekeeper
    const scopeVerdictRes = await this.gatekeeper.evaluateTarget({
      context,
      target: request.target,
      action: request.action,
      port: request.port,
      scopeId: request.scopeId,
      scopeToken: request.scopeToken,
      scopeOverride: request.scopeOverride,
      allowMetadata: request.allowMetadata,
    });

    if (scopeVerdictRes.isErr) {
      return err(scopeVerdictRes.error);
    }
    const verdict = scopeVerdictRes.value;
    if (!verdict.allowed) {
      // Record rejected execution in persistence if repo exists
      if (this.executionRepo) {
        await this.executionRepo.createExecution({
          id: executionId,
          workspace_id: request.workspaceId,
          organization_id: request.organizationId,
          scope_id: request.scopeId,
          action: request.action,
          target: request.target,
          capability_uri: request.capabilityUri,
          state: 'REJECTED',
          requested_by: request.requestedBy,
          command: request.command,
        });
      }

      return err(
        makeExecutionProblem(
          (verdict.errorCode as ErrorCodeType) || ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS,
          `Execution target rejected by Scope Gatekeeper: ${verdict.reason}`
        )
      );
    }

    // 7. Resolve Resource Limits
    const limits: ResourceLimits = {
      timeoutMs: Math.min(
        request.resourceLimits?.timeoutMs ?? DEFAULT_RESOURCE_LIMITS.timeoutMs,
        300_000 // 5 minute max ceiling
      ),
      startupTimeoutMs: Math.min(
        request.resourceLimits?.startupTimeoutMs ?? DEFAULT_RESOURCE_LIMITS.startupTimeoutMs,
        30_000
      ),
      maxStdoutBytes: Math.min(
        request.resourceLimits?.maxStdoutBytes ?? DEFAULT_RESOURCE_LIMITS.maxStdoutBytes,
        50 * 1024 * 1024 // 50 MB max ceiling
      ),
      maxStderrBytes: Math.min(
        request.resourceLimits?.maxStderrBytes ?? DEFAULT_RESOURCE_LIMITS.maxStderrBytes,
        50 * 1024 * 1024 // 50 MB max ceiling
      ),
      maxCombinedOutputBytes: Math.min(
        request.resourceLimits?.maxCombinedOutputBytes ?? DEFAULT_RESOURCE_LIMITS.maxCombinedOutputBytes,
        100 * 1024 * 1024
      ),
      cancellationGracePeriodMs:
        request.resourceLimits?.cancellationGracePeriodMs ??
        DEFAULT_RESOURCE_LIMITS.cancellationGracePeriodMs,
      maxArtifactSizeBytes:
        request.resourceLimits?.maxArtifactSizeBytes ??
        DEFAULT_RESOURCE_LIMITS.maxArtifactSizeBytes,
      maxEnvironmentBytes:
        request.resourceLimits?.maxEnvironmentBytes ??
        DEFAULT_RESOURCE_LIMITS.maxEnvironmentBytes,
    };

    // 8. Control Plane Persistence: Record AUTHORIZED
    if (this.executionRepo) {
      await this.executionRepo.createExecution({
        id: executionId,
        workspace_id: request.workspaceId,
        organization_id: request.organizationId,
        scope_id: request.scopeId,
        action: request.action,
        target: request.target,
        capability_uri: request.capabilityUri,
        state: 'AUTHORIZED',
        requested_by: request.requestedBy,
        command: request.command,
        resource_policy: limits as unknown as Record<string, unknown>,
        execution_policy: (request.executionPolicy || {}) as Record<string, unknown>,
      });
    }

    // 9. Emit Lifecycle Event: execution.authorized
    await this.emitEvent('execution.authorized', request.workspaceId, context, {
      executionId,
      workspaceId: request.workspaceId,
      organizationId: request.organizationId,
      action: request.action,
      target: request.target,
    });

    // 10. Spawn Sandboxed Worker Subprocess
    const workerId = createWorkerId().unwrapOr(generateUUIDv4() as WorkerId);
    if (this.executionRepo) {
      await this.executionRepo.acquireWorkerLease(
        workerId,
        executionId,
        request.workspaceId,
        limits.timeoutMs + 10_000
      );
      this.assertValidTransition('AUTHORIZED', 'STARTING');
      await this.executionRepo.transitionState(
        executionId,
        request.workspaceId,
        ['AUTHORIZED', 'QUEUED'],
        'STARTING',
        { started_at: startedAt }
      );
    }

    const spawnRes = await spawnSandboxedWorker({
      executable: request.command.executable,
      args: request.command.args,
      customEnv: request.environment,
      baseScratchDir: this.baseScratchDir,
      executionId,
      workerId,
    });

    if (spawnRes.isErr) {
      const failedAt = new Date().toISOString() as IsoTimestamp;
      if (this.executionRepo) {
        this.assertValidTransition('STARTING', 'FAILED');
        await this.executionRepo.transitionState(
          executionId,
          request.workspaceId,
          'STARTING',
          'FAILED',
          {
            failure_details: { error: spawnRes.error },
            completed_at: failedAt,
          }
        );
        await this.executionRepo.releaseWorkerLease(workerId);
      }
      return err(
        makeExecutionProblem(
          ErrorCode.EXEC_PROCESS_CRASH,
          `Failed to spawn sandboxed worker: ${spawnRes.error}`
        )
      );
    }

    const worker = spawnRes.value;
    const child = worker.process;

    // Setup Output Taps
    let outputLimitBreached = false;
    const onLimitExceeded = (_streamName: string) => {
      outputLimitBreached = true;
      if (request.executionPolicy?.failOnOutputLimit) {
        // Force terminate worker on output flood
        void killProcessTree(worker.pid, child, 'SIGKILL');
      }
    };

    const stdoutTap = new OutputTap({
      streamName: 'stdout',
      maxBytes: limits.maxStdoutBytes,
      onLimitExceeded,
    });
    const stderrTap = new OutputTap({
      streamName: 'stderr',
      maxBytes: limits.maxStderrBytes,
      onLimitExceeded,
    });

    const activeHandle: ActiveExecutionHandle = {
      executionId,
      workspaceId: request.workspaceId,
      worker,
      workerId,
      outputTapStdout: stdoutTap,
      outputTapStderr: stderrTap,
      cancellationRequested: false,
      abortGraceTimeout: null,
      lastHeartbeat: Date.now(),
    };
    this.activeExecutions.set(executionId, activeHandle);

    if (this.executionRepo) {
      this.assertValidTransition('STARTING', 'RUNNING');
      await this.executionRepo.transitionState(
        executionId,
        request.workspaceId,
        'STARTING',
        'RUNNING'
      );
    }
    await this.emitEvent('execution.started', request.workspaceId, context, {
      executionId,
      workspaceId: request.workspaceId,
      workerId,
      pid: worker.pid,
    });

    // 11. Supervised Execution Lifecycle Promise
    return new Promise<Result<ExecutionResult, ProblemDetails>>((resolve) => {
      let resolved = false;
      let workerPayload: unknown = undefined;
      let workerArtifacts: ExecutionArtifactReference[] = [];

      // Timers
      let wallClockTimer: NodeJS.Timeout | null = null;
      let startupTimer: NodeJS.Timeout | null = null;
      let hasStarted = false;

      const finishExecution = async (
        state: ExecutionState,
        exitCode: number | null,
        reason: ExecutionTerminationReason,
        failureMsg?: string
      ) => {
        if (resolved) return;
        resolved = true;

        if (wallClockTimer) clearTimeout(wallClockTimer);
        if (startupTimer) clearTimeout(startupTimer);
        if (activeHandle.abortGraceTimeout) clearTimeout(activeHandle.abortGraceTimeout);

        this.activeExecutions.delete(executionId);

        // Ensure process tree is fully eliminated
        await killProcessTree(worker.pid, child, 'SIGKILL');
        await worker.cleanup();

        const completedAt = new Date().toISOString() as IsoTimestamp;
        const durationMs = Date.now() - startedAtTime;
        const rawOutputSha256 = stdoutTap.getSha256();

        // Database updates
        if (this.executionRepo) {
          try {
            await this.executionRepo.recordAttempt({
              execution_id: executionId,
              workspace_id: request.workspaceId,
              worker_id: workerId,
              state,
              exit_code: exitCode,
              termination_reason: reason,
              started_at: startedAt,
              completed_at: completedAt,
              duration_ms: durationMs,
            });

            await this.executionRepo.transitionState(
              executionId,
              request.workspaceId,
              ['RUNNING', 'CANCELLING', 'STARTING'],
              state,
              {
                result_payload: workerPayload,
                failure_details: failureMsg ? { error: failureMsg, reason } : null,
                stdout_summary: stdoutTap.getText().substring(0, 1024),
                stderr_summary: stderrTap.getText().substring(0, 1024),
                raw_output_sha256: rawOutputSha256,
                completed_at: completedAt,
              }
            );

            await this.executionRepo.releaseWorkerLease(workerId);
          } catch (dbErr) {
            this.logger?.error('Failed to update execution persistence on completion', {
              error: dbErr instanceof Error ? dbErr.message : String(dbErr),
              executionId,
            });
          }
        }

        // Metrics & Telemetry
        this.durationHistogram?.record(durationMs, {
          action: request.action,
          state,
        });

        const result: ExecutionResult = {
          executionId,
          workspaceId: request.workspaceId,
          organizationId: request.organizationId,
          state,
          exitCode,
          terminationReason: reason,
          stdout: stdoutTap.getText(),
          stderr: stderrTap.getText(),
          stdoutTruncated: stdoutTap.isTruncated(),
          stderrTruncated: stderrTap.isTruncated(),
          outputSha256: rawOutputSha256,
          payload: workerPayload,
          artifacts: workerArtifacts,
          telemetry: {
            durationMs,
            stdoutBytes: stdoutTap.getTotalBytes(),
            stderrBytes: stderrTap.getTotalBytes(),
          },
          failure:
            state === 'FAILED' || state === 'TIMED_OUT' || state === 'TERMINATED'
              ? {
                  code:
                    reason === 'TIMEOUT_WALL_CLOCK' || reason === 'TIMEOUT_STARTUP'
                      ? ErrorCode.EXEC_TIMEOUT_EXCEEDED
                      : reason === 'OUTPUT_LIMIT_EXCEEDED'
                        ? ErrorCode.EXEC_OUTPUT_LIMIT_EXCEEDED
                        : ErrorCode.EXEC_PROCESS_CRASH,
                  message: failureMsg || `Execution ended with state ${state} (${reason})`,
                  terminationReason: reason,
                }
              : undefined,
          startedAt,
          completedAt,
        };

        // Event emission
        await this.emitEvent(
          state === 'SUCCEEDED'
            ? 'execution.completed'
            : state === 'CANCELLED'
              ? 'execution.cancelled'
              : state === 'TIMED_OUT'
                ? 'execution.timed_out'
                : 'execution.failed',
          request.workspaceId,
          context,
          {
            executionId,
            workspaceId: request.workspaceId,
            state,
            durationMs,
            exitCode,
            terminationReason: reason,
          }
        );

        resolve(ok(result));
      };

      // 12. Setup Wall-Clock Timeout Timer
      wallClockTimer = setTimeout(() => {
        void finishExecution('TIMED_OUT', null, 'TIMEOUT_WALL_CLOCK', 'Execution exceeded wall-clock timeout');
      }, limits.timeoutMs);

      // 13. Setup Startup Timeout Timer
      startupTimer = setTimeout(() => {
        if (!hasStarted) {
          void finishExecution('TIMED_OUT', null, 'TIMEOUT_STARTUP', 'Worker failed to produce output or start within startup timeout');
        }
      }, limits.startupTimeoutMs);

      // 14. Stream Handlers
      if (child.stdout) {
        const rl = readline.createInterface({
          input: child.stdout,
          terminal: false,
        });

        rl.on('line', (line) => {
          hasStarted = true;
          stdoutTap.write(line + '\n');

          // Attempt protocol message decoding
          const decoded = decodeWorkerMessage(line);
          if (decoded.isOk) {
            const msg = decoded.value;
            if (msg.type === 'STARTUP') {
              // Send INIT message to worker
              if (child.stdin && !child.stdin.destroyed) {
                child.stdin.write(
                  encodeProtocolMessage({
                    type: 'INIT',
                    version: '1.0',
                    executionId,
                    target: request.target,
                    action: request.action,
                    payload: request.inputPayload,
                  })
                );
              }
            } else if (msg.type === 'HEARTBEAT') {
              activeHandle.lastHeartbeat = Date.now();
              if (this.executionRepo) {
                void this.executionRepo.heartbeatWorker(workerId);
              }
            } else if (msg.type === 'COMPLETED') {
              workerPayload = msg.payload;
              if (msg.artifacts) {
                workerArtifacts = [...msg.artifacts];
              }
            } else if (msg.type === 'FAILED') {
              void finishExecution('FAILED', null, 'PROCESS_CRASH', msg.error);
            }
          }
        });
      }

      if (child.stderr) {
        child.stderr.on('data', (chunk) => {
          hasStarted = true;
          stderrTap.write(chunk);
        });
      }

      // 15. Subprocess Exit & Error Handlers
      child.on('error', (err) => {
        void finishExecution('FAILED', null, 'PROCESS_CRASH', err.message);
      });

      child.on('close', (code, signal) => {
        if (activeHandle.cancellationRequested) {
          void finishExecution('CANCELLED', code, 'OPERATOR_CANCELLED');
          return;
        }

        if (outputLimitBreached && request.executionPolicy?.failOnOutputLimit) {
          void finishExecution('FAILED', code, 'OUTPUT_LIMIT_EXCEEDED', 'Execution output exceeded maximum byte limit');
          return;
        }

        if (code === 0) {
          void finishExecution('SUCCEEDED', 0, 'NORMAL_EXIT');
        } else {
          const isFailOnNonZero = request.executionPolicy?.failOnNonZeroExit ?? true;
          if (isFailOnNonZero) {
            void finishExecution('FAILED', code, 'PROCESS_CRASH', `Subprocess exited with non-zero code ${code} (signal: ${signal})`);
          } else {
            void finishExecution('SUCCEEDED', code, 'NORMAL_EXIT');
          }
        }
      });
    });
  }

  async getExecution(
    id: ExecutionId,
    workspaceId: WorkspaceId
  ): Promise<Result<ExecutionResult, ProblemDetails>> {
    if (!this.executionRepo) {
      return err(
        makeExecutionProblem(
          ErrorCode.INTERNAL_FAULT,
          'ExecutionRepository required to query execution status'
        )
      );
    }

    const record = await this.executionRepo.findById(id, workspaceId);
    if (!record) {
      return err(
        makeExecutionProblem(
          ErrorCode.STORAGE_NOT_FOUND,
          `Execution '${id}' not found in workspace '${workspaceId}'`
        )
      );
    }

    const dbArtifacts = await this.executionRepo.listArtifacts(id, workspaceId);
    const artifacts: ExecutionArtifactReference[] = dbArtifacts.map((a) => ({
      name: a.name,
      contentSha256: a.content_sha256,
      storageUri: a.storage_uri,
      byteSize: a.byte_size,
      mimeType: a.mime_type,
    }));

    const result: ExecutionResult = {
      executionId: record.id,
      workspaceId: record.workspace_id,
      organizationId: record.organization_id,
      state: record.state as ExecutionState,
      exitCode: null,
      terminationReason: (record.state === 'SUCCEEDED' ? 'NORMAL_EXIT' : 'PROCESS_CRASH') as ExecutionTerminationReason,
      stdout: record.stdout_summary || '',
      stderr: record.stderr_summary || '',
      stdoutTruncated: false,
      stderrTruncated: false,
      outputSha256: record.raw_output_sha256 || '',
      payload: record.result_payload,
      artifacts,
      telemetry: {
        durationMs: 0,
        stdoutBytes: (record.stdout_summary || '').length,
        stderrBytes: (record.stderr_summary || '').length,
      },
      startedAt: record.started_at as IsoTimestamp | undefined,
      completedAt: record.completed_at as IsoTimestamp,
    };

    return ok(result);
  }

  async cancelExecution(request: CancellationRequest): Promise<Result<void, ProblemDetails>> {
    const handle = this.activeExecutions.get(request.executionId);
    if (!handle) {
      // Check persistence if already terminated
      if (this.executionRepo) {
        const record = await this.executionRepo.findById(request.executionId, request.workspaceId);
        if (record && isTerminalState(record.state as ExecutionState)) {
          return ok(undefined);
        }
      }
      return err(
        makeExecutionProblem(
          ErrorCode.STORAGE_NOT_FOUND,
          `Active execution '${request.executionId}' not found for cancellation`
        )
      );
    }

    // Tenancy check on cancellation
    if (handle.workspaceId !== request.workspaceId) {
      return err(
        makeExecutionProblem(
          ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          `Cannot cancel execution: workspace mismatch`
        )
      );
    }

    handle.cancellationRequested = true;

    // Send CANCEL message on stdin if available
    const child = handle.worker.process;
    if (child.stdin && !child.stdin.destroyed) {
      try {
        child.stdin.write(
          encodeProtocolMessage({
            type: 'CANCEL',
            reason: request.reason,
            gracePeriodMs: 1500,
          })
        );
      } catch {
        // ignore
      }
    }

    // Set grace timeout then force kill
    handle.abortGraceTimeout = setTimeout(() => {
      void killProcessTree(handle.worker.pid, child, 'SIGKILL');
    }, 1500);

    return ok(undefined);
  }

  private assertValidTransition(from: ExecutionState, to: ExecutionState): void {
    if (!isValidStateTransition(from, to)) {
      throw new Error(`Illegal execution state transition attempted from '${from}' to '${to}'`);
    }
  }

  private validateRequestParameters(request: ExecutionRequest): Result<void, ProblemDetails> {
    if (!request.workspaceId) {
      return err(makeExecutionProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Missing workspaceId'));
    }
    if (!request.organizationId) {
      return err(makeExecutionProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Missing organizationId'));
    }
    if (!request.requestedBy) {
      return err(makeExecutionProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Missing requestedBy'));
    }
    if (!request.action || typeof request.action !== 'string') {
      return err(makeExecutionProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid or missing action'));
    }
    if (!request.target || typeof request.target !== 'string') {
      return err(makeExecutionProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid or missing target'));
    }
    if (!request.command || !request.command.executable) {
      return err(makeExecutionProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'Invalid or missing command executable'));
    }
    if (!Array.isArray(request.command.args)) {
      return err(makeExecutionProblem(ErrorCode.INVALID_PAYLOAD_SCHEMA, 'command.args must be an array'));
    }

    return ok(undefined);
  }

  private mapActionToPermissionBit(action: string): number | undefined {
    const act = action.toLowerCase();
    switch (act) {
      case 'read':
      case 'view_scope':
        return PermissionBit.SCOPE_READ;
      case 'recon_passive':
      case 'passive':
        return PermissionBit.RECON_PASSIVE;
      case 'probing_active':
      case 'probe':
        return PermissionBit.PROBING_ACTIVE;
      case 'scan_invasive':
      case 'scan':
        return PermissionBit.SCAN_INVASIVE;
      case 'execute':
      case 'workflow_execute':
        return PermissionBit.WORKFLOW_EXECUTE;
      default:
        return undefined;
    }
  }

  private async emitEvent(
    type: string,
    workspaceId: WorkspaceId,
    securityContext: SecurityContextToken,
    payload: Record<string, unknown>
  ): Promise<void> {
    if (!this.eventPublisher) return;
    try {
      const eventId = createEventId(generateUUIDv7()).unwrapOr(generateUUIDv7() as any);
      const correlationId = createCorrelationId(generateUUIDv7()).unwrapOr(generateUUIDv7() as any);
      const causationId = createCausationId(generateUUIDv7()).unwrapOr(generateUUIDv7() as any);
      const envelope = createCanonicalEventEnvelope({
        eventId,
        eventType: type,
        schemaVersion: '1.0.0',
        occurredAt: nowIso(),
        producer: {
          module_name: 'mod_execution_supervisor',
          node_id: 'supervisor-01',
          environment: process.env.NODE_ENV || 'production',
          build_version: '0.1.0',
        },
        workspaceId,
        correlationId,
        causationId,
        traceId: '00-00000000000000000000000000000000-0000000000000000-01' as TraceId,
        authorizationContext: securityContext,
        scopeReference: {
          scope_id: 'default',
          scope_sha256: '0000000000000000000000000000000000000000000000000000000000000000',
        },
        payload,
        integrity: {
          algorithm: 'HMAC-SHA256',
          signature: 'supervisor-internal',
          key_id: 'supervisor-key-01',
        },
      });
      await this.eventPublisher.publish(envelope);
    } catch {
      // Don't fail execution orchestration if event bus is transiently offline
    }
  }
}
