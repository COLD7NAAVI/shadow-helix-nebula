/**
 * Shadow : Helix Nebula (SHN) — Capability Execution Dispatcher & Gateway
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Context 6 (BC-EXE),
 *                    Phase 0.4 (INV-01, INV-03, INV-04, INV-06, INV-14),
 *                    Phase 0.7 Section 4.2.3, Phase 0.8, Phase 0.9 (Tool Integration)
 */

import {
  ok,
  err,
  createEventId,
  createCorrelationId,
  createCausationId,
  createCanonicalEventEnvelope,
  generateUUIDv7,
  isSecurityContextExpired,
  nowIso,
  type Result,
  type TraceId,
  type EventId,
  type CorrelationId,
  type CausationId,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { makeCapabilityProblem } from '../errors.js';
import type {
  ICapabilityRegistry,
  CapabilityExecutionRequest,
  CapabilityExecutionResult,
} from '../contracts.js';
import type {
  IExecutionSupervisor,
  ExecutionRequest,
} from '@shn/execution-supervisor';
import type { IScopeGatekeeper, TenancyValidator } from '@shn/scope-gatekeeper';
import type { IEventPublisher } from '@shn/event-bus';
import type { ILogger, IMeter, IHistogram } from '@shn/telemetry';

export interface CapabilityDispatcherOptions {
  readonly registry: ICapabilityRegistry;
  readonly supervisor: IExecutionSupervisor;
  readonly scopeGatekeeper?: IScopeGatekeeper | undefined;
  readonly tenancyValidator?: TenancyValidator | undefined;
  readonly eventPublisher?: IEventPublisher | undefined;
  readonly meter?: IMeter | undefined;
  readonly logger?: ILogger | undefined;
}

export class CapabilityDispatcher {
  private readonly registry: ICapabilityRegistry;
  private readonly supervisor: IExecutionSupervisor;
  private readonly scopeGatekeeper?: IScopeGatekeeper | undefined;
  private readonly tenancyValidator?: TenancyValidator | undefined;
  private readonly eventPublisher?: IEventPublisher | undefined;
  private readonly meter?: IMeter | undefined;
  private readonly logger?: ILogger | undefined;
  private readonly durationHistogram?: IHistogram | undefined;

  constructor(options: CapabilityDispatcherOptions) {
    this.registry = options.registry;
    this.supervisor = options.supervisor;
    this.scopeGatekeeper = options.scopeGatekeeper;
    this.tenancyValidator = options.tenancyValidator;
    this.eventPublisher = options.eventPublisher;
    this.meter = options.meter;
    this.logger = options.logger;

    if (this.meter) {
      this.durationHistogram = this.meter.createHistogram(
        'capability_execution_duration_ms',
        [10, 50, 100, 250, 500, 1000, 5000, 15000, 30000, 60000, 300000],
        'Capability execution duration in milliseconds'
      );
    }
  }

  async executeCapability(
    request: CapabilityExecutionRequest
  ): Promise<Result<CapabilityExecutionResult, ProblemDetails>> {
    const startTime = Date.now();

    // ------------------------------------------------------------------------
    // 1. Identity & Multi-Tenant Workspace Assertion (INV-01)
    // ------------------------------------------------------------------------
    const secCtx = request.securityContext;
    if (!secCtx) {
      return err(
        makeCapabilityProblem(
          ErrorCode.AUTH_UNAUTHENTICATED,
          'Security context token is required for capability execution'
        )
      );
    }

    if (isSecurityContextExpired(secCtx)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.AUTH_TOKEN_EXPIRED,
          'Security context token has expired'
        )
      );
    }

    if (secCtx.subject_id !== request.actorId) {
      return err(
        makeCapabilityProblem(
          ErrorCode.AUTH_FORBIDDEN,
          'Security context subject does not match requested actor ID'
        )
      );
    }

    if (secCtx.workspace_id !== request.workspaceId) {
      return err(
        makeCapabilityProblem(
          ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          'Security context workspace does not match execution request workspace'
        )
      );
    }

    if (this.tenancyValidator) {
      const orgTenancyRes = await this.tenancyValidator.verifyWorkspaceBelongsToOrg(
        request.workspaceId,
        request.organizationId
      );
      if (orgTenancyRes.isErr) {
        return err(orgTenancyRes.error);
      }
    }

    // ------------------------------------------------------------------------
    // 2. Capability Resolution & Lifecycle Check
    // ------------------------------------------------------------------------
    const capability = await this.registry.findCapability(request.capabilityId, request.workspaceId);
    if (!capability) {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_NOT_FOUND,
          `Capability '${request.capabilityId}' is not registered`
        )
      );
    }

    if (capability.workspaceId && capability.workspaceId !== request.workspaceId) {
      return err(
        makeCapabilityProblem(
          ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          `Capability '${capability.id}' belongs to workspace '${capability.workspaceId}' and cannot be executed in workspace '${request.workspaceId}'`
        )
      );
    }

    if (capability.lifecycleState === 'DISABLED') {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_DISABLED,
          `Capability '${request.capabilityId}' is disabled`
        )
      );
    }

    if (capability.lifecycleState === 'REVOKED') {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_REVOKED,
          `Capability '${request.capabilityId}' has been revoked`
        )
      );
    }

    // ------------------------------------------------------------------------
    // 3. RBAC Permission Check (Stage 4 Integration)
    // ------------------------------------------------------------------------
    const userPermissions = Number(secCtx.permission_mask ?? 0);
    if ((userPermissions & capability.requiredPermissions) !== capability.requiredPermissions) {
      this.logger?.warn('Capability execution denied: insufficient actor permissions', {
        actorId: request.actorId,
        capabilityId: capability.id,
        requiredPermissions: capability.requiredPermissions,
        userPermissions,
      });
      return err(
        makeCapabilityProblem(
          ErrorCode.AUTH_FORBIDDEN,
          `Actor '${request.actorId}' lacks required permissions for capability '${capability.id}'`
        )
      );
    }

    // ------------------------------------------------------------------------
    // 4. Provider Adapter Resolution (Phase 0.9 §9)
    // ------------------------------------------------------------------------
    const adapterRes = await this.registry.resolveProvider(capability.id, {
      workspaceId: request.workspaceId,
      target: request.target,
      preferredAdapterId: request.preferredAdapterId,
    });

    if (adapterRes.isErr) {
      return err(adapterRes.error);
    }
    const adapter = adapterRes.value;

    // ------------------------------------------------------------------------
    // 5. Adapter Parameter & Target Validation
    // ------------------------------------------------------------------------
    const targetValRes = adapter.validateTarget(capability, request.target, request.port);
    if (targetValRes.isErr) {
      return err(targetValRes.error);
    }

    const paramValRes = adapter.validateParameters(capability, request.parameters ?? {});
    if (paramValRes.isErr) {
      return err(paramValRes.error);
    }
    const sanitizedParams = paramValRes.value;

    // ------------------------------------------------------------------------
    // 6. Pre-Dispatch Scope Gatekeeper Authorization (INV-06 / Stage 5)
    // ------------------------------------------------------------------------
    if (this.scopeGatekeeper) {
      const scopeEvalRes = await this.scopeGatekeeper.evaluateTarget({
        context: secCtx,
        target: request.target,
        port: request.port,
        action: capability.requiredScopeAction,
        scopeId: request.scopeId,
        scopeToken: request.scopeToken,
        scopeOverride: request.scopeOverride,
      });

      if (scopeEvalRes.isErr) {
        return err(scopeEvalRes.error);
      }

      if (!scopeEvalRes.value.allowed) {
        this.logger?.warn('Capability execution rejected by Scope Gatekeeper', {
          target: request.target,
          action: capability.requiredScopeAction,
          reason: scopeEvalRes.value.reason,
        });
        return err(
          makeCapabilityProblem(
            ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS,
            `Target '${request.target}' rejected by Scope Gatekeeper: ${scopeEvalRes.value.reason}`
          )
        );
      }
    }

    // ------------------------------------------------------------------------
    // 7. Command Vector Generation
    // ------------------------------------------------------------------------
    const cmdRes = adapter.buildCommand(capability, request.target, sanitizedParams, request.port);
    if (cmdRes.isErr) {
      return err(cmdRes.error);
    }
    const commandVector = cmdRes.value;

    // ------------------------------------------------------------------------
    // 8. Execution Request Construction for Stage 6 Execution Supervisor
    // ------------------------------------------------------------------------
    const executionRequest: ExecutionRequest = {
      workspaceId: request.workspaceId,
      organizationId: request.organizationId,
      requestedBy: request.actorId,
      securityContext: request.securityContext,
      action: capability.requiredScopeAction,
      target: request.target,
      port: request.port,
      capabilityUri: String(capability.id),
      scopeId: request.scopeId,
      scopeToken: request.scopeToken,
      scopeOverride: request.scopeOverride,
      command: {
        executable: commandVector.executable,
        args: commandVector.args,
      },
      environment: commandVector.env,
      inputPayload: commandVector.inputPayload,
      resourceLimits: {
        ...capability.resourceRequirements,
        ...commandVector.resourceLimits,
        ...request.resourceLimits,
      },
    };

    // ------------------------------------------------------------------------
    // 9. Dispatch to Execution Supervisor (Stage 6)
    // ------------------------------------------------------------------------
    const supervisorRes = await this.supervisor.execute(executionRequest);
    const durationMs = Date.now() - startTime;

    if (supervisorRes.isErr) {
      this.recordTelemetry(durationMs, {
        capability_id: capability.id,
        adapter_id: adapter.adapterId,
        state: 'FAILED',
      });
      return err(supervisorRes.error);
    }

    const execRecord = supervisorRes.value;

    // ------------------------------------------------------------------------
    // 10. Output Interpretation via Adapter
    // ------------------------------------------------------------------------
    let parsedOutput = undefined;
    if (execRecord.state === 'SUCCEEDED') {
      const parseRes = adapter.parseOutput(
        execRecord.stdout,
        execRecord.stderr,
        execRecord.exitCode ?? 0,
        execRecord.outputSha256
      );
      if (parseRes.isOk) {
        parsedOutput = parseRes.value;
      }
    }

    this.recordTelemetry(durationMs, {
      capability_id: capability.id,
      adapter_id: adapter.adapterId,
      state: execRecord.state,
    });
    await this.publishLifecycleEvent(request, capability.id, adapter.adapterId, execRecord.state);

    return ok({
      executionId: execRecord.executionId,
      capabilityId: capability.id,
      adapterId: adapter.adapterId,
      state: execRecord.state,
      exitCode: execRecord.exitCode ?? (execRecord.state === 'SUCCEEDED' ? 0 : 1),
      rawOutput: execRecord.stdout,
      rawStderr: execRecord.stderr,
      rawOutputSha256: execRecord.outputSha256,
      durationMs,
      output: parsedOutput,
      ...(execRecord.failure
        ? {
            failureDetails: makeCapabilityProblem(
              ErrorCode.ADAPTER_EXECUTION_FAILED,
              execRecord.failure.message
            ),
          }
        : {}),
    });
  }

  private recordTelemetry(
    durationMs: number,
    labels: Record<string, string>
  ): void {
    try {
      this.durationHistogram?.record(durationMs, labels);
    } catch {
      // Telemetry non-fatal
    }
  }

  private async publishLifecycleEvent(
    request: CapabilityExecutionRequest,
    capabilityId: string,
    adapterId: string,
    state: string
  ): Promise<void> {
    if (!this.eventPublisher) return;
    try {
      const eventId = createEventId(generateUUIDv7()).unwrapOr(generateUUIDv7() as EventId);
      const correlationId = createCorrelationId(generateUUIDv7()).unwrapOr(generateUUIDv7() as CorrelationId);
      const causationId = createCausationId(generateUUIDv7()).unwrapOr(generateUUIDv7() as CausationId);

      const envelope = createCanonicalEventEnvelope({
        eventId,
        eventType: `capability.execution.${state.toLowerCase()}`,
        schemaVersion: '1.0.0',
        occurredAt: nowIso(),
        producer: {
          module_name: 'mod_capability_registry',
          node_id: 'capability-dispatcher-01',
          environment: process.env.NODE_ENV || 'production',
          build_version: '0.1.0',
        },
        workspaceId: request.workspaceId,
        correlationId,
        causationId,
        traceId: '00-00000000000000000000000000000000-0000000000000000-01' as TraceId,
        authorizationContext: request.securityContext,
        scopeReference: {
          scope_id: request.scopeId ?? 'default',
          scope_sha256: '0000000000000000000000000000000000000000000000000000000000000000',
        },
        payload: {
          capabilityId,
          adapterId,
          state,
          target: request.target,
          actorId: request.actorId,
        },
        integrity: {
          algorithm: 'HMAC-SHA256',
          signature: 'dispatcher-internal',
          key_id: 'dispatcher-key-01',
        },
      });

      await this.eventPublisher.publish(envelope);
    } catch {
      // Event publishing non-fatal
    }
  }
}
