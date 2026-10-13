/**
 * Shadow : Helix Nebula (SHN) — Capability Execution Controller
 *
 * Authoritative Spec: Phase 0.3 Context 6 (BC-EXE), Phase 0.4 (INV-01, INV-06, INV-14),
 * Phase 0.14 Perimeter B & D.
 * Orchestrates capability dispatch, scope verification, and execution lifecycle querying.
 */

import type { WorkspaceId, ExecutionId, OrganizationId, ScopeId } from '@shn/shared-kernel';
import type { ScopeToken } from '@shn/scope-gatekeeper';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { CapabilityDispatcher } from '@shn/capability-registry';
import type { ExecutionRepository } from '@shn/data-access';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface ExecutionControllerOptions {
  dispatcher: CapabilityDispatcher;
  executionRepo?: ExecutionRepository | undefined;
}

export class ExecutionController {
  private readonly dispatcher: CapabilityDispatcher;
  private readonly executionRepo?: ExecutionRepository | undefined;

  constructor(options: ExecutionControllerOptions) {
    this.dispatcher = options.dispatcher;
    this.executionRepo = options.executionRepo;
  }

  async execute(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;

    if (!req.securityContext || !req.actor) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        detail: 'Authentication required to execute capabilities.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const body = req.body ?? {};
    const {
      capabilityId,
      target,
      port,
      parameters,
      scopeId,
      scopeToken,
      preferredAdapterId,
      scopeOverride,
    } = body;

    if (!capabilityId || typeof capabilityId !== 'string') {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Field "capabilityId" is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    if (!target || typeof target !== 'string') {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Field "target" is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const orgId = req.actor.organizationId ?? (req.securityContext.workspace_id as unknown as OrganizationId);

    const result = await this.dispatcher.executeCapability({
      capabilityId,
      target: target.trim(),
      port: port !== undefined ? Number(port) : undefined,
      parameters: parameters ?? {},
      securityContext: req.securityContext,
      workspaceId,
      organizationId: orgId,
      actorId: req.actor.id,
      scopeId: scopeId as ScopeId | undefined,
      scopeToken: scopeToken as ScopeToken | undefined,
      scopeOverride: scopeOverride ?? undefined,
      preferredAdapterId,
    });

    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const executionId = req.params['executionId'] as ExecutionId;

    if (!this.executionRepo) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: 'Execution repository not configured on gateway.',
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 501,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const record = await this.executionRepo.findById(executionId, workspaceId);
    if (!record) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: `Execution "${executionId}" not found in workspace "${workspaceId}".`,
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 404,
      });
      sendProblemDetails(res, problem);
      return;
    }

    res.status(200).json(record);
  }

  async list(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    if (!this.executionRepo) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: 'Execution repository not configured on gateway.',
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 501,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const limit = req.query['limit'] ? parseInt(req.query['limit'], 10) : 50;
    const offset = req.query['offset'] ? parseInt(req.query['offset'], 10) : 0;
    const records = await this.executionRepo.listByWorkspace(workspaceId, limit, offset);
    res.status(200).json(records);
  }
}
