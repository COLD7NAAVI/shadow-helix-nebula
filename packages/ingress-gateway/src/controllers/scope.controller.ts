/**
 * Shadow : Helix Nebula (SHN) — Scope Gatekeeper Controller
 *
 * Authoritative Spec: Phase 0.3 Context 5 (BC-SCP), Phase 0.7, Phase 0.14 Section 8.
 * Handles scope boundary querying and creation for multi-tenant containment.
 */

import {
  generateUUIDv7,
  createScopeId,
  type WorkspaceId,
  type ScopeId,
  type OrganizationId,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import { ScopeRepository } from '@shn/data-access';
import { createHash } from 'node:crypto';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface ScopeControllerOptions {
  scopeRepo: ScopeRepository;
}

export class ScopeController {
  private readonly scopeRepo: ScopeRepository;

  constructor(options: ScopeControllerOptions) {
    this.scopeRepo = options.scopeRepo;
  }

  async list(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    try {
      const scopes = await this.scopeRepo.listByWorkspace(workspaceId);
      res.status(200).json(scopes);
    } catch {
      res.status(200).json([]);
    }
  }

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const scopeId = req.params['scopeId'] as ScopeId;

    if (!scopeId) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Scope ID is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    try {
      const record = await this.scopeRepo.findById(scopeId, workspaceId);
      if (!record) {
        const problem = createProblemDetails({
          errorCode: ErrorCode.STORAGE_NOT_FOUND,
          detail: `Scope "${scopeId}" not found in workspace "${workspaceId}".`,
          instance: req.path,
          correlationId: req.correlationId,
          customStatus: 404,
        });
        sendProblemDetails(res, problem);
        return;
      }
      res.status(200).json(record);
    } catch {
      const problem = createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: `Scope "${scopeId}" not found.`,
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 404,
      });
      sendProblemDetails(res, problem);
    }
  }

  async create(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const body = req.body ?? {};
    const {
      name,
      description,
      inclusions = [],
      exclusions = [],
      allowedActions = ['RECON_PASSIVE', 'PROBING_ACTIVE', 'PORT_SCAN'],
      disallowedActions = ['EXPLOIT', 'DENIAL_OF_SERVICE'],
      portRanges = [{ start: 1, end: 65535 }],
      validFrom = new Date().toISOString(),
      validUntil = new Date(Date.now() + 86400000 * 30).toISOString(),
      rateLimits = { requests_per_second: 50 },
    } = body;

    if (!name || typeof name !== 'string' || !name.trim()) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Field "name" is required and cannot be empty.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const orgId = req.actor?.organizationId ?? (req.securityContext?.workspace_id as unknown as OrganizationId);
    const scopeIdRes = createScopeId(generateUUIDv7());
    const scopeId = scopeIdRes.isOk ? scopeIdRes.value : (generateUUIDv7() as ScopeId);

    const canonicalData = JSON.stringify({
      workspaceId,
      inclusions,
      exclusions,
      allowedActions,
      disallowedActions,
      portRanges,
      validFrom,
      validUntil,
    });
    const scopeSha256 = createHash('sha256').update(canonicalData).digest('hex');

    try {
      const record = await this.scopeRepo.createScope({
        id: scopeId,
        workspace_id: workspaceId,
        organization_id: orgId,
        name: name.trim(),
        description: description ? String(description).trim() : null,
        status: 'ACTIVE',
        inclusions,
        exclusions,
        allowed_actions: allowedActions,
        disallowed_actions: disallowedActions,
        port_ranges: portRanges,
        valid_from: validFrom,
        valid_until: validUntil,
        rate_limits: rateLimits,
        scope_sha256: scopeSha256,
        created_by: req.actor?.id ?? null,
      });

      res.status(201).json(record);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const isConflict = errMsg.includes('duplicate key') || errMsg.includes('unique constraint');
      const problem = createProblemDetails({
        errorCode: isConflict ? ErrorCode.STORAGE_CONCURRENCY_CONFLICT : ErrorCode.STORAGE_TRANSACTION_FAILED,
        detail: isConflict ? 'A scope with this name already exists in the workspace.' : `Failed to create scope boundary: ${errMsg}`,
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: isConflict ? 409 : 500,
      });
      sendProblemDetails(res, problem);
    }
  }
}
