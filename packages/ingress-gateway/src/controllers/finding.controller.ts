/**
 * Shadow : Helix Nebula (SHN) — Finding Lifecycle Controller
 *
 * Authoritative Spec: Phase 0.3 Context 3 (BC-FND), Phase 0.4 (INV-05), Phase 0.14 Section 8.
 * Handles vulnerability finding ingestion, evidence validation, state transitions, and audit trail.
 */

import type { WorkspaceId, FindingId, AssetId, ExecutionId } from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { FindingLifecycleService, FindingStatus } from '@shn/asset-inventory';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface FindingControllerOptions {
  findingService: FindingLifecycleService;
}

export class FindingController {
  private readonly findingService: FindingLifecycleService;

  constructor(options: FindingControllerOptions) {
    this.findingService = options.findingService;
  }

  async record(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const body = req.body ?? {};
    const {
      assetId,
      executionId,
      title,
      description,
      category,
      severity,
      cveId,
      cweId,
      cvssScore,
      cvssVector,
      rawEvidenceSha256,
      evidenceArtifactId,
      remediationGuidance,
      metadata,
    } = body;

    if (!assetId || !title || !description || !category || !severity || !rawEvidenceSha256) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Required fields: assetId, title, description, category, severity, rawEvidenceSha256.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const orgId = req.actor?.organizationId ?? (req.securityContext?.workspace_id as any);

    const result = await this.findingService.recordFinding({
      workspaceId,
      organizationId: orgId,
      assetId: assetId as AssetId,
      executionId: executionId ? (executionId as ExecutionId) : undefined,
      title: String(title).trim(),
      description: String(description).trim(),
      category: String(category).trim(),
      severity,
      cveId: cveId ?? undefined,
      cweId: cweId ?? undefined,
      cvssScore: cvssScore !== undefined && cvssScore !== null ? Number(cvssScore) : undefined,
      cvssVector: cvssVector ?? undefined,
      rawEvidenceSha256: String(rawEvidenceSha256).trim(),
      evidenceArtifactId: evidenceArtifactId ?? undefined,
      remediationGuidance: remediationGuidance ?? undefined,
      metadata: metadata ?? undefined,
      correlationId: req.correlationId,
    });

    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(201).json(result.value);
  }

  async list(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const query = req.query;

    const filter: any = {};
    if (query['assetId']) filter.assetId = query['assetId'];
    if (query['status']) filter.status = query['status'];
    if (query['severity']) filter.severity = query['severity'];
    if (query['limit']) filter.limit = parseInt(query['limit'], 10);
    if (query['offset']) filter.offset = parseInt(query['offset'], 10);

    const result = await this.findingService.listFindings(workspaceId, filter);
    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const findingId = req.params['findingId'] as FindingId;

    const result = await this.findingService.getFinding(findingId, workspaceId);
    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }

  async transition(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const findingId = req.params['findingId'] as FindingId;
    const body = req.body ?? {};
    const { toStatus, reason } = body;

    if (!toStatus || typeof toStatus !== 'string') {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Field "toStatus" is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    if (!req.actor) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        detail: 'Authentication required for status transition.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const result = await this.findingService.transitionStatus({
      findingId,
      workspaceId,
      toStatus: toStatus as FindingStatus,
      changedBy: req.actor.id,
      reason,
      correlationId: req.correlationId,
    });

    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }

  async getHistory(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const findingId = req.params['findingId'] as FindingId;

    const result = await this.findingService.getStatusHistory(findingId, workspaceId);
    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }
}
