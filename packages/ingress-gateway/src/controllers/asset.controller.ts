/**
 * Shadow : Helix Nebula (SHN) — Asset Inventory Controller
 *
 * Authoritative Spec: Phase 0.3 Context 2 (BC-NRM), Phase 0.14 Section 8.
 * Handles asset registration, canonicalization, querying, and updating.
 */

import type { WorkspaceId, AssetId } from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { AssetInventoryService } from '@shn/asset-inventory';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface AssetControllerOptions {
  assetService: AssetInventoryService;
}

export class AssetController {
  private readonly assetService: AssetInventoryService;

  constructor(options: AssetControllerOptions) {
    this.assetService = options.assetService;
  }

  async register(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const body = req.body ?? {};
    const { rawTarget, type, name, criticality, status, tags, metadata } = body;

    if (!rawTarget || typeof rawTarget !== 'string' || !rawTarget.trim()) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Field "rawTarget" is required and cannot be empty.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const orgId = req.actor?.organizationId ?? (req.securityContext?.workspace_id as any);

    const result = await this.assetService.registerAsset({
      workspaceId,
      organizationId: orgId,
      rawTarget: rawTarget.trim(),
      type,
      name,
      criticality,
      status,
      tags,
      metadata,
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
    if (query['type']) filter.type = query['type'];
    if (query['status']) filter.status = query['status'];
    if (query['limit']) filter.limit = parseInt(query['limit'], 10);
    if (query['offset']) filter.offset = parseInt(query['offset'], 10);

    const result = await this.assetService.listAssets(workspaceId, filter);
    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const assetId = req.params['assetId'] as AssetId;

    const result = await this.assetService.getAsset(assetId, workspaceId);
    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }

  async update(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const assetId = req.params['assetId'] as AssetId;
    const body = req.body ?? {};

    const result = await this.assetService.updateAsset(assetId, workspaceId, {
      name: body.name,
      criticality: body.criticality,
      status: body.status,
      tags: body.tags,
      metadata: body.metadata,
      correlationId: req.correlationId,
    });

    if (result.isErr) {
      sendProblemDetails(res, result.error);
      return;
    }

    res.status(200).json(result.value);
  }
}
