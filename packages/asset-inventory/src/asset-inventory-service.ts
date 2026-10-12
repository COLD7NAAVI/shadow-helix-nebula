/**
 * Shadow : Helix Nebula (SHN) — Asset Inventory Service
 *
 * Authoritative Spec: Phase 0.3 (BC-NRM), Phase 0.4 (INV-01, DATA-INV-08),
 * Phase 0.7 Section 4.3.5 (mod_asset_inventory), Phase 0.10 Section 6.
 * Enforces canonicalization, deduplication, tenant hermeticity, and audit logging.
 */

import {
  ok,
  err,
  type Result,
  type AssetId,
  type WorkspaceId,
  createAssetId,
  generateUUIDv7,
  createEventId,
  createCorrelationId,
  createCausationId,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
} from '@shn/error-catalog';
import {
  AssetRepository,
  type AssetRecord,
  type CreateAssetParams,
  type UpdateAssetParams,
  type ListAssetOptions,
} from '@shn/data-access';
import { normalizeTarget, canonicalizeTarget } from './canonicalizer.js';
import type {
  AssetEntity,
  RegisterAssetCommand,
  UpdateAssetCommand,
  ListAssetsFilter,
} from './contracts.js';

export interface AssetInventoryEventPublisher {
  publish(event: any): Promise<unknown>;
}

export interface AssetInventoryServiceOptions {
  assetRepository: AssetRepository;
  eventBus?: AssetInventoryEventPublisher | undefined;
}

export class AssetInventoryService {
  private readonly repo: AssetRepository;
  private readonly eventBus?: AssetInventoryEventPublisher | undefined;

  constructor(options: AssetInventoryServiceOptions) {
    this.repo = options.assetRepository;
    this.eventBus = options.eventBus;
  }

  /**
   * Registers a new asset after canonicalization and validation.
   * Enforces uniqueness within workspace (BC-NRM deduplication).
   */
  async registerAsset(cmd: RegisterAssetCommand): Promise<Result<AssetEntity, ProblemDetails>> {
    const correlationId = cmd.correlationId ?? generateUUIDv7();
    const instance = `/workspaces/${cmd.workspaceId}/assets`;

    // 1. Determine canonical value and type
    let type = cmd.type;
    let canonicalValue: string;

    if (!type) {
      const normRes = normalizeTarget(cmd.rawTarget);
      if (normRes.isErr) {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.ASSET_VALIDATION_FAILED,
            detail: normRes.error,
            instance,
            correlationId,
            invalidParams: [{ name: 'rawTarget', reason: normRes.error }],
          })
        );
      }
      type = normRes.value.type;
      canonicalValue = normRes.value.canonicalValue;
    } else {
      const canonRes = canonicalizeTarget(type, cmd.rawTarget);
      if (canonRes.isErr) {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.ASSET_VALIDATION_FAILED,
            detail: canonRes.error,
            instance,
            correlationId,
            invalidParams: [{ name: 'rawTarget', reason: canonRes.error }],
          })
        );
      }
      canonicalValue = canonRes.value;
    }

    // 2. Generate or validate Asset ID
    let assetId: AssetId;
    if (cmd.id) {
      const idRes = createAssetId(cmd.id);
      if (idRes.isErr) {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.ASSET_VALIDATION_FAILED,
            detail: `Invalid AssetId: ${idRes.error}`,
            instance,
            correlationId,
          })
        );
      }
      assetId = idRes.value;
    } else {
      const generated = createAssetId(generateUUIDv7());
      assetId = generated.isOk ? generated.value : (generateUUIDv7() as AssetId);
    }

    try {
      const createParams: CreateAssetParams = {
        id: assetId,
        workspaceId: cmd.workspaceId,
        organizationId: cmd.organizationId,
        type,
        canonicalValue,
        name: cmd.name || canonicalValue,
        criticality: cmd.criticality ?? 'MEDIUM',
        status: cmd.status ?? 'ACTIVE',
        tags: cmd.tags ?? [],
        metadata: cmd.metadata ?? {},
      };

      const record = await this.repo.createAsset(createParams);
      const entity = this.mapRecordToEntity(record);

      // 3. Emit Domain Event if EventBus is configured
      if (this.eventBus) {
        try {
          const evIdRes = createEventId(generateUUIDv7());
          const corrRes = createCorrelationId(correlationId);
          const causRes = createCausationId(generateUUIDv7());

          await this.eventBus.publish({
            eventId: evIdRes.isOk ? evIdRes.value : generateUUIDv7(),
            eventType: 'asset.inventory.registered',
            schemaVersion: '1.0.0',
            occurredAt: entity.createdAt,
            workspaceId: entity.workspaceId,
            correlationId: corrRes.isOk ? corrRes.value : correlationId,
            causationId: causRes.isOk ? causRes.value : generateUUIDv7(),
            producer: { module: 'mod_asset_inventory' },
            payload: {
              assetId: entity.id,
              type: entity.type,
              canonicalValue: entity.canonicalValue,
              criticality: entity.criticality,
              status: entity.status,
            },
          });
        } catch {
          // Failure to publish async event does not abort synchronous database transaction
        }
      }

      return ok(entity);
    } catch (e: any) {
      if (e?.code === '23505' || e?.message?.includes('duplicate key')) {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.ASSET_ALREADY_EXISTS,
            detail: `Asset "${canonicalValue}" (${type}) already exists in workspace "${cmd.workspaceId}".`,
            instance,
            correlationId,
          })
        );
      }
      return err(
        createProblemDetails({
          errorCode: ErrorCode.ASSET_VALIDATION_FAILED,
          detail: `Failed to persist asset: ${e?.message || 'Unknown error'}`,
          instance,
          correlationId,
        })
      );
    }
  }

  /**
   * Retrieves an asset by ID strictly within the authorized workspace.
   */
  async getAsset(id: AssetId, workspaceId: WorkspaceId): Promise<Result<AssetEntity, ProblemDetails>> {
    const record = await this.repo.findById(id, workspaceId);
    if (!record) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.ASSET_NOT_FOUND,
          detail: `Asset "${id}" not found in workspace "${workspaceId}".`,
          instance: `/workspaces/${workspaceId}/assets/${id}`,
          correlationId: generateUUIDv7(),
        })
      );
    }
    return ok(this.mapRecordToEntity(record));
  }

  /**
   * Retrieves an asset by canonical value within a workspace.
   */
  async getByCanonical(
    workspaceId: WorkspaceId,
    type: AssetEntity['type'],
    canonicalValue: string
  ): Promise<Result<AssetEntity, ProblemDetails>> {
    const record = await this.repo.findByCanonicalValue(workspaceId, type, canonicalValue);
    if (!record) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.ASSET_NOT_FOUND,
          detail: `Asset with canonical value "${canonicalValue}" (${type}) not found in workspace.`,
          instance: `/workspaces/${workspaceId}/assets`,
          correlationId: generateUUIDv7(),
        })
      );
    }
    return ok(this.mapRecordToEntity(record));
  }

  /**
   * Updates mutable attributes of an existing asset.
   */
  async updateAsset(
    id: AssetId,
    workspaceId: WorkspaceId,
    cmd: UpdateAssetCommand
  ): Promise<Result<AssetEntity, ProblemDetails>> {
    const correlationId = cmd.correlationId ?? generateUUIDv7();
    const instance = `/workspaces/${workspaceId}/assets/${id}`;

    const updateParams: UpdateAssetParams = {};
    if (cmd.name !== undefined) (updateParams as any).name = cmd.name;
    if (cmd.criticality !== undefined) (updateParams as any).criticality = cmd.criticality;
    if (cmd.status !== undefined) (updateParams as any).status = cmd.status;
    if (cmd.tags !== undefined) (updateParams as any).tags = cmd.tags;
    if (cmd.metadata !== undefined) (updateParams as any).metadata = cmd.metadata;

    const updated = await this.repo.updateAsset(id, workspaceId, updateParams);

    if (!updated) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.ASSET_NOT_FOUND,
          detail: `Asset "${id}" not found in workspace "${workspaceId}".`,
          instance,
          correlationId,
        })
      );
    }

    return ok(this.mapRecordToEntity(updated));
  }

  /**
   * Lists assets in workspace with optional filtering.
   */
  async listAssets(
    workspaceId: WorkspaceId,
    filter?: ListAssetsFilter
  ): Promise<Result<AssetEntity[], ProblemDetails>> {
    const options: ListAssetOptions = {};
    if (filter?.type) (options as any).type = filter.type;
    if (filter?.status) (options as any).status = filter.status;
    if (filter?.limit !== undefined) (options as any).limit = filter.limit;
    if (filter?.offset !== undefined) (options as any).offset = filter.offset;

    const records = await this.repo.listAssets(workspaceId, options);
    return ok(records.map((r) => this.mapRecordToEntity(r)));
  }

  private mapRecordToEntity(r: AssetRecord): AssetEntity {
    return {
      id: r.id,
      workspaceId: r.workspaceId,
      organizationId: r.organizationId,
      type: r.type,
      canonicalValue: r.canonicalValue,
      name: r.name,
      criticality: r.criticality,
      status: r.status,
      tags: r.tags,
      metadata: r.metadata,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    };
  }
}
