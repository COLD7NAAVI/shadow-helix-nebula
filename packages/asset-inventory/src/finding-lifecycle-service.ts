/**
 * Shadow : Helix Nebula (SHN) — Finding Lifecycle Service
 *
 * Authoritative Spec: Phase 0.3 (BC-FND), Phase 0.4 (INV-01, INV-05, INV-11),
 * Phase 0.7 Section 4.3.5 (mod_finding_lifecycle), Phase 0.10 Section 7-8.
 * Enforces formal state machine transitions, mandatory raw evidence SHA-256 hashes,
 * CVSS boundaries, and tenant-isolated audit logging.
 */

import {
  ok,
  err,
  type Result,
  type FindingId,
  type WorkspaceId,
  createFindingId,
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
  FindingRepository,
  AssetRepository,
  type FindingRecord,
  type FindingStatusTransitionRecord,
  type CreateFindingParams,
  type TransitionStatusParams,
  type ListFindingOptions,
} from '@shn/data-access';
import { assertValidFindingStateTransition } from './finding-state-machine.js';
import type {
  FindingEntity,
  RecordFindingCommand,
  TransitionFindingStatusCommand,
  FindingStatusTransition,
  ListFindingsFilter,
} from './contracts.js';

const SHA256_HEX_REGEX = /^[0-9a-fA-F]{64}$/;

export interface FindingEventPublisher {
  publish(event: any): Promise<unknown>;
}

export interface FindingLifecycleServiceOptions {
  findingRepository: FindingRepository;
  assetRepository?: AssetRepository | undefined;
  eventBus?: FindingEventPublisher | undefined;
}

export class FindingLifecycleService {
  private readonly findingRepo: FindingRepository;
  private readonly assetRepo?: AssetRepository | undefined;
  private readonly eventBus?: FindingEventPublisher | undefined;

  constructor(options: FindingLifecycleServiceOptions) {
    this.findingRepo = options.findingRepository;
    this.assetRepo = options.assetRepository;
    this.eventBus = options.eventBus;
  }

  /**
   * Records a new finding with mandatory raw evidence SHA-256 (INV-05)
   * and verifies target asset belongs to the same workspace.
   */
  async recordFinding(cmd: RecordFindingCommand): Promise<Result<FindingEntity, ProblemDetails>> {
    const correlationId = cmd.correlationId ?? generateUUIDv7();
    const instance = `/workspaces/${cmd.workspaceId}/findings`;

    // 1. Evidence SHA-256 Hash Integrity Check (INV-05)
    if (!cmd.rawEvidenceSha256 || !SHA256_HEX_REGEX.test(cmd.rawEvidenceSha256)) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.FINDING_EVIDENCE_HASH_INVALID,
          detail: 'Mandatory cryptographic evidence hash (rawEvidenceSha256) is missing or invalid. Must be a 64-character lowercase hex string.',
          instance,
          correlationId,
          invalidParams: [{ name: 'rawEvidenceSha256', reason: 'Must match /^[0-9a-fA-F]{64}$/' }],
        })
      );
    }

    // 2. CVSS Score Range Validation
    if (cmd.cvssScore !== undefined && cmd.cvssScore !== null) {
      if (typeof cmd.cvssScore !== 'number' || cmd.cvssScore < 0.0 || cmd.cvssScore > 10.0) {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.FINDING_CVSS_INVALID,
            detail: `CVSS score must be a number between 0.0 and 10.0 inclusive. Received: ${cmd.cvssScore}`,
            instance,
            correlationId,
            invalidParams: [{ name: 'cvssScore', reason: 'Out of valid CVSS range [0.0..10.0]' }],
          })
        );
      }
    }

    // 3. Verify Target Asset belongs to Workspace if AssetRepository is provided
    if (this.assetRepo) {
      const asset = await this.assetRepo.findById(cmd.assetId, cmd.workspaceId);
      if (!asset) {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.ASSET_NOT_FOUND,
            detail: `Associated target asset "${cmd.assetId}" not found in workspace "${cmd.workspaceId}".`,
            instance,
            correlationId,
          })
        );
      }
    }

    // 4. Generate or validate Finding ID
    let findingId: FindingId;
    if (cmd.id) {
      const idRes = createFindingId(cmd.id);
      if (idRes.isErr) {
        return err(
          createProblemDetails({
            errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
            detail: `Invalid FindingId: ${idRes.error}`,
            instance,
            correlationId,
          })
        );
      }
      findingId = idRes.value;
    } else {
      const generated = createFindingId(generateUUIDv7());
      findingId = generated.isOk ? generated.value : (generateUUIDv7() as FindingId);
    }

    try {
      const createParams: CreateFindingParams = {
        id: findingId,
        workspaceId: cmd.workspaceId,
        organizationId: cmd.organizationId,
        assetId: cmd.assetId,
        executionId: cmd.executionId ?? null,
        title: cmd.title,
        description: cmd.description,
        category: cmd.category,
        severity: cmd.severity,
        cveId: cmd.cveId ?? null,
        cweId: cmd.cweId ?? null,
        cvssScore: cmd.cvssScore ?? null,
        cvssVector: cmd.cvssVector ?? null,
        status: cmd.status ?? 'DRAFT',
        rawEvidenceSha256: cmd.rawEvidenceSha256.toLowerCase(),
        evidenceArtifactId: cmd.evidenceArtifactId ?? null,
        remediationGuidance: cmd.remediationGuidance ?? null,
        metadata: cmd.metadata ?? {},
      };

      const record = await this.findingRepo.createFinding(createParams);
      const entity = this.mapRecordToEntity(record);

      // 5. Emit Domain Event
      if (this.eventBus) {
        try {
          const evIdRes = createEventId(generateUUIDv7());
          const corrRes = createCorrelationId(correlationId);
          const causRes = createCausationId(generateUUIDv7());

          await this.eventBus.publish({
            eventId: evIdRes.isOk ? evIdRes.value : generateUUIDv7(),
            eventType: 'finding.lifecycle.discovered',
            schemaVersion: '1.0.0',
            occurredAt: entity.createdAt,
            workspaceId: entity.workspaceId,
            correlationId: corrRes.isOk ? corrRes.value : correlationId,
            causationId: causRes.isOk ? causRes.value : generateUUIDv7(),
            producer: { module: 'mod_finding_lifecycle' },
            payload: {
              findingId: entity.id,
              assetId: entity.assetId,
              severity: entity.severity,
              status: entity.status,
              cveId: entity.cveId,
              rawEvidenceSha256: entity.rawEvidenceSha256,
            },
          });
        } catch {
          // Failure to publish async event does not abort synchronous database transaction
        }
      }

      return ok(entity);
    } catch (e: any) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: `Failed to record finding: ${e?.message || 'Unknown database error'}`,
          instance,
          correlationId,
        })
      );
    }
  }

  /**
   * Retrieves a finding by ID strictly within the authorized workspace.
   */
  async getFinding(id: FindingId, workspaceId: WorkspaceId): Promise<Result<FindingEntity, ProblemDetails>> {
    const record = await this.findingRepo.findById(id, workspaceId);
    if (!record) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.FINDING_NOT_FOUND,
          detail: `Finding "${id}" not found in workspace "${workspaceId}".`,
          instance: `/workspaces/${workspaceId}/findings/${id}`,
          correlationId: generateUUIDv7(),
        })
      );
    }
    return ok(this.mapRecordToEntity(record));
  }

  /**
   * Lists findings in workspace with optional filters.
   */
  async listFindings(
    workspaceId: WorkspaceId,
    filter?: ListFindingsFilter
  ): Promise<Result<FindingEntity[], ProblemDetails>> {
    const options: ListFindingOptions = {};
    if (filter?.assetId) (options as any).assetId = filter.assetId;
    if (filter?.status) (options as any).status = filter.status;
    if (filter?.severity) (options as any).severity = filter.severity;
    if (filter?.limit !== undefined) (options as any).limit = filter.limit;
    if (filter?.offset !== undefined) (options as any).offset = filter.offset;

    const records = await this.findingRepo.listFindings(workspaceId, options);
    return ok(records.map((r) => this.mapRecordToEntity(r)));
  }

  /**
   * Transitions finding lifecycle status atomically and records immutable transition history.
   * Enforces formal state machine transitions.
   */
  async transitionStatus(
    cmd: TransitionFindingStatusCommand
  ): Promise<Result<FindingEntity, ProblemDetails>> {
    const correlationId = cmd.correlationId ?? generateUUIDv7();
    const instance = `/workspaces/${cmd.workspaceId}/findings/${cmd.findingId}/transitions`;

    // 1. Fetch current finding state
    const current = await this.findingRepo.findById(cmd.findingId, cmd.workspaceId);
    if (!current) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.FINDING_NOT_FOUND,
          detail: `Finding "${cmd.findingId}" not found in workspace "${cmd.workspaceId}".`,
          instance,
          correlationId,
        })
      );
    }

    // 2. Validate state transition
    const transitionCheck = assertValidFindingStateTransition(current.status, cmd.toStatus);
    if (transitionCheck.isErr) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.FINDING_INVALID_STATE_TRANSITION,
          detail: transitionCheck.error,
          instance,
          correlationId,
        })
      );
    }

    // 3. Execute atomic transition with audit entry
    const transitionParams: TransitionStatusParams = {
      findingId: cmd.findingId,
      workspaceId: cmd.workspaceId,
      toStatus: cmd.toStatus,
      changedBy: cmd.changedBy,
    };
    if (cmd.reason !== undefined) {
      (transitionParams as any).reason = cmd.reason;
    }

    const updated = await this.findingRepo.transitionStatus(transitionParams);

    if (!updated) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.FINDING_NOT_FOUND,
          detail: `Failed to transition finding "${cmd.findingId}". Resource missing or concurrency conflict.`,
          instance,
          correlationId,
        })
      );
    }

    const entity = this.mapRecordToEntity(updated);

    // 4. Emit Domain Event
    if (this.eventBus) {
      try {
        const evIdRes = createEventId(generateUUIDv7());
        const corrRes = createCorrelationId(correlationId);
        const causRes = createCausationId(generateUUIDv7());

        await this.eventBus.publish({
          eventId: evIdRes.isOk ? evIdRes.value : generateUUIDv7(),
          eventType: 'finding.lifecycle.status_transitioned',
          schemaVersion: '1.0.0',
          occurredAt: new Date().toISOString(),
          workspaceId: entity.workspaceId,
          correlationId: corrRes.isOk ? corrRes.value : correlationId,
          causationId: causRes.isOk ? causRes.value : generateUUIDv7(),
          producer: { module: 'mod_finding_lifecycle' },
          payload: {
            findingId: entity.id,
            fromStatus: current.status,
            toStatus: entity.status,
            changedBy: cmd.changedBy,
            reason: cmd.reason ?? null,
          },
        });
      } catch {
        // Event publish failure non-blocking
      }
    }

    return ok(entity);
  }

  /**
   * Retrieves the immutable status transition audit history for a finding.
   */
  async getStatusHistory(
    findingId: FindingId,
    workspaceId: WorkspaceId
  ): Promise<Result<FindingStatusTransition[], ProblemDetails>> {
    const instance = `/workspaces/${workspaceId}/findings/${findingId}/history`;

    // Verify finding exists in workspace first
    const finding = await this.findingRepo.findById(findingId, workspaceId);
    if (!finding) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.FINDING_NOT_FOUND,
          detail: `Finding "${findingId}" not found in workspace "${workspaceId}".`,
          instance,
          correlationId: generateUUIDv7(),
        })
      );
    }

    const records = await this.findingRepo.listStatusTransitions(findingId, workspaceId);
    const history: FindingStatusTransition[] = records.map((r: FindingStatusTransitionRecord) => ({
      id: r.id,
      findingId: r.findingId,
      workspaceId: r.workspaceId,
      fromStatus: r.fromStatus,
      toStatus: r.toStatus,
      changedBy: r.changedBy,
      reason: r.reason,
      createdAt: r.createdAt,
    }));

    return ok(history);
  }

  private mapRecordToEntity(r: FindingRecord): FindingEntity {
    return {
      id: r.id,
      workspaceId: r.workspaceId,
      organizationId: r.organizationId,
      assetId: r.assetId,
      executionId: r.executionId,
      title: r.title,
      description: r.description,
      category: r.category,
      severity: r.severity,
      cveId: r.cveId,
      cweId: r.cweId,
      cvssScore: r.cvssScore,
      cvssVector: r.cvssVector,
      status: r.status,
      rawEvidenceSha256: r.rawEvidenceSha256,
      evidenceArtifactId: r.evidenceArtifactId,
      remediationGuidance: r.remediationGuidance,
      metadata: r.metadata,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    };
  }
}
