/**
 * Shadow : Helix Nebula (SHN) — Asset Inventory & Finding Lifecycle Contracts
 *
 * Authoritative Spec: Phase 0.3 (BC-NRM, BC-FND), Phase 0.4 (INV-01, INV-05, INV-11),
 * Phase 0.7 Section 4.3.5 (mod_asset_inventory, mod_finding_lifecycle), Phase 0.10 Section 6-8.
 */

import type {
  AssetId,
  FindingId,
  WorkspaceId,
  OrganizationId,
  UserId,
  ExecutionId,
} from '@shn/shared-kernel';
import type {
  AssetType,
  AssetCriticality,
  AssetStatus,
  FindingSeverity,
  FindingStatus,
} from '@shn/data-access';

export type {
  AssetType,
  AssetCriticality,
  AssetStatus,
  FindingSeverity,
  FindingStatus,
};

export interface AssetEntity {
  id: AssetId;
  workspaceId: WorkspaceId;
  organizationId: OrganizationId;
  type: AssetType;
  canonicalValue: string;
  name: string;
  criticality: AssetCriticality;
  status: AssetStatus;
  tags: readonly string[];
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface RegisterAssetCommand {
  id?: AssetId;
  workspaceId: WorkspaceId;
  organizationId: OrganizationId;
  rawTarget: string;
  type?: AssetType;
  name?: string;
  criticality?: AssetCriticality;
  status?: AssetStatus;
  tags?: readonly string[];
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

export interface UpdateAssetCommand {
  name?: string;
  criticality?: AssetCriticality;
  status?: AssetStatus;
  tags?: readonly string[];
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

export interface ListAssetsFilter {
  type?: AssetType;
  status?: AssetStatus;
  limit?: number;
  offset?: number;
}

export interface FindingEntity {
  id: FindingId;
  workspaceId: WorkspaceId;
  organizationId: OrganizationId;
  assetId: AssetId;
  executionId?: ExecutionId | null;
  title: string;
  description: string;
  category: string;
  severity: FindingSeverity;
  cveId?: string | null;
  cweId?: string | null;
  cvssScore?: number | null;
  cvssVector?: string | null;
  status: FindingStatus;
  rawEvidenceSha256: string;
  evidenceArtifactId?: string | null;
  remediationGuidance?: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface RecordFindingCommand {
  id?: FindingId | undefined;
  workspaceId: WorkspaceId;
  organizationId: OrganizationId;
  assetId: AssetId;
  executionId?: ExecutionId | null | undefined;
  title: string;
  description: string;
  category: string;
  severity: FindingSeverity;
  cveId?: string | null | undefined;
  cweId?: string | null | undefined;
  cvssScore?: number | null | undefined;
  cvssVector?: string | null | undefined;
  status?: FindingStatus | undefined;
  rawEvidenceSha256: string;
  evidenceArtifactId?: string | null | undefined;
  remediationGuidance?: string | null | undefined;
  metadata?: Record<string, unknown> | undefined;
  correlationId?: string | undefined;
}

export interface TransitionFindingStatusCommand {
  findingId: FindingId;
  workspaceId: WorkspaceId;
  toStatus: FindingStatus;
  changedBy: UserId;
  reason?: string;
  correlationId?: string;
}

export interface FindingStatusTransition {
  id: string;
  findingId: FindingId;
  workspaceId: WorkspaceId;
  fromStatus: FindingStatus;
  toStatus: FindingStatus;
  changedBy: UserId;
  reason: string | null;
  createdAt: string;
}

export interface ListFindingsFilter {
  assetId?: AssetId;
  status?: FindingStatus;
  severity?: FindingSeverity;
  limit?: number;
  offset?: number;
}
