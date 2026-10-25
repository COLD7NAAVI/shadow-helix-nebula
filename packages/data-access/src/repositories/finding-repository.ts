/**
 * Shadow : Helix Nebula (SHN) — Finding Lifecycle Repository
 *
 * Authoritative Spec: Phase 0.3 (BC-FND), Phase 0.4 (INV-01, INV-05),
 *                    Phase 0.7 Section 4.3.5 (mod_finding_lifecycle),
 *                    Phase 0.10 (Sections 4 & 7)
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import { runInTransaction } from '../transaction.js';
import type {
  WorkspaceId,
  OrganizationId,
  AssetId,
  FindingId,
  ExecutionId,
  UserId,
} from '@shn/shared-kernel';

export type FindingSeverity = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FindingStatus =
  | 'DRAFT'
  | 'UNDER_REVIEW'
  | 'CONFIRMED'
  | 'REMEDIATED'
  | 'FALSE_POSITIVE'
  | 'ACCEPTED_RISK';

export interface FindingRecord {
  readonly id: FindingId;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly assetId: AssetId;
  readonly executionId: ExecutionId | null;
  readonly title: string;
  readonly description: string;
  readonly category: string;
  readonly severity: FindingSeverity;
  readonly cveId: string | null;
  readonly cweId: string | null;
  readonly cvssScore: number | null;
  readonly cvssVector: string | null;
  readonly status: FindingStatus;
  readonly rawEvidenceSha256: string;
  readonly evidenceArtifactId: string | null;
  readonly remediationGuidance: string | null;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface FindingStatusTransitionRecord {
  readonly id: string;
  readonly findingId: FindingId;
  readonly workspaceId: WorkspaceId;
  readonly fromStatus: FindingStatus;
  readonly toStatus: FindingStatus;
  readonly changedBy: UserId;
  readonly reason: string | null;
  readonly createdAt: string;
}

export interface CreateFindingParams {
  readonly id?: FindingId;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly assetId: AssetId;
  readonly executionId?: ExecutionId | null;
  readonly title: string;
  readonly description: string;
  readonly category: string;
  readonly severity?: FindingSeverity;
  readonly cveId?: string | null;
  readonly cweId?: string | null;
  readonly cvssScore?: number | null;
  readonly cvssVector?: string | null;
  readonly status?: FindingStatus;
  readonly rawEvidenceSha256: string;
  readonly evidenceArtifactId?: string | null;
  readonly remediationGuidance?: string | null;
  readonly metadata?: Record<string, unknown>;
}

export interface ListFindingOptions {
  readonly assetId?: AssetId;
  readonly status?: FindingStatus;
  readonly severity?: FindingSeverity;
  readonly limit?: number;
  readonly offset?: number;
}

export interface TransitionStatusParams {
  readonly findingId: FindingId;
  readonly workspaceId: WorkspaceId;
  readonly toStatus: FindingStatus;
  readonly changedBy: UserId;
  readonly reason?: string;
}

export class FindingRepository {
  constructor(private readonly pool: DatabasePool) {}

  private getExecutor(client?: DatabaseClient): DatabasePool | DatabaseClient {
    return client ?? this.pool;
  }

  private mapRow(row: any): FindingRecord {
    return {
      id: row.id as FindingId,
      workspaceId: row.workspace_id as WorkspaceId,
      organizationId: row.organization_id as OrganizationId,
      assetId: row.asset_id as AssetId,
      executionId: (row.execution_id as ExecutionId) ?? null,
      title: row.title,
      description: row.description,
      category: row.category,
      severity: row.severity as FindingSeverity,
      cveId: row.cve_id ?? null,
      cweId: row.cwe_id ?? null,
      cvssScore: row.cvss_score !== null ? parseFloat(row.cvss_score) : null,
      cvssVector: row.cvss_vector ?? null,
      status: row.status as FindingStatus,
      rawEvidenceSha256: row.raw_evidence_sha256,
      evidenceArtifactId: row.evidence_artifact_id ?? null,
      remediationGuidance: row.remediation_guidance ?? null,
      metadata: typeof row.metadata === 'object' && row.metadata !== null ? row.metadata : {},
      createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
      updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  private mapTransitionRow(row: any): FindingStatusTransitionRecord {
    return {
      id: row.id,
      findingId: row.finding_id as FindingId,
      workspaceId: row.workspace_id as WorkspaceId,
      fromStatus: row.from_status as FindingStatus,
      toStatus: row.to_status as FindingStatus,
      changedBy: row.changed_by as UserId,
      reason: row.reason ?? null,
      createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
    };
  }

  async createFinding(params: CreateFindingParams, client?: DatabaseClient): Promise<FindingRecord> {
    const executor = this.getExecutor(client);
    const query = `
      INSERT INTO findings.findings (
        id, workspace_id, organization_id, asset_id, execution_id,
        title, description, category, severity, cve_id, cwe_id,
        cvss_score, cvss_vector, status, raw_evidence_sha256,
        evidence_artifact_id, remediation_guidance, metadata,
        created_at, updated_at
      )
      VALUES (
        COALESCE($1, gen_random_uuid()), $2, $3, $4, $5,
        $6, $7, $8, $9, $10, $11,
        $12, $13, $14, $15,
        $16, $17, $18,
        clock_timestamp(), clock_timestamp()
      )
      RETURNING *;
    `;

    const values = [
      params.id ?? null,
      params.workspaceId,
      params.organizationId,
      params.assetId,
      params.executionId ?? null,
      params.title,
      params.description,
      params.category,
      params.severity ?? 'INFORMATIONAL',
      params.cveId ?? null,
      params.cweId ?? null,
      params.cvssScore ?? null,
      params.cvssVector ?? null,
      params.status ?? 'DRAFT',
      params.rawEvidenceSha256,
      params.evidenceArtifactId ?? null,
      params.remediationGuidance ?? null,
      JSON.stringify(params.metadata ?? {}),
    ];

    const result = await executor.query(query, values);
    return this.mapRow(result.rows[0]);
  }

  async findById(
    id: FindingId,
    workspaceId?: WorkspaceId,
    client?: DatabaseClient
  ): Promise<FindingRecord | null> {
    const executor = this.getExecutor(client);
    let query = `SELECT * FROM findings.findings WHERE id = $1`;
    const params: any[] = [id];

    if (workspaceId) {
      query += ` AND workspace_id = $2`;
      params.push(workspaceId);
    }

    const result = await executor.query(query, params);
    if (result.rows.length === 0) return null;
    return this.mapRow(result.rows[0]);
  }

  async listFindings(
    workspaceId: WorkspaceId,
    options: ListFindingOptions = {},
    client?: DatabaseClient
  ): Promise<FindingRecord[]> {
    const executor = this.getExecutor(client);
    const clauses: string[] = ['workspace_id = $1'];
    const params: any[] = [workspaceId];
    let idx = 2;

    if (options.assetId) {
      clauses.push(`asset_id = $${idx++}`);
      params.push(options.assetId);
    }
    if (options.status) {
      clauses.push(`status = $${idx++}`);
      params.push(options.status);
    }
    if (options.severity) {
      clauses.push(`severity = $${idx++}`);
      params.push(options.severity);
    }

    let query = `
      SELECT * FROM findings.findings
      WHERE ${clauses.join(' AND ')}
      ORDER BY created_at DESC
    `;

    if (options.limit !== undefined) {
      query += ` LIMIT $${idx++}`;
      params.push(options.limit);
    }
    if (options.offset !== undefined) {
      query += ` OFFSET $${idx++}`;
      params.push(options.offset);
    }

    const result = await executor.query(query, params);
    return result.rows.map((row: any) => this.mapRow(row));
  }

  async transitionStatus(
    params: TransitionStatusParams,
    existingClient?: DatabaseClient
  ): Promise<FindingRecord | null> {
    const runInTx = async (client: DatabaseClient): Promise<FindingRecord | null> => {
      // 1. Fetch current status with row-level lock
      const selectQuery = `
        SELECT * FROM findings.findings
        WHERE id = $1 AND workspace_id = $2
        FOR UPDATE;
      `;
      const selectRes = await client.query(selectQuery, [params.findingId, params.workspaceId]);
      if (selectRes.rows.length === 0) return null;

      const currentRecord = this.mapRow(selectRes.rows[0]);
      const fromStatus = currentRecord.status;

      // 2. Update status
      const updateQuery = `
        UPDATE findings.findings
        SET status = $1, updated_at = clock_timestamp()
        WHERE id = $2 AND workspace_id = $3
        RETURNING *;
      `;
      const updateRes = await client.query(updateQuery, [
        params.toStatus,
        params.findingId,
        params.workspaceId,
      ]);

      // 3. Insert transition record
      const transitionQuery = `
        INSERT INTO findings.finding_status_transitions (
          finding_id, workspace_id, from_status, to_status, changed_by, reason, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp());
      `;
      await client.query(transitionQuery, [
        params.findingId,
        params.workspaceId,
        fromStatus,
        params.toStatus,
        params.changedBy,
        params.reason ?? null,
      ]);

      return this.mapRow(updateRes.rows[0]);
    };

    if (existingClient) {
      return runInTx(existingClient);
    }

    return runInTransaction(this.pool, (client) => runInTx(client));
  }

  async listStatusTransitions(
    findingId: FindingId,
    workspaceId: WorkspaceId,
    client?: DatabaseClient
  ): Promise<FindingStatusTransitionRecord[]> {
    const executor = this.getExecutor(client);
    const query = `
      SELECT * FROM findings.finding_status_transitions
      WHERE finding_id = $1 AND workspace_id = $2
      ORDER BY created_at ASC;
    `;
    const result = await executor.query(query, [findingId, workspaceId]);
    return result.rows.map((row: any) => this.mapTransitionRow(row));
  }

  async deleteFinding(
    id: FindingId,
    workspaceId: WorkspaceId,
    client?: DatabaseClient
  ): Promise<boolean> {
    const executor = this.getExecutor(client);
    const query = `DELETE FROM findings.findings WHERE id = $1 AND workspace_id = $2;`;
    const result = await executor.query(query, [id, workspaceId]);
    return (result.rowCount ?? 0) > 0;
  }

  async countFindings(workspaceId: WorkspaceId, client?: DatabaseClient): Promise<number> {
    const executor = this.getExecutor(client);
    const query = `SELECT COUNT(*)::int AS count FROM findings.findings WHERE workspace_id = $1;`;
    const result = await executor.query(query, [workspaceId]);
    return Number(result.rows[0]?.count ?? 0);
  }

  async listByWorkspace(
    workspaceId: WorkspaceId,
    options: ListFindingOptions = {},
    client?: DatabaseClient
  ): Promise<FindingRecord[]> {
    return this.listFindings(workspaceId, options, client);
  }

  async create(params: CreateFindingParams, client?: DatabaseClient): Promise<FindingRecord> {
    return this.createFinding(params, client);
  }
}
