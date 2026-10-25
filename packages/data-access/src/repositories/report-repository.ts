/**
 * Shadow : Helix Nebula (SHN) — Report Repository
 *
 * Persists formal security assessment reports with cryptographic content hashes.
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import { generateUUIDv7 } from '@shn/shared-kernel';

export type ReportType = 'EXECUTIVE_SUMMARY' | 'TECHNICAL_ASSESSMENT' | 'COMPLIANCE_AUDIT' | 'EVIDENCE_CATALOG';
export type ReportStatus = 'DRAFT' | 'GENERATING' | 'COMPLETED' | 'FAILED';

export interface ReportRecord {
  readonly id: string;
  readonly workspaceId: string;
  readonly organizationId: string;
  readonly title: string;
  readonly reportType: ReportType;
  readonly scopeId: string | null;
  readonly status: ReportStatus;
  readonly version: number;
  readonly summaryContent: Record<string, unknown>;
  readonly findingsSnapshot: unknown[];
  readonly assetsSnapshot: unknown[];
  readonly executionsSnapshot: unknown[];
  readonly htmlContent: string | null;
  readonly contentSha256: string;
  readonly generatedBy: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateReportParams {
  readonly id?: string;
  readonly workspaceId: string;
  readonly organizationId: string;
  readonly title: string;
  readonly reportType?: ReportType;
  readonly scopeId?: string | null;
  readonly status?: ReportStatus;
  readonly summaryContent?: Record<string, unknown>;
  readonly findingsSnapshot?: unknown[];
  readonly assetsSnapshot?: unknown[];
  readonly executionsSnapshot?: unknown[];
  readonly htmlContent?: string | null;
  readonly contentSha256: string;
  readonly generatedBy: string;
}

export class ReportRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async listByWorkspace(workspaceId: string, limit = 50): Promise<ReportRecord[]> {
    const query = `
      SELECT id, workspace_id, organization_id, title, report_type, scope_id, status,
             version, summary_content, findings_snapshot, assets_snapshot,
             executions_snapshot, html_content, content_sha256, generated_by,
             created_at, updated_at
      FROM reporting.reports
      WHERE workspace_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `;
    const res = await this.db.query(query, [workspaceId, limit]);
    return res.rows.map((r: any) => this.mapRow(r));
  }

  async findById(id: string, workspaceId: string): Promise<ReportRecord | null> {
    const query = `
      SELECT id, workspace_id, organization_id, title, report_type, scope_id, status,
             version, summary_content, findings_snapshot, assets_snapshot,
             executions_snapshot, html_content, content_sha256, generated_by,
             created_at, updated_at
      FROM reporting.reports
      WHERE id = $1 AND workspace_id = $2
      LIMIT 1;
    `;
    const res = await this.db.query(query, [id, workspaceId]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  async create(params: CreateReportParams): Promise<ReportRecord> {
    const id = params.id ?? generateUUIDv7();
    const query = `
      INSERT INTO reporting.reports (
        id, workspace_id, organization_id, title, report_type, scope_id, status,
        version, summary_content, findings_snapshot, assets_snapshot, executions_snapshot,
        html_content, content_sha256, generated_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13, $14)
      RETURNING id, workspace_id, organization_id, title, report_type, scope_id, status,
                version, summary_content, findings_snapshot, assets_snapshot, executions_snapshot,
                html_content, content_sha256, generated_by, created_at, updated_at;
    `;
    const res = await this.db.query(query, [
      id,
      params.workspaceId,
      params.organizationId,
      params.title,
      params.reportType ?? 'EXECUTIVE_SUMMARY',
      params.scopeId ?? null,
      params.status ?? 'COMPLETED',
      JSON.stringify(params.summaryContent ?? {}),
      JSON.stringify(params.findingsSnapshot ?? []),
      JSON.stringify(params.assetsSnapshot ?? []),
      JSON.stringify(params.executionsSnapshot ?? []),
      params.htmlContent ?? null,
      params.contentSha256,
      params.generatedBy,
    ]);

    return this.mapRow(res.rows[0]);
  }

  private mapRow(row: any): ReportRecord {
    return {
      id: row.id,
      workspaceId: row.workspace_id,
      organizationId: row.organization_id,
      title: row.title,
      reportType: row.report_type,
      scopeId: row.scope_id,
      status: row.status,
      version: Number(row.version),
      summaryContent: typeof row.summary_content === 'string' ? JSON.parse(row.summary_content) : row.summary_content,
      findingsSnapshot: typeof row.findings_snapshot === 'string' ? JSON.parse(row.findings_snapshot) : row.findings_snapshot,
      assetsSnapshot: typeof row.assets_snapshot === 'string' ? JSON.parse(row.assets_snapshot) : row.assets_snapshot,
      executionsSnapshot: typeof row.executions_snapshot === 'string' ? JSON.parse(row.executions_snapshot) : row.executions_snapshot,
      htmlContent: row.html_content,
      contentSha256: row.content_sha256,
      generatedBy: row.generated_by,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }
}
