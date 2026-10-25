/**
 * Shadow : Helix Nebula (SHN) — AI Recommendation Repository
 *
 * Persists structured, schema-validated security recommendations.
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import { generateUUIDv7 } from '@shn/shared-kernel';

export type RecommendationStatus = 'PENDING' | 'APPROVED' | 'DISMISSED' | 'EXECUTING' | 'COMPLETED' | 'FAILED';

export interface AiRecommendationRecord {
  readonly id: string;
  readonly workspaceId: string;
  readonly organizationId: string;
  readonly recommendationId: string;
  readonly objective: string;
  readonly rationale: string;
  readonly proposedCapability: string;
  readonly parameters: Record<string, unknown>;
  readonly target: string;
  readonly requiredScopeAction: string;
  readonly riskLevel: string;
  readonly requiresApproval: boolean;
  readonly confidence: number;
  readonly supportingEvidenceIds: string[];
  readonly assumptions: string[];
  readonly expectedImpact: string | null;
  readonly rollbackConditions: string | null;
  readonly status: RecommendationStatus;
  readonly executionId: string | null;
  readonly approvedBy: string | null;
  readonly approvedAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateAiRecommendationParams {
  readonly id?: string;
  readonly workspaceId: string;
  readonly organizationId: string;
  readonly recommendationId: string;
  readonly objective: string;
  readonly rationale: string;
  readonly proposedCapability: string;
  readonly parameters?: Record<string, unknown>;
  readonly target: string;
  readonly requiredScopeAction: string;
  readonly riskLevel?: string;
  readonly requiresApproval?: boolean;
  readonly confidence?: number;
  readonly supportingEvidenceIds?: string[];
  readonly assumptions?: string[];
  readonly expectedImpact?: string | null;
  readonly rollbackConditions?: string | null;
}

export class AiRecommendationRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async listByWorkspace(workspaceId: string, limit = 50): Promise<AiRecommendationRecord[]> {
    const query = `
      SELECT id, workspace_id, organization_id, recommendation_id, objective, rationale,
             proposed_capability, parameters, target, required_scope_action, risk_level,
             requires_approval, confidence, supporting_evidence_ids, assumptions,
             expected_impact, rollback_conditions, status, execution_id, approved_by,
             approved_at, created_at, updated_at
      FROM ai.recommendations
      WHERE workspace_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `;
    const res = await this.db.query(query, [workspaceId, limit]);
    return res.rows.map((r: any) => this.mapRow(r));
  }

  async findById(id: string, workspaceId: string): Promise<AiRecommendationRecord | null> {
    const query = `
      SELECT id, workspace_id, organization_id, recommendation_id, objective, rationale,
             proposed_capability, parameters, target, required_scope_action, risk_level,
             requires_approval, confidence, supporting_evidence_ids, assumptions,
             expected_impact, rollback_conditions, status, execution_id, approved_by,
             approved_at, created_at, updated_at
      FROM ai.recommendations
      WHERE id = $1 AND workspace_id = $2
      LIMIT 1;
    `;
    const res = await this.db.query(query, [id, workspaceId]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  async findByRecommendationId(recId: string, workspaceId: string): Promise<AiRecommendationRecord | null> {
    const query = `
      SELECT id, workspace_id, organization_id, recommendation_id, objective, rationale,
             proposed_capability, parameters, target, required_scope_action, risk_level,
             requires_approval, confidence, supporting_evidence_ids, assumptions,
             expected_impact, rollback_conditions, status, execution_id, approved_by,
             approved_at, created_at, updated_at
      FROM ai.recommendations
      WHERE recommendation_id = $1 AND workspace_id = $2
      LIMIT 1;
    `;
    const res = await this.db.query(query, [recId, workspaceId]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  async create(params: CreateAiRecommendationParams): Promise<AiRecommendationRecord> {
    const id = params.id ?? generateUUIDv7();
    const query = `
      INSERT INTO ai.recommendations (
        id, workspace_id, organization_id, recommendation_id, objective, rationale,
        proposed_capability, parameters, target, required_scope_action, risk_level,
        requires_approval, confidence, supporting_evidence_ids, assumptions,
        expected_impact, rollback_conditions, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14, $15, $16, $17, 'PENDING')
      ON CONFLICT (workspace_id, recommendation_id) DO UPDATE SET
        objective = EXCLUDED.objective,
        rationale = EXCLUDED.rationale,
        parameters = EXCLUDED.parameters,
        confidence = EXCLUDED.confidence,
        updated_at = clock_timestamp()
      RETURNING id, workspace_id, organization_id, recommendation_id, objective, rationale,
                proposed_capability, parameters, target, required_scope_action, risk_level,
                requires_approval, confidence, supporting_evidence_ids, assumptions,
                expected_impact, rollback_conditions, status, execution_id, approved_by,
                approved_at, created_at, updated_at;
    `;
    const res = await this.db.query(query, [
      id,
      params.workspaceId,
      params.organizationId,
      params.recommendationId,
      params.objective,
      params.rationale,
      params.proposedCapability,
      JSON.stringify(params.parameters ?? {}),
      params.target,
      params.requiredScopeAction,
      params.riskLevel ?? 'LOW',
      params.requiresApproval ?? false,
      params.confidence ?? 0.85,
      params.supportingEvidenceIds ?? [],
      params.assumptions ?? [],
      params.expectedImpact ?? null,
      params.rollbackConditions ?? null,
    ]);

    return this.mapRow(res.rows[0]);
  }

  async updateStatus(
    id: string,
    workspaceId: string,
    status: RecommendationStatus,
    updates: { approvedBy?: string | null; executionId?: string | null } = {}
  ): Promise<AiRecommendationRecord | null> {
    const query = `
      UPDATE ai.recommendations
      SET status = $1,
          approved_by = COALESCE($2, approved_by),
          approved_at = CASE WHEN $2 IS NOT NULL THEN clock_timestamp() ELSE approved_at END,
          execution_id = COALESCE($3, execution_id),
          updated_at = clock_timestamp()
      WHERE id = $4 AND workspace_id = $5
      RETURNING id, workspace_id, organization_id, recommendation_id, objective, rationale,
                proposed_capability, parameters, target, required_scope_action, risk_level,
                requires_approval, confidence, supporting_evidence_ids, assumptions,
                expected_impact, rollback_conditions, status, execution_id, approved_by,
                approved_at, created_at, updated_at;
    `;
    const res = await this.db.query(query, [
      status,
      updates.approvedBy ?? null,
      updates.executionId ?? null,
      id,
      workspaceId,
    ]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  private mapRow(row: any): AiRecommendationRecord {
    return {
      id: row.id,
      workspaceId: row.workspace_id,
      organizationId: row.organization_id,
      recommendationId: row.recommendation_id,
      objective: row.objective,
      rationale: row.rationale,
      proposedCapability: row.proposed_capability,
      parameters: typeof row.parameters === 'string' ? JSON.parse(row.parameters) : row.parameters,
      target: row.target,
      requiredScopeAction: row.required_scope_action,
      riskLevel: row.risk_level,
      requiresApproval: Boolean(row.requires_approval),
      confidence: Number(row.confidence),
      supportingEvidenceIds: Array.isArray(row.supporting_evidence_ids) ? row.supporting_evidence_ids : [],
      assumptions: Array.isArray(row.assumptions) ? row.assumptions : [],
      expectedImpact: row.expected_impact,
      rollbackConditions: row.rollback_conditions,
      status: row.status,
      executionId: row.execution_id,
      approvedBy: row.approved_by,
      approvedAt: row.approved_at ? new Date(row.approved_at).toISOString() : null,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }
}
