/**
 * Shadow : Helix Nebula (SHN) — AI Provider Repository
 *
 * Persists configurable AI provider definitions and models.
 * API keys are referenced through encrypted Secrets Vault (secrets.metadata).
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import { generateUUIDv7 } from '@shn/shared-kernel';

export type AiProviderType = 'OPENAI_COMPATIBLE' | 'OLLAMA' | 'ANTHROPIC' | 'LOCAL_HEURISTIC';
export type AiHealthStatus = 'UNKNOWN' | 'HEALTHY' | 'DEGRADED' | 'UNREACHABLE';

export interface AiProviderRecord {
  readonly id: string;
  readonly organizationId: string;
  readonly workspaceId: string | null;
  readonly providerType: AiProviderType;
  readonly displayName: string;
  readonly baseUrl: string | null;
  readonly modelName: string;
  readonly secretId: string | null;
  readonly isDefault: boolean;
  readonly isActive: boolean;
  readonly maxTokens: number;
  readonly temperature: number;
  readonly timeoutMs: number;
  readonly healthStatus: AiHealthStatus;
  readonly lastHealthCheckAt: string | null;
  readonly healthDetails: Record<string, unknown>;
  readonly privacyAcknowledged: boolean;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateAiProviderParams {
  readonly id?: string;
  readonly organizationId: string;
  readonly workspaceId?: string | null;
  readonly providerType: AiProviderType;
  readonly displayName: string;
  readonly baseUrl?: string | null;
  readonly modelName: string;
  readonly secretId?: string | null;
  readonly isDefault?: boolean;
  readonly isActive?: boolean;
  readonly maxTokens?: number;
  readonly temperature?: number;
  readonly timeoutMs?: number;
  readonly privacyAcknowledged?: boolean;
  readonly createdBy: string;
}

export class AiProviderRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async listByOrganization(organizationId: string, workspaceId?: string | null): Promise<AiProviderRecord[]> {
    let query = `
      SELECT id, organization_id, workspace_id, provider_type, display_name, base_url,
             model_name, secret_id, is_default, is_active, max_tokens, temperature,
             timeout_ms, health_status, last_health_check_at, health_details,
             privacy_acknowledged, created_by, created_at, updated_at
      FROM ai.provider_configs
      WHERE organization_id = $1
    `;
    const params: any[] = [organizationId];
    if (workspaceId !== undefined) {
      query += ` AND (workspace_id = $2 OR workspace_id IS NULL)`;
      params.push(workspaceId);
    }
    query += ` ORDER BY is_default DESC, created_at ASC;`;

    const res = await this.db.query(query, params);
    return res.rows.map((r: any) => this.mapRow(r));
  }

  async findById(id: string, organizationId: string): Promise<AiProviderRecord | null> {
    const query = `
      SELECT id, organization_id, workspace_id, provider_type, display_name, base_url,
             model_name, secret_id, is_default, is_active, max_tokens, temperature,
             timeout_ms, health_status, last_health_check_at, health_details,
             privacy_acknowledged, created_by, created_at, updated_at
      FROM ai.provider_configs
      WHERE id = $1 AND organization_id = $2
      LIMIT 1;
    `;
    const res = await this.db.query(query, [id, organizationId]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  async findDefault(organizationId: string, workspaceId?: string | null): Promise<AiProviderRecord | null> {
    const query = `
      SELECT id, organization_id, workspace_id, provider_type, display_name, base_url,
             model_name, secret_id, is_default, is_active, max_tokens, temperature,
             timeout_ms, health_status, last_health_check_at, health_details,
             privacy_acknowledged, created_by, created_at, updated_at
      FROM ai.provider_configs
      WHERE organization_id = $1 AND is_active = true
        AND (workspace_id = $2 OR workspace_id IS NULL)
      ORDER BY is_default DESC, (workspace_id IS NOT NULL) DESC, created_at ASC
      LIMIT 1;
    `;
    const res = await this.db.query(query, [organizationId, workspaceId ?? null]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  async create(params: CreateAiProviderParams): Promise<AiProviderRecord> {
    const id = params.id ?? generateUUIDv7();
    const query = `
      INSERT INTO ai.provider_configs (
        id, organization_id, workspace_id, provider_type, display_name, base_url,
        model_name, secret_id, is_default, is_active, max_tokens, temperature,
        timeout_ms, privacy_acknowledged, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING id, organization_id, workspace_id, provider_type, display_name, base_url,
                model_name, secret_id, is_default, is_active, max_tokens, temperature,
                timeout_ms, health_status, last_health_check_at, health_details,
                privacy_acknowledged, created_by, created_at, updated_at;
    `;
    const res = await this.db.query(query, [
      id,
      params.organizationId,
      params.workspaceId ?? null,
      params.providerType,
      params.displayName,
      params.baseUrl ?? null,
      params.modelName,
      params.secretId ?? null,
      params.isDefault ?? false,
      params.isActive ?? true,
      params.maxTokens ?? 4096,
      params.temperature ?? 0.2,
      params.timeoutMs ?? 30000,
      params.privacyAcknowledged ?? false,
      params.createdBy,
    ]);

    return this.mapRow(res.rows[0]);
  }

  async updateHealth(
    id: string,
    healthStatus: AiHealthStatus,
    details: Record<string, unknown> = {}
  ): Promise<void> {
    const query = `
      UPDATE ai.provider_configs
      SET health_status = $1,
          health_details = $2::jsonb,
          last_health_check_at = clock_timestamp(),
          updated_at = clock_timestamp()
      WHERE id = $3;
    `;
    await this.db.query(query, [healthStatus, JSON.stringify(details), id]);
  }

  async delete(id: string, organizationId: string): Promise<boolean> {
    const query = `DELETE FROM ai.provider_configs WHERE id = $1 AND organization_id = $2;`;
    const res = await this.db.query(query, [id, organizationId]);
    return (res.rowCount ?? 0) > 0;
  }

  private mapRow(row: any): AiProviderRecord {
    return {
      id: row.id,
      organizationId: row.organization_id,
      workspaceId: row.workspace_id,
      providerType: row.provider_type,
      displayName: row.display_name,
      baseUrl: row.base_url,
      modelName: row.model_name,
      secretId: row.secret_id,
      isDefault: Boolean(row.is_default),
      isActive: Boolean(row.is_active),
      maxTokens: Number(row.max_tokens),
      temperature: Number(row.temperature),
      timeoutMs: Number(row.timeout_ms),
      healthStatus: row.health_status,
      lastHealthCheckAt: row.last_health_check_at ? new Date(row.last_health_check_at).toISOString() : null,
      healthDetails: typeof row.health_details === 'string' ? JSON.parse(row.health_details) : row.health_details,
      privacyAcknowledged: Boolean(row.privacy_acknowledged),
      createdBy: row.created_by,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }
}
