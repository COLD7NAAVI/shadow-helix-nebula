/**
 * Shadow : Helix Nebula (SHN) — Asset Inventory Repository
 *
 * Authoritative Spec: Phase 0.3 (BC-NRM), Phase 0.4 (INV-01),
 *                    Phase 0.10 (Sections 4 & 6)
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import type { WorkspaceId, OrganizationId, AssetId } from '@shn/shared-kernel';

export type AssetType = 'IPV4' | 'IPV6' | 'CIDR' | 'FQDN' | 'URL' | 'HOST';
export type AssetCriticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AssetStatus = 'ACTIVE' | 'INACTIVE' | 'ARCHIVED';

export interface AssetRecord {
  readonly id: AssetId;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly type: AssetType;
  readonly canonicalValue: string;
  readonly name: string;
  readonly criticality: AssetCriticality;
  readonly status: AssetStatus;
  readonly tags: readonly string[];
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateAssetParams {
  readonly id?: AssetId;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly type: AssetType;
  readonly canonicalValue: string;
  readonly name: string;
  readonly criticality?: AssetCriticality;
  readonly status?: AssetStatus;
  readonly tags?: readonly string[];
  readonly metadata?: Record<string, unknown>;
}

export interface UpdateAssetParams {
  readonly name?: string;
  readonly criticality?: AssetCriticality;
  readonly status?: AssetStatus;
  readonly tags?: readonly string[];
  readonly metadata?: Record<string, unknown>;
}

export interface ListAssetOptions {
  readonly type?: AssetType;
  readonly status?: AssetStatus;
  readonly limit?: number;
  readonly offset?: number;
}

export class AssetRepository {
  constructor(private readonly pool: DatabasePool) {}

  private getExecutor(client?: DatabaseClient): DatabasePool | DatabaseClient {
    return client ?? this.pool;
  }

  private mapRow(row: any): AssetRecord {
    return {
      id: row.id as AssetId,
      workspaceId: row.workspace_id as WorkspaceId,
      organizationId: row.organization_id as OrganizationId,
      type: row.type as AssetType,
      canonicalValue: row.canonical_value,
      name: row.name,
      criticality: row.criticality as AssetCriticality,
      status: row.status as AssetStatus,
      tags: Array.isArray(row.tags) ? row.tags : [],
      metadata: typeof row.metadata === 'object' && row.metadata !== null ? row.metadata : {},
      createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
      updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  async createAsset(params: CreateAssetParams, client?: DatabaseClient): Promise<AssetRecord> {
    const executor = this.getExecutor(client);
    const query = `
      INSERT INTO inventory.assets (
        id, workspace_id, organization_id, type, canonical_value,
        name, criticality, status, tags, metadata, created_at, updated_at
      )
      VALUES (
        COALESCE($1, gen_random_uuid()), $2, $3, $4, $5,
        $6, $7, $8, $9, $10, clock_timestamp(), clock_timestamp()
      )
      RETURNING *;
    `;

    const values = [
      params.id ?? null,
      params.workspaceId,
      params.organizationId,
      params.type,
      params.canonicalValue,
      params.name,
      params.criticality ?? 'MEDIUM',
      params.status ?? 'ACTIVE',
      params.tags ?? [],
      JSON.stringify(params.metadata ?? {}),
    ];

    const result = await executor.query(query, values);
    return this.mapRow(result.rows[0]);
  }

  async findById(
    id: AssetId,
    workspaceId?: WorkspaceId,
    client?: DatabaseClient
  ): Promise<AssetRecord | null> {
    const executor = this.getExecutor(client);
    let query = `SELECT * FROM inventory.assets WHERE id = $1`;
    const params: any[] = [id];

    if (workspaceId) {
      query += ` AND workspace_id = $2`;
      params.push(workspaceId);
    }

    const result = await executor.query(query, params);
    if (result.rows.length === 0) return null;
    return this.mapRow(result.rows[0]);
  }

  async findByCanonicalValue(
    workspaceId: WorkspaceId,
    type: AssetType,
    canonicalValue: string,
    client?: DatabaseClient
  ): Promise<AssetRecord | null> {
    const executor = this.getExecutor(client);
    const query = `
      SELECT * FROM inventory.assets
      WHERE workspace_id = $1 AND type = $2 AND canonical_value = $3;
    `;
    const result = await executor.query(query, [workspaceId, type, canonicalValue]);
    if (result.rows.length === 0) return null;
    return this.mapRow(result.rows[0]);
  }

  async listAssets(
    workspaceId: WorkspaceId,
    options: ListAssetOptions = {},
    client?: DatabaseClient
  ): Promise<AssetRecord[]> {
    const executor = this.getExecutor(client);
    const clauses: string[] = ['workspace_id = $1'];
    const params: any[] = [workspaceId];
    let idx = 2;

    if (options.type) {
      clauses.push(`type = $${idx++}`);
      params.push(options.type);
    }
    if (options.status) {
      clauses.push(`status = $${idx++}`);
      params.push(options.status);
    }

    let query = `
      SELECT * FROM inventory.assets
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

  async updateAsset(
    id: AssetId,
    workspaceId: WorkspaceId,
    params: UpdateAssetParams,
    client?: DatabaseClient
  ): Promise<AssetRecord | null> {
    const executor = this.getExecutor(client);
    const updates: string[] = ['updated_at = clock_timestamp()'];
    const values: any[] = [id, workspaceId];
    let idx = 3;

    if (params.name !== undefined) {
      updates.push(`name = $${idx++}`);
      values.push(params.name);
    }
    if (params.criticality !== undefined) {
      updates.push(`criticality = $${idx++}`);
      values.push(params.criticality);
    }
    if (params.status !== undefined) {
      updates.push(`status = $${idx++}`);
      values.push(params.status);
    }
    if (params.tags !== undefined) {
      updates.push(`tags = $${idx++}`);
      values.push(params.tags);
    }
    if (params.metadata !== undefined) {
      updates.push(`metadata = $${idx++}`);
      values.push(JSON.stringify(params.metadata));
    }

    const query = `
      UPDATE inventory.assets
      SET ${updates.join(', ')}
      WHERE id = $1 AND workspace_id = $2
      RETURNING *;
    `;

    const result = await executor.query(query, values);
    if (result.rows.length === 0) return null;
    return this.mapRow(result.rows[0]);
  }

  async deleteAsset(
    id: AssetId,
    workspaceId: WorkspaceId,
    client?: DatabaseClient
  ): Promise<boolean> {
    const executor = this.getExecutor(client);
    const query = `DELETE FROM inventory.assets WHERE id = $1 AND workspace_id = $2;`;
    const result = await executor.query(query, [id, workspaceId]);
    return (result.rowCount ?? 0) > 0;
  }

  async countAssets(workspaceId: WorkspaceId, client?: DatabaseClient): Promise<number> {
    const executor = this.getExecutor(client);
    const query = `SELECT COUNT(*)::int AS count FROM inventory.assets WHERE workspace_id = $1;`;
    const result = await executor.query(query, [workspaceId]);
    return Number(result.rows[0]?.count ?? 0);
  }

  async listByWorkspace(
    workspaceId: WorkspaceId,
    options: ListAssetOptions = {},
    client?: DatabaseClient
  ): Promise<AssetRecord[]> {
    return this.listAssets(workspaceId, options, client);
  }

  async create(params: CreateAssetParams, client?: DatabaseClient): Promise<AssetRecord> {
    return this.createAsset(params, client);
  }
}
