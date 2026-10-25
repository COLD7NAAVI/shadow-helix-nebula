/**
 * Shadow : Helix Nebula (SHN) — Interactive Graph Layout Repository
 *
 * Persists Obsidian-like graph node positions, annotations, and view filters.
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import { generateUUIDv7 } from '@shn/shared-kernel';

export interface GraphLayoutRecord {
  readonly id: string;
  readonly workspaceId: string;
  readonly name: string;
  readonly isDefault: boolean;
  readonly positions: Record<string, { x: number; y: number }>;
  readonly annotations: Array<{ nodeId: string; note: string; createdAt: string }>;
  readonly filters: {
    nodeTypes: string[];
    minSeverity?: string;
    showHypotheses: boolean;
  };
  readonly createdBy: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface SaveGraphLayoutParams {
  readonly id?: string;
  readonly workspaceId: string;
  readonly name?: string;
  readonly isDefault?: boolean;
  readonly positions: Record<string, { x: number; y: number }>;
  readonly annotations?: Array<{ nodeId: string; note: string; createdAt: string }>;
  readonly filters?: {
    nodeTypes: string[];
    minSeverity?: string;
    showHypotheses: boolean;
  };
  readonly createdBy: string;
}

export class GraphLayoutRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findByWorkspace(workspaceId: string, name = 'Default Graph View'): Promise<GraphLayoutRecord | null> {
    const query = `
      SELECT id, workspace_id, name, is_default, positions, annotations, filters,
             created_by, created_at, updated_at
      FROM ui.graph_layouts
      WHERE workspace_id = $1 AND name = $2
      LIMIT 1;
    `;
    const res = await this.db.query(query, [workspaceId, name]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  async saveLayout(params: SaveGraphLayoutParams): Promise<GraphLayoutRecord> {
    const name = params.name ?? 'Default Graph View';
    const isDefault = params.isDefault ?? true;
    const annotations = JSON.stringify(params.annotations ?? []);
    const filters = JSON.stringify(params.filters ?? {
      nodeTypes: ['ASSET', 'SERVICE', 'FINDING', 'SCOPE', 'EXECUTION', 'HYPOTHESIS'],
      showHypotheses: true,
    });
    const positions = JSON.stringify(params.positions ?? {});
    const id = params.id ?? generateUUIDv7();

    const query = `
      INSERT INTO ui.graph_layouts (
        id, workspace_id, name, is_default, positions, annotations, filters, created_by, updated_at
      ) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, clock_timestamp())
      ON CONFLICT (workspace_id, name) DO UPDATE SET
        positions = EXCLUDED.positions,
        annotations = EXCLUDED.annotations,
        filters = EXCLUDED.filters,
        is_default = EXCLUDED.is_default,
        updated_at = clock_timestamp()
      RETURNING id, workspace_id, name, is_default, positions, annotations, filters,
                created_by, created_at, updated_at;
    `;

    const res = await this.db.query(query, [
      id,
      params.workspaceId,
      name,
      isDefault,
      positions,
      annotations,
      filters,
      params.createdBy,
    ]);

    return this.mapRow(res.rows[0]);
  }

  private mapRow(row: any): GraphLayoutRecord {
    return {
      id: row.id,
      workspaceId: row.workspace_id,
      name: row.name,
      isDefault: row.is_default,
      positions: typeof row.positions === 'string' ? JSON.parse(row.positions) : row.positions,
      annotations: typeof row.annotations === 'string' ? JSON.parse(row.annotations) : row.annotations,
      filters: typeof row.filters === 'string' ? JSON.parse(row.filters) : row.filters,
      createdBy: row.created_by,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }
}
