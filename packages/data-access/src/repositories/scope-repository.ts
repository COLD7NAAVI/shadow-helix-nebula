/**
 * Shadow : Helix Nebula (SHN) — Scope Repository
 *
 * Bounded Context: Scope Enforcement (mod_scope_gatekeeper / BC-SCP)
 * Owns table: workspace.scopes
 * Every query enforces workspace_id multi-tenant hermeticity (INV-19, DATA-INV-08).
 */

import {
  isValidUUID,
  type ScopeId,
  type WorkspaceId,
  type OrganizationId,
  type UserId,
} from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export type ScopeStatus = 'ACTIVE' | 'SUSPENDED' | 'ARCHIVED' | 'EXPIRED';

export interface ScopeRecord {
  readonly id: ScopeId;
  readonly workspace_id: WorkspaceId;
  readonly organization_id: OrganizationId;
  readonly name: string;
  readonly description: string | null;
  readonly status: ScopeStatus;
  readonly inclusions: readonly unknown[];
  readonly exclusions: readonly unknown[];
  readonly allowed_actions: readonly string[];
  readonly disallowed_actions: readonly string[];
  readonly port_ranges: readonly { start: number; end: number }[];
  readonly valid_from: string;
  readonly valid_until: string;
  readonly rate_limits: Record<string, unknown>;
  readonly scope_sha256: string;
  readonly created_by: UserId | null;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface CreateScopeInput {
  readonly id?: ScopeId | string;
  readonly workspace_id: WorkspaceId | string;
  readonly organization_id: OrganizationId | string;
  readonly name: string;
  readonly description?: string | null;
  readonly status?: ScopeStatus;
  readonly inclusions: readonly unknown[];
  readonly exclusions?: readonly unknown[];
  readonly allowed_actions?: readonly string[];
  readonly disallowed_actions?: readonly string[];
  readonly port_ranges?: readonly { start: number; end: number }[];
  readonly valid_from: Date | string;
  readonly valid_until: Date | string;
  readonly rate_limits?: Record<string, unknown>;
  readonly scope_sha256: string;
  readonly created_by?: UserId | string | null;
}

export class ScopeRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async createScope(input: CreateScopeInput): Promise<ScopeRecord> {
    if (input.id !== undefined && !isValidUUID(input.id)) {
      throw new Error(`Invalid ScopeId: ${String(input.id)}`);
    }
    if (!isValidUUID(input.workspace_id)) {
      throw new Error(`Invalid WorkspaceId: ${String(input.workspace_id)}`);
    }
    if (!isValidUUID(input.organization_id)) {
      throw new Error(`Invalid OrganizationId: ${String(input.organization_id)}`);
    }
    if (input.created_by && !isValidUUID(input.created_by)) {
      throw new Error(`Invalid UserId: ${String(input.created_by)}`);
    }
    if (typeof input.name !== 'string' || input.name.trim().length === 0) {
      throw new Error('Scope name must be a non-empty string');
    }
    if (typeof input.scope_sha256 !== 'string' || input.scope_sha256.length !== 64) {
      throw new Error('Scope sha256 must be a 64-character hex string');
    }

    const validFrom = input.valid_from instanceof Date ? input.valid_from.toISOString() : String(input.valid_from);
    const validUntil = input.valid_until instanceof Date ? input.valid_until.toISOString() : String(input.valid_until);

    const query = input.id
      ? `INSERT INTO workspace.scopes (
           id, workspace_id, organization_id, name, description, status,
           inclusions, exclusions, allowed_actions, disallowed_actions,
           port_ranges, valid_from, valid_until, rate_limits, scope_sha256, created_by
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
         RETURNING *;`
      : `INSERT INTO workspace.scopes (
           workspace_id, organization_id, name, description, status,
           inclusions, exclusions, allowed_actions, disallowed_actions,
           port_ranges, valid_from, valid_until, rate_limits, scope_sha256, created_by
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         RETURNING *;`;

    const params = input.id
      ? [
          input.id,
          input.workspace_id,
          input.organization_id,
          input.name.trim(),
          input.description ?? null,
          input.status ?? 'ACTIVE',
          JSON.stringify(input.inclusions ?? []),
          JSON.stringify(input.exclusions ?? []),
          JSON.stringify(input.allowed_actions ?? []),
          JSON.stringify(input.disallowed_actions ?? []),
          JSON.stringify(input.port_ranges ?? []),
          validFrom,
          validUntil,
          JSON.stringify(input.rate_limits ?? {}),
          input.scope_sha256,
          input.created_by ?? null,
        ]
      : [
          input.workspace_id,
          input.organization_id,
          input.name.trim(),
          input.description ?? null,
          input.status ?? 'ACTIVE',
          JSON.stringify(input.inclusions ?? []),
          JSON.stringify(input.exclusions ?? []),
          JSON.stringify(input.allowed_actions ?? []),
          JSON.stringify(input.disallowed_actions ?? []),
          JSON.stringify(input.port_ranges ?? []),
          validFrom,
          validUntil,
          JSON.stringify(input.rate_limits ?? {}),
          input.scope_sha256,
          input.created_by ?? null,
        ];

    const result = await this.db.query<ScopeRecord>(query, params);
    const row = result.rows[0];
    if (!row) throw new Error('Failed to create scope boundary: empty result set returned');
    return row;
  }

  async findById(
    scopeId: ScopeId | string,
    workspaceId: WorkspaceId | string
  ): Promise<ScopeRecord | null> {
    if (!isValidUUID(scopeId)) throw new Error(`Invalid ScopeId: ${String(scopeId)}`);
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    const result = await this.db.query<ScopeRecord>(
      `SELECT * FROM workspace.scopes
       WHERE id = $1 AND workspace_id = $2;`,
      [scopeId, workspaceId]
    );

    return result.rows[0] ?? null;
  }

  async findActiveByWorkspace(
    workspaceId: WorkspaceId | string
  ): Promise<readonly ScopeRecord[]> {
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    const result = await this.db.query<ScopeRecord>(
      `SELECT * FROM workspace.scopes
       WHERE workspace_id = $1 AND status = 'ACTIVE'
       ORDER BY created_at DESC;`,
      [workspaceId]
    );

    return result.rows;
  }

  async findBySha256(
    scopeSha256: string,
    workspaceId: WorkspaceId | string
  ): Promise<ScopeRecord | null> {
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);
    if (typeof scopeSha256 !== 'string' || scopeSha256.length !== 64) {
      throw new Error(`Invalid scope_sha256: must be 64-char string`);
    }

    const result = await this.db.query<ScopeRecord>(
      `SELECT * FROM workspace.scopes
       WHERE scope_sha256 = $1 AND workspace_id = $2;`,
      [scopeSha256, workspaceId]
    );

    return result.rows[0] ?? null;
  }

  async updateStatus(
    scopeId: ScopeId | string,
    workspaceId: WorkspaceId | string,
    status: ScopeStatus
  ): Promise<void> {
    if (!isValidUUID(scopeId)) throw new Error(`Invalid ScopeId: ${String(scopeId)}`);
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    await this.db.query(
      `UPDATE workspace.scopes
       SET status = $1, updated_at = clock_timestamp()
       WHERE id = $2 AND workspace_id = $3;`,
      [status, scopeId, workspaceId]
    );
  }

  async listByWorkspace(
    workspaceId: WorkspaceId | string
  ): Promise<readonly ScopeRecord[]> {
    if (!isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);

    const result = await this.db.query<ScopeRecord>(
      `SELECT * FROM workspace.scopes
       WHERE workspace_id = $1
       ORDER BY created_at DESC;`,
      [workspaceId]
    );

    return result.rows;
  }
}
