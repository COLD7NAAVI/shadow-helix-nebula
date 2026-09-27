/**
 * Shadow : Helix Nebula (SHN) — Workspace Repository
 *
 * Bounded Context: Workspace (mod_workspace)
 * Owns table: workspace.workspaces
 * Strictly prohibits cross-context SQL joins (MOD-INV-01, DATA-INV-05).
 */

import { isValidUUID, type WorkspaceId, type OrganizationId } from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface WorkspaceRecord {
  readonly id: WorkspaceId;
  readonly organization_id: OrganizationId;
  readonly name: string;
  readonly slug: string;
  readonly environment: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface CreateWorkspaceInput {
  readonly id: WorkspaceId;
  readonly organization_id: OrganizationId;
  readonly name: string;
  readonly slug: string;
  readonly environment?: string;
}

export class WorkspaceRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findById(id: WorkspaceId): Promise<WorkspaceRecord | null> {
    if (typeof id !== 'string' || !isValidUUID(id)) {
      throw new Error(`Invalid WorkspaceId: must be a valid UUID string (received: ${String(id)})`);
    }

    const result = await this.db.query<WorkspaceRecord>(
      `SELECT id, organization_id, name, slug, environment, created_at, updated_at
       FROM workspace.workspaces
       WHERE id = $1;`,
      [id]
    );
    return result.rows[0] ?? null;
  }

  async findByIdAndOrganization(
    id: WorkspaceId,
    organizationId: OrganizationId
  ): Promise<WorkspaceRecord | null> {
    if (typeof id !== 'string' || !isValidUUID(id)) {
      throw new Error(`Invalid WorkspaceId: must be a valid UUID string (received: ${String(id)})`);
    }
    if (typeof organizationId !== 'string' || !isValidUUID(organizationId)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID string (received: ${String(organizationId)})`);
    }

    const result = await this.db.query<WorkspaceRecord>(
      `SELECT id, organization_id, name, slug, environment, created_at, updated_at
       FROM workspace.workspaces
       WHERE id = $1 AND organization_id = $2;`,
      [id, organizationId]
    );
    return result.rows[0] ?? null;
  }

  async findBySlug(
    organizationId: OrganizationId,
    slug: string
  ): Promise<WorkspaceRecord | null> {
    if (typeof organizationId !== 'string' || !isValidUUID(organizationId)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID string (received: ${String(organizationId)})`);
    }
    if (typeof slug !== 'string' || slug.trim().length === 0) {
      throw new Error('Invalid workspace slug: must be a non-empty string');
    }

    const result = await this.db.query<WorkspaceRecord>(
      `SELECT id, organization_id, name, slug, environment, created_at, updated_at
       FROM workspace.workspaces
       WHERE organization_id = $1 AND slug = $2;`,
      [organizationId, slug.trim().toLowerCase()]
    );
    return result.rows[0] ?? null;
  }

  async listByOrganization(
    organizationId: OrganizationId
  ): Promise<WorkspaceRecord[]> {
    if (typeof organizationId !== 'string' || !isValidUUID(organizationId)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID string (received: ${String(organizationId)})`);
    }

    const result = await this.db.query<WorkspaceRecord>(
      `SELECT id, organization_id, name, slug, environment, created_at, updated_at
       FROM workspace.workspaces
       WHERE organization_id = $1
       ORDER BY created_at ASC;`,
      [organizationId]
    );
    return result.rows;
  }

  async create(input: CreateWorkspaceInput): Promise<WorkspaceRecord> {
    if (typeof input.id !== 'string' || !isValidUUID(input.id)) {
      throw new Error(`Invalid WorkspaceId in create: must be a valid UUID string (received: ${String(input.id)})`);
    }
    if (typeof input.organization_id !== 'string' || !isValidUUID(input.organization_id)) {
      throw new Error(`Invalid OrganizationId in create: must be a valid UUID string (received: ${String(input.organization_id)})`);
    }
    if (typeof input.name !== 'string' || input.name.trim().length === 0) {
      throw new Error('Workspace name must be a non-empty string');
    }
    if (typeof input.slug !== 'string' || input.slug.trim().length === 0) {
      throw new Error('Workspace slug must be a non-empty string');
    }

    const result = await this.db.query<WorkspaceRecord>(
      `INSERT INTO workspace.workspaces (id, organization_id, name, slug, environment)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, organization_id, name, slug, environment, created_at, updated_at;`,
      [
        input.id,
        input.organization_id,
        input.name.trim(),
        input.slug.trim().toLowerCase(),
        input.environment ?? 'production',
      ]
    );
    const row = result.rows[0];
    if (!row) {
      throw new Error('Failed to create workspace: empty result set returned.');
    }
    return row;
  }
}
