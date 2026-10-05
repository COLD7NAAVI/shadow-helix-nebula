/**
 * Shadow : Helix Nebula (SHN) — Role Repository
 *
 * Bounded Context: IAM (mod_auth_rbac)
 * Owns tables: iam.roles, iam.user_roles
 */

import {
  isValidUUID,
  type RoleId,
  type UserId,
  type OrganizationId,
  type WorkspaceId,
} from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface RoleRecord {
  readonly id: RoleId;
  readonly name: string;
  readonly description: string;
  readonly is_system: boolean;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface UserRoleRecord {
  readonly id: string;
  readonly user_id: UserId;
  readonly role_id: RoleId;
  readonly role_name: string;
  readonly organization_id: OrganizationId;
  readonly workspace_id: WorkspaceId | null;
  readonly assigned_by: UserId | null;
  readonly assigned_at: string;
}

export class RoleRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findRoleByName(name: string): Promise<RoleRecord | null> {
    const result = await this.db.query<RoleRecord>(
      `SELECT id, name, description, is_system, created_at, updated_at
       FROM iam.roles
       WHERE name = $1;`,
      [name.trim().toUpperCase()]
    );
    return result.rows[0] ?? null;
  }

  async findRoleById(id: RoleId | string): Promise<RoleRecord | null> {
    if (!isValidUUID(id)) {
      throw new Error(`Invalid RoleId: must be a valid UUID (received: ${String(id)})`);
    }

    const result = await this.db.query<RoleRecord>(
      `SELECT id, name, description, is_system, created_at, updated_at
       FROM iam.roles
       WHERE id = $1;`,
      [id]
    );
    return result.rows[0] ?? null;
  }

  async listRoles(): Promise<RoleRecord[]> {
    const result = await this.db.query<RoleRecord>(
      `SELECT id, name, description, is_system, created_at, updated_at
       FROM iam.roles
       ORDER BY name ASC;`
    );
    return result.rows;
  }

  async getUserRoles(
    userId: UserId | string,
    organizationId: OrganizationId | string,
    workspaceId?: WorkspaceId | string | null
  ): Promise<UserRoleRecord[]> {
    if (!isValidUUID(userId)) {
      throw new Error(`Invalid UserId: must be a valid UUID (received: ${String(userId)})`);
    }
    if (!isValidUUID(organizationId)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID (received: ${String(organizationId)})`);
    }
    if (workspaceId && !isValidUUID(workspaceId)) {
      throw new Error(`Invalid WorkspaceId: must be a valid UUID (received: ${String(workspaceId)})`);
    }

    let query: string;
    let params: unknown[];

    if (workspaceId) {
      query = `
        SELECT ur.id, ur.user_id, ur.role_id, r.name as role_name, ur.organization_id,
               ur.workspace_id, ur.assigned_by, ur.assigned_at
        FROM iam.user_roles ur
        JOIN iam.roles r ON ur.role_id = r.id
        WHERE ur.user_id = $1
          AND ur.organization_id = $2
          AND (ur.workspace_id = $3 OR ur.workspace_id IS NULL)
        ORDER BY r.name ASC;
      `;
      params = [userId, organizationId, workspaceId];
    } else {
      query = `
        SELECT ur.id, ur.user_id, ur.role_id, r.name as role_name, ur.organization_id,
               ur.workspace_id, ur.assigned_by, ur.assigned_at
        FROM iam.user_roles ur
        JOIN iam.roles r ON ur.role_id = r.id
        WHERE ur.user_id = $1
          AND ur.organization_id = $2
        ORDER BY r.name ASC;
      `;
      params = [userId, organizationId];
    }

    const result = await this.db.query<UserRoleRecord>(query, params);
    return result.rows;
  }

  async assignUserRole(
    userId: UserId | string,
    roleId: RoleId | string,
    organizationId: OrganizationId | string,
    workspaceId: WorkspaceId | string | null = null,
    assignedBy: UserId | string | null = null
  ): Promise<void> {
    if (!isValidUUID(userId)) throw new Error(`Invalid UserId: ${String(userId)}`);
    if (!isValidUUID(roleId)) throw new Error(`Invalid RoleId: ${String(roleId)}`);
    if (!isValidUUID(organizationId)) throw new Error(`Invalid OrganizationId: ${String(organizationId)}`);
    if (workspaceId && !isValidUUID(workspaceId)) throw new Error(`Invalid WorkspaceId: ${String(workspaceId)}`);
    if (assignedBy && !isValidUUID(assignedBy)) throw new Error(`Invalid AssignedBy UserId: ${String(assignedBy)}`);

    await this.db.query(
      `INSERT INTO iam.user_roles (user_id, role_id, organization_id, workspace_id, assigned_by)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, role_id, organization_id, workspace_id) DO NOTHING;`,
      [userId, roleId, organizationId, workspaceId, assignedBy]
    );
  }

  async revokeUserRole(
    userId: UserId | string,
    roleId: RoleId | string,
    organizationId: OrganizationId | string,
    workspaceId: WorkspaceId | string | null = null
  ): Promise<void> {
    if (!isValidUUID(userId)) throw new Error(`Invalid UserId: ${String(userId)}`);
    if (!isValidUUID(roleId)) throw new Error(`Invalid RoleId: ${String(roleId)}`);
    if (!isValidUUID(organizationId)) throw new Error(`Invalid OrganizationId: ${String(organizationId)}`);

    if (workspaceId) {
      await this.db.query(
        `DELETE FROM iam.user_roles
         WHERE user_id = $1 AND role_id = $2 AND organization_id = $3 AND workspace_id = $4;`,
        [userId, roleId, organizationId, workspaceId]
      );
    } else {
      await this.db.query(
        `DELETE FROM iam.user_roles
         WHERE user_id = $1 AND role_id = $2 AND organization_id = $3 AND workspace_id IS NULL;`,
        [userId, roleId, organizationId]
      );
    }
  }
}
