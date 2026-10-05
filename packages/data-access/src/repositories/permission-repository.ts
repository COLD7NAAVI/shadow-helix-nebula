/**
 * Shadow : Helix Nebula (SHN) — Permission Repository
 *
 * Bounded Context: IAM (mod_auth_rbac)
 * Owns tables: iam.permissions, iam.role_permissions
 */

import { isValidUUID, type PermissionId, type RoleId } from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface PermissionRecord {
  readonly id: PermissionId;
  readonly name: string;
  readonly bitmask: number;
  readonly description: string;
  readonly created_at: string;
}

export class PermissionRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async listPermissions(): Promise<PermissionRecord[]> {
    const result = await this.db.query<PermissionRecord>(
      `SELECT id, name, bitmask, description, created_at
       FROM iam.permissions
       ORDER BY bitmask ASC;`
    );
    return result.rows;
  }

  async getRolePermissions(roleId: RoleId | string): Promise<PermissionRecord[]> {
    if (!isValidUUID(roleId)) {
      throw new Error(`Invalid RoleId: must be a valid UUID (received: ${String(roleId)})`);
    }

    const result = await this.db.query<PermissionRecord>(
      `SELECT p.id, p.name, p.bitmask, p.description, p.created_at
       FROM iam.permissions p
       JOIN iam.role_permissions rp ON p.id = rp.permission_id
       WHERE rp.role_id = $1
       ORDER BY p.bitmask ASC;`,
      [roleId]
    );
    return result.rows;
  }

  async getEffectivePermissions(
    roleIds: Array<RoleId | string>
  ): Promise<{ permissions: PermissionRecord[]; bitmask: number }> {
    if (!Array.isArray(roleIds) || roleIds.length === 0) {
      return { permissions: [], bitmask: 0 };
    }

    for (const rId of roleIds) {
      if (!isValidUUID(rId)) {
        throw new Error(`Invalid RoleId: must be a valid UUID (received: ${String(rId)})`);
      }
    }

    const result = await this.db.query<PermissionRecord>(
      `SELECT DISTINCT p.id, p.name, p.bitmask, p.description, p.created_at
       FROM iam.permissions p
       JOIN iam.role_permissions rp ON p.id = rp.permission_id
       WHERE rp.role_id = ANY($1::uuid[])
       ORDER BY p.bitmask ASC;`,
      [roleIds]
    );

    let bitmask = 0;
    for (const perm of result.rows) {
      bitmask |= perm.bitmask;
    }

    return {
      permissions: result.rows,
      bitmask,
    };
  }
}
