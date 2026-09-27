/**
 * Shadow : Helix Nebula (SHN) — User Repository
 *
 * Bounded Context: IAM (mod_auth_rbac)
 * Owns table: iam.users
 * Strictly prohibits cross-context SQL joins (MOD-INV-01, DATA-INV-05).
 */

import { isValidUUID, type OrganizationId } from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface UserRecord {
  readonly id: string;
  readonly organization_id: OrganizationId;
  readonly email: string;
  readonly display_name: string;
  readonly status: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface CreateUserInput {
  readonly id: string;
  readonly organization_id: OrganizationId;
  readonly email: string;
  readonly display_name: string;
  readonly status?: string;
}

export class UserRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findById(id: string): Promise<UserRecord | null> {
    if (typeof id !== 'string' || !isValidUUID(id)) {
      throw new Error(`Invalid user id: must be a valid UUID string (received: ${String(id)})`);
    }

    const result = await this.db.query<UserRecord>(
      `SELECT id, organization_id, email, display_name, status, created_at, updated_at
       FROM iam.users
       WHERE id = $1;`,
      [id]
    );
    return result.rows[0] ?? null;
  }

  async findByEmail(
    organizationId: OrganizationId,
    email: string
  ): Promise<UserRecord | null> {
    if (typeof organizationId !== 'string' || !isValidUUID(organizationId)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID string (received: ${String(organizationId)})`);
    }
    if (typeof email !== 'string' || !email.includes('@')) {
      throw new Error(`Invalid email address: "${email}"`);
    }

    const result = await this.db.query<UserRecord>(
      `SELECT id, organization_id, email, display_name, status, created_at, updated_at
       FROM iam.users
       WHERE organization_id = $1 AND email = $2;`,
      [organizationId, email.trim().toLowerCase()]
    );
    return result.rows[0] ?? null;
  }

  async listByOrganization(organizationId: OrganizationId): Promise<UserRecord[]> {
    if (typeof organizationId !== 'string' || !isValidUUID(organizationId)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID string (received: ${String(organizationId)})`);
    }

    const result = await this.db.query<UserRecord>(
      `SELECT id, organization_id, email, display_name, status, created_at, updated_at
       FROM iam.users
       WHERE organization_id = $1
       ORDER BY created_at ASC;`,
      [organizationId]
    );
    return result.rows;
  }

  async create(input: CreateUserInput): Promise<UserRecord> {
    if (typeof input.id !== 'string' || !isValidUUID(input.id)) {
      throw new Error(`Invalid user id in create: must be a valid UUID string (received: ${String(input.id)})`);
    }
    if (typeof input.organization_id !== 'string' || !isValidUUID(input.organization_id)) {
      throw new Error(`Invalid OrganizationId in create: must be a valid UUID string (received: ${String(input.organization_id)})`);
    }
    if (typeof input.email !== 'string' || !input.email.includes('@')) {
      throw new Error(`Invalid email address in create: "${input.email}"`);
    }
    if (typeof input.display_name !== 'string' || input.display_name.trim().length === 0) {
      throw new Error('User display_name must be a non-empty string');
    }

    const result = await this.db.query<UserRecord>(
      `INSERT INTO iam.users (id, organization_id, email, display_name, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, organization_id, email, display_name, status, created_at, updated_at;`,
      [
        input.id,
        input.organization_id,
        input.email.trim().toLowerCase(),
        input.display_name.trim(),
        input.status ?? 'active',
      ]
    );
    const row = result.rows[0];
    if (!row) {
      throw new Error('Failed to create user: empty result set returned.');
    }
    return row;
  }
}
