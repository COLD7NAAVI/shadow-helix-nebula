/**
 * Shadow : Helix Nebula (SHN) — Organization Repository
 *
 * Bounded Context: IAM (mod_auth_rbac)
 * Owns table: iam.organizations
 * Strictly prohibits cross-context SQL joins (MOD-INV-01, DATA-INV-05).
 */

import { isValidUUID, type OrganizationId } from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface OrganizationRecord {
  readonly id: OrganizationId;
  readonly name: string;
  readonly slug: string;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface CreateOrganizationInput {
  readonly id: OrganizationId;
  readonly name: string;
  readonly slug: string;
}

export class OrganizationRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findById(id: OrganizationId): Promise<OrganizationRecord | null> {
    if (typeof id !== 'string' || !isValidUUID(id)) {
      throw new Error(`Invalid OrganizationId: must be a valid UUID string (received: ${String(id)})`);
    }

    const result = await this.db.query<OrganizationRecord>(
      `SELECT id, name, slug, created_at, updated_at
       FROM iam.organizations
       WHERE id = $1;`,
      [id]
    );
    return result.rows[0] ?? null;
  }

  async findBySlug(slug: string): Promise<OrganizationRecord | null> {
    if (typeof slug !== 'string' || slug.trim().length === 0) {
      throw new Error('Invalid organization slug: must be a non-empty string');
    }

    const result = await this.db.query<OrganizationRecord>(
      `SELECT id, name, slug, created_at, updated_at
       FROM iam.organizations
       WHERE slug = $1;`,
      [slug.trim().toLowerCase()]
    );
    return result.rows[0] ?? null;
  }

  async create(input: CreateOrganizationInput): Promise<OrganizationRecord> {
    if (typeof input.id !== 'string' || !isValidUUID(input.id)) {
      throw new Error(`Invalid OrganizationId in create: must be a valid UUID string (received: ${String(input.id)})`);
    }

    if (typeof input.name !== 'string' || input.name.trim().length === 0) {
      throw new Error('Organization name must be a non-empty string');
    }

    if (typeof input.slug !== 'string' || input.slug.trim().length === 0) {
      throw new Error('Organization slug must be a non-empty string');
    }

    const result = await this.db.query<OrganizationRecord>(
      `INSERT INTO iam.organizations (id, name, slug)
       VALUES ($1, $2, $3)
       RETURNING id, name, slug, created_at, updated_at;`,
      [input.id, input.name.trim(), input.slug.trim().toLowerCase()]
    );
    const row = result.rows[0];
    if (!row) {
      throw new Error('Failed to create organization: empty result set returned.');
    }
    return row;
  }
}
