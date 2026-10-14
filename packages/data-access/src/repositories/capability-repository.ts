/**
 * Shadow : Helix Nebula (SHN) — Capability & Tool Adapter Repository
 *
 * Authoritative Spec: Phase 0.3 (BC-CAP), Phase 0.4 (INV-01, INV-03, INV-04),
 *                    Phase 0.7 Section 4.2.3 (mod_capability_registry),
 *                    Phase 0.8 (Plugin & Adapter Contracts),
 *                    Phase 0.9 (Tool Integration Architecture),
 *                    Phase 0.10 (Data Architecture), Phase 0.14
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import type { WorkspaceId } from '@shn/shared-kernel';

export interface CapabilityRecord {
  readonly internalId: string;
  readonly id: string;
  readonly workspaceId: WorkspaceId | null;
  readonly name: string;
  readonly version: string;
  readonly displayName: string;
  readonly description: string;
  readonly category: string;
  readonly riskLevel: string;
  readonly supportedTargets: readonly string[];
  readonly requiredPermissions: string;
  readonly requiredScopeAction: string;
  readonly argumentSchema: Record<string, unknown>;
  readonly outputSchema: Record<string, unknown>;
  readonly environmentRequirements: Record<string, unknown>;
  readonly resourceRequirements: Record<string, unknown>;
  readonly platformCompatibility: readonly string[];
  readonly lifecycleState: string;
  readonly integrityDigest: string;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface AdapterRecord {
  readonly internalId: string;
  readonly id: string;
  readonly workspaceId: WorkspaceId | null;
  readonly name: string;
  readonly version: string;
  readonly lifecycleState: string;
  readonly supportedCapabilities: readonly { readonly capabilityId: string; readonly versionConstraint: string }[];
  readonly platformCompatibility: readonly string[];
  readonly binaryPath: string;
  readonly manifestDigest: string;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface WorkspaceBindingRecord {
  readonly workspaceId: WorkspaceId;
  readonly capabilityId: string;
  readonly preferredAdapterId: string;
  readonly isEnabled: boolean;
  readonly overrides: Record<string, unknown>;
  readonly updatedAt: string;
}

export interface CreateCapabilityInput {
  readonly id: string;
  readonly workspaceId?: WorkspaceId | null | undefined;
  readonly name: string;
  readonly version: string;
  readonly displayName: string;
  readonly description: string;
  readonly category: string;
  readonly riskLevel?: string | undefined;
  readonly supportedTargets: readonly string[];
  readonly requiredPermissions?: number | bigint | undefined;
  readonly requiredScopeAction: string;
  readonly argumentSchema?: Record<string, unknown> | undefined;
  readonly outputSchema?: Record<string, unknown> | undefined;
  readonly environmentRequirements?: Record<string, unknown> | undefined;
  readonly resourceRequirements?: Record<string, unknown> | undefined;
  readonly platformCompatibility?: readonly string[] | undefined;
  readonly lifecycleState?: string | undefined;
  readonly integrityDigest: string;
  readonly metadata?: Record<string, unknown> | undefined;
}

export interface CreateAdapterInput {
  readonly id: string;
  readonly workspaceId?: WorkspaceId | null | undefined;
  readonly name: string;
  readonly version: string;
  readonly lifecycleState?: string | undefined;
  readonly supportedCapabilities: readonly { readonly capabilityId: string; readonly versionConstraint: string }[];
  readonly platformCompatibility?: readonly string[] | undefined;
  readonly binaryPath: string;
  readonly manifestDigest: string;
  readonly metadata?: Record<string, unknown> | undefined;
}

export interface ListCapabilitiesFilter {
  readonly workspaceId?: WorkspaceId | null | undefined;
  readonly category?: string | undefined;
  readonly lifecycleState?: string | undefined;
  readonly includeSystem?: boolean | undefined;
}

export interface ListAdaptersFilter {
  readonly workspaceId?: WorkspaceId | null | undefined;
  readonly capabilityId?: string | undefined;
  readonly lifecycleState?: string | undefined;
  readonly includeSystem?: boolean | undefined;
}

export class CapabilityRepository {
  constructor(private readonly pool: DatabasePool) {}

  private getExecutor(client?: DatabaseClient): DatabasePool | DatabaseClient {
    return client ?? this.pool;
  }

  // --------------------------------------------------------------------------
  // 1. Capability Management
  // --------------------------------------------------------------------------

  async registerCapability(
    input: CreateCapabilityInput,
    client?: DatabaseClient
  ): Promise<CapabilityRecord> {
    const executor = this.getExecutor(client);
    const targetWorkspaceId = input.workspaceId ?? null;

    const existing = await this.findCapabilityExact(input.id, targetWorkspaceId, client);
    if (existing) {
      if (existing.name !== input.name) {
        throw new Error(
          `Conflict: Capability '${input.id}' already exists with name '${existing.name}', cannot register with name '${input.name}'`
        );
      }
      if (existing.version !== input.version) {
        throw new Error(
          `Conflict: Capability '${input.id}' already exists with version '${existing.version}', cannot register with version '${input.version}'`
        );
      }
      return existing;
    }

    const sql = `
      INSERT INTO capabilities.capabilities (
        id, workspace_id, name, version, display_name, description,
        category, risk_level, supported_targets, required_permissions,
        required_scope_action, argument_schema, output_schema,
        environment_requirements, resource_requirements, platform_compatibility,
        lifecycle_state, integrity_digest, metadata
      ) VALUES (
        $1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10,
        $11, $12, $13,
        $14, $15, $16,
        $17, $18, $19
      )
      RETURNING *;
    `;
    const params = [
      input.id,
      targetWorkspaceId,
      input.name,
      input.version,
      input.displayName,
      input.description,
      input.category,
      input.riskLevel ?? 'INFORMATIONAL',
      input.supportedTargets,
      String(input.requiredPermissions ?? 0),
      input.requiredScopeAction,
      JSON.stringify(input.argumentSchema ?? {}),
      JSON.stringify(input.outputSchema ?? {}),
      JSON.stringify(input.environmentRequirements ?? {}),
      JSON.stringify(input.resourceRequirements ?? {}),
      input.platformCompatibility ?? ['linux', 'darwin', 'win32'],
      input.lifecycleState ?? 'ACTIVE',
      input.integrityDigest,
      JSON.stringify(input.metadata ?? {}),
    ];

    try {
      const result = await executor.query(sql, params);
      return this.mapCapabilityRow(result.rows[0]);
    } catch (err: any) {
      if (err.code === '23505') {
        const recheck = await this.findCapabilityExact(input.id, targetWorkspaceId, client);
        if (recheck) {
          if (recheck.name !== input.name || recheck.version !== input.version) {
            throw new Error(
              `Conflict: Capability '${input.id}' already exists with conflicting definition`
            );
          }
          return recheck;
        }
      }
      throw err;
    }
  }

  async findCapabilityById(
    id: string,
    workspaceId?: WorkspaceId | null,
    client?: DatabaseClient
  ): Promise<CapabilityRecord | null> {
    const executor = this.getExecutor(client);
    let sql: string;
    let params: unknown[];

    if (workspaceId) {
      // Find workspace-specific override first, or fall back to system-wide capability
      sql = `
        SELECT * FROM capabilities.capabilities
        WHERE id = $1 AND (workspace_id = $2 OR workspace_id IS NULL)
        ORDER BY CASE WHEN workspace_id = $2 THEN 0 ELSE 1 END
        LIMIT 1;
      `;
      params = [id, workspaceId];
    } else {
      sql = `
        SELECT * FROM capabilities.capabilities
        WHERE id = $1 AND workspace_id IS NULL
        LIMIT 1;
      `;
      params = [id];
    }

    const result = await executor.query(sql, params);
    if (result.rows.length === 0) return null;
    return this.mapCapabilityRow(result.rows[0]);
  }

  async listCapabilities(
    filter?: ListCapabilitiesFilter,
    client?: DatabaseClient
  ): Promise<readonly CapabilityRecord[]> {
    const executor = this.getExecutor(client);
    const conditions: string[] = [];
    const params: unknown[] = [];

    const workspaceId = filter?.workspaceId;
    const includeSystem = filter?.includeSystem ?? true;

    if (workspaceId) {
      if (includeSystem) {
        params.push(workspaceId);
        conditions.push(`(workspace_id = $${params.length} OR workspace_id IS NULL)`);
      } else {
        params.push(workspaceId);
        conditions.push(`workspace_id = $${params.length}`);
      }
    } else if (includeSystem) {
      conditions.push('workspace_id IS NULL');
    }

    if (filter?.category) {
      params.push(filter.category);
      conditions.push(`category = $${params.length}`);
    }

    if (filter?.lifecycleState) {
      params.push(filter.lifecycleState);
      conditions.push(`lifecycle_state = $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `SELECT * FROM capabilities.capabilities ${whereClause} ORDER BY category ASC, name ASC;`;
    const result = await executor.query(sql, params);
    return result.rows.map((row: any) => this.mapCapabilityRow(row));
  }

  async updateCapabilityLifecycle(
    id: string,
    state: string,
    workspaceId?: WorkspaceId | null,
    client?: DatabaseClient
  ): Promise<boolean> {
    const executor = this.getExecutor(client);
    let sql: string;
    let params: unknown[];

    if (workspaceId) {
      sql = `
        UPDATE capabilities.capabilities
        SET lifecycle_state = $1, updated_at = clock_timestamp()
        WHERE id = $2 AND workspace_id = $3;
      `;
      params = [state, id, workspaceId];
    } else {
      sql = `
        UPDATE capabilities.capabilities
        SET lifecycle_state = $1, updated_at = clock_timestamp()
        WHERE id = $2 AND workspace_id IS NULL;
      `;
      params = [state, id];
    }

    const result = await executor.query(sql, params);
    return (result.rowCount ?? 0) > 0;
  }

  // --------------------------------------------------------------------------
  // 2. Adapter Management
  // --------------------------------------------------------------------------

  async registerAdapter(
    input: CreateAdapterInput,
    client?: DatabaseClient
  ): Promise<AdapterRecord> {
    const executor = this.getExecutor(client);
    const targetWorkspaceId = input.workspaceId ?? null;

    const existing = await this.findAdapterExact(input.id, targetWorkspaceId, client);
    if (existing) {
      if (existing.name !== input.name) {
        throw new Error(
          `Conflict: Adapter '${input.id}' already exists with name '${existing.name}', cannot register with name '${input.name}'`
        );
      }
      if (existing.version !== input.version) {
        throw new Error(
          `Conflict: Adapter '${input.id}' already exists with version '${existing.version}', cannot register with version '${input.version}'`
        );
      }
      return existing;
    }

    const sql = `
      INSERT INTO capabilities.adapters (
        id, workspace_id, name, version, lifecycle_state,
        supported_capabilities, platform_compatibility, binary_path,
        manifest_digest, metadata
      ) VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8,
        $9, $10
      )
      RETURNING *;
    `;
    const params = [
      input.id,
      targetWorkspaceId,
      input.name,
      input.version,
      input.lifecycleState ?? 'REGISTERED',
      JSON.stringify(input.supportedCapabilities),
      input.platformCompatibility ?? ['linux', 'darwin', 'win32'],
      input.binaryPath,
      input.manifestDigest,
      JSON.stringify(input.metadata ?? {}),
    ];

    try {
      const result = await executor.query(sql, params);
      return this.mapAdapterRow(result.rows[0]);
    } catch (err: any) {
      if (err.code === '23505') {
        const recheck = await this.findAdapterExact(input.id, targetWorkspaceId, client);
        if (recheck) {
          if (recheck.name !== input.name || recheck.version !== input.version) {
            throw new Error(
              `Conflict: Adapter '${input.id}' already exists with conflicting definition`
            );
          }
          return recheck;
        }
      }
      throw err;
    }
  }

  async findAdapterById(
    id: string,
    workspaceId?: WorkspaceId | null,
    client?: DatabaseClient
  ): Promise<AdapterRecord | null> {
    const executor = this.getExecutor(client);
    let sql: string;
    let params: unknown[];

    if (workspaceId) {
      sql = `
        SELECT * FROM capabilities.adapters
        WHERE id = $1 AND (workspace_id = $2 OR workspace_id IS NULL)
        ORDER BY CASE WHEN workspace_id = $2 THEN 0 ELSE 1 END
        LIMIT 1;
      `;
      params = [id, workspaceId];
    } else {
      sql = `
        SELECT * FROM capabilities.adapters
        WHERE id = $1 AND workspace_id IS NULL
        LIMIT 1;
      `;
      params = [id];
    }

    const result = await executor.query(sql, params);
    if (result.rows.length === 0) return null;
    return this.mapAdapterRow(result.rows[0]);
  }

  async listAdapters(
    filter?: ListAdaptersFilter,
    client?: DatabaseClient
  ): Promise<readonly AdapterRecord[]> {
    const executor = this.getExecutor(client);
    const conditions: string[] = [];
    const params: unknown[] = [];

    const workspaceId = filter?.workspaceId;
    const includeSystem = filter?.includeSystem ?? true;

    if (workspaceId) {
      if (includeSystem) {
        params.push(workspaceId);
        conditions.push(`(workspace_id = $${params.length} OR workspace_id IS NULL)`);
      } else {
        params.push(workspaceId);
        conditions.push(`workspace_id = $${params.length}`);
      }
    } else if (includeSystem) {
      conditions.push('workspace_id IS NULL');
    }

    if (filter?.lifecycleState) {
      params.push(filter.lifecycleState);
      conditions.push(`lifecycle_state = $${params.length}`);
    }

    if (filter?.capabilityId) {
      params.push(filter.capabilityId);
      conditions.push(`supported_capabilities @> jsonb_build_array(jsonb_build_object('capabilityId', $${params.length}::text))`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `SELECT * FROM capabilities.adapters ${whereClause} ORDER BY name ASC;`;
    const result = await executor.query(sql, params);
    return result.rows.map((row: any) => this.mapAdapterRow(row));
  }

  async updateAdapterLifecycle(
    id: string,
    state: string,
    workspaceId?: WorkspaceId | null,
    client?: DatabaseClient
  ): Promise<boolean> {
    const executor = this.getExecutor(client);
    let sql: string;
    let params: unknown[];

    if (workspaceId) {
      sql = `
        UPDATE capabilities.adapters
        SET lifecycle_state = $1, updated_at = clock_timestamp()
        WHERE id = $2 AND workspace_id = $3;
      `;
      params = [state, id, workspaceId];
    } else {
      sql = `
        UPDATE capabilities.adapters
        SET lifecycle_state = $1, updated_at = clock_timestamp()
        WHERE id = $2 AND workspace_id IS NULL;
      `;
      params = [state, id];
    }

    const result = await executor.query(sql, params);
    return (result.rowCount ?? 0) > 0;
  }

  // --------------------------------------------------------------------------
  // 3. Workspace Bindings
  // --------------------------------------------------------------------------

  async setWorkspaceBinding(
    workspaceId: WorkspaceId,
    capabilityId: string,
    preferredAdapterId: string,
    isEnabled: boolean = true,
    overrides: Record<string, unknown> = {},
    client?: DatabaseClient
  ): Promise<void> {
    const executor = this.getExecutor(client);
    const sql = `
      INSERT INTO capabilities.workspace_bindings (
        workspace_id, capability_id, preferred_adapter_id, is_enabled, overrides, updated_at
      ) VALUES ($1, $2, $3, $4, $5, clock_timestamp())
      ON CONFLICT (workspace_id, capability_id) DO UPDATE SET
        preferred_adapter_id = EXCLUDED.preferred_adapter_id,
        is_enabled = EXCLUDED.is_enabled,
        overrides = EXCLUDED.overrides,
        updated_at = clock_timestamp();
    `;
    await executor.query(sql, [
      workspaceId,
      capabilityId,
      preferredAdapterId,
      isEnabled,
      JSON.stringify(overrides),
    ]);
  }

  async getWorkspaceBinding(
    workspaceId: WorkspaceId,
    capabilityId: string,
    client?: DatabaseClient
  ): Promise<WorkspaceBindingRecord | null> {
    const executor = this.getExecutor(client);
    const sql = `
      SELECT * FROM capabilities.workspace_bindings
      WHERE workspace_id = $1 AND capability_id = $2
      LIMIT 1;
    `;
    const result = await executor.query(sql, [workspaceId, capabilityId]);
    if (result.rows.length === 0 || !result.rows[0]) return null;
    const row = result.rows[0] as any;
    return {
      workspaceId: row.workspace_id as WorkspaceId,
      capabilityId: String(row.capability_id),
      preferredAdapterId: String(row.preferred_adapter_id),
      isEnabled: Boolean(row.is_enabled),
      overrides: (row.overrides ?? {}) as Record<string, unknown>,
      updatedAt: (row.updated_at as Date).toISOString(),
    };
  }

  // --------------------------------------------------------------------------
  // Mappers
  // --------------------------------------------------------------------------

  private mapCapabilityRow(row: any): CapabilityRecord {
    return {
      internalId: row.internal_id,
      id: row.id,
      workspaceId: row.workspace_id ?? null,
      name: row.name,
      version: row.version,
      displayName: row.display_name,
      description: row.description,
      category: row.category,
      riskLevel: row.risk_level,
      supportedTargets: row.supported_targets ?? [],
      requiredPermissions: String(row.required_permissions),
      requiredScopeAction: row.required_scope_action,
      argumentSchema: row.argument_schema ?? {},
      outputSchema: row.output_schema ?? {},
      environmentRequirements: row.environment_requirements ?? {},
      resourceRequirements: row.resource_requirements ?? {},
      platformCompatibility: row.platform_compatibility ?? [],
      lifecycleState: row.lifecycle_state,
      integrityDigest: row.integrity_digest,
      metadata: row.metadata ?? {},
      createdAt: row.created_at.toISOString(),
      updatedAt: row.updated_at.toISOString(),
    };
  }

  private mapAdapterRow(row: any): AdapterRecord {
    return {
      internalId: row.internal_id,
      id: row.id,
      workspaceId: row.workspace_id ?? null,
      name: row.name,
      version: row.version,
      lifecycleState: row.lifecycle_state,
      supportedCapabilities: row.supported_capabilities ?? [],
      platformCompatibility: row.platform_compatibility ?? [],
      binaryPath: row.binary_path,
      manifestDigest: row.manifest_digest,
      metadata: row.metadata ?? {},
      createdAt: row.created_at.toISOString(),
      updatedAt: row.updated_at.toISOString(),
    };
  }

  private async findAdapterExact(
    id: string,
    workspaceId: WorkspaceId | null,
    client?: DatabaseClient
  ): Promise<AdapterRecord | null> {
    const executor = this.getExecutor(client);
    const sql = workspaceId
      ? `SELECT * FROM capabilities.adapters WHERE id = $1 AND workspace_id = $2 LIMIT 1;`
      : `SELECT * FROM capabilities.adapters WHERE id = $1 AND workspace_id IS NULL LIMIT 1;`;
    const params = workspaceId ? [id, workspaceId] : [id];
    const result = await executor.query(sql, params);
    if (result.rows.length === 0 || !result.rows[0]) return null;
    return this.mapAdapterRow(result.rows[0]);
  }

  private async findCapabilityExact(
    id: string,
    workspaceId: WorkspaceId | null,
    client?: DatabaseClient
  ): Promise<CapabilityRecord | null> {
    const executor = this.getExecutor(client);
    const sql = workspaceId
      ? `SELECT * FROM capabilities.capabilities WHERE id = $1 AND workspace_id = $2 LIMIT 1;`
      : `SELECT * FROM capabilities.capabilities WHERE id = $1 AND workspace_id IS NULL LIMIT 1;`;
    const params = workspaceId ? [id, workspaceId] : [id];
    const result = await executor.query(sql, params);
    if (result.rows.length === 0 || !result.rows[0]) return null;
    return this.mapCapabilityRow(result.rows[0]);
  }
}
