/**
 * Shadow : Helix Nebula (SHN) — Execution Repository
 *
 * Bounded Context: Execution Supervision & Worker Sandbox (mod_execution_supervisor / BC-EXE)
 * Owns tables in schema: execution.*
 * Every query strictly enforces workspace_id multi-tenant hermeticity (INV-01, INV-14, DATA-INV-08).
 */

import {
  isValidUUID,
  type ExecutionId,
  type WorkspaceId,
  type OrganizationId,
  type UserId,
  type ScopeId,
} from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface ExecutionRecord {
  readonly id: ExecutionId;
  readonly workspace_id: WorkspaceId;
  readonly organization_id: OrganizationId;
  readonly scope_id: ScopeId | null;
  readonly action: string;
  readonly target: string;
  readonly capability_uri: string;
  readonly state: string;
  readonly requested_by: UserId;
  readonly command: Record<string, unknown>;
  readonly resource_policy: Record<string, unknown>;
  readonly execution_policy: Record<string, unknown>;
  readonly worker_spec: Record<string, unknown>;
  readonly result_payload: unknown | null;
  readonly failure_details: unknown | null;
  readonly stdout_summary: string | null;
  readonly stderr_summary: string | null;
  readonly raw_output_sha256: string | null;
  readonly created_at: string;
  readonly started_at: string | null;
  readonly completed_at: string | null;
  readonly updated_at: string;
  readonly version: number;
}

export interface ExecutionAttemptRecord {
  readonly id: string;
  readonly execution_id: ExecutionId;
  readonly workspace_id: WorkspaceId;
  readonly attempt_number: number;
  readonly worker_id: string;
  readonly state: string;
  readonly exit_code: number | null;
  readonly termination_reason: string | null;
  readonly started_at: string;
  readonly completed_at: string | null;
  readonly duration_ms: number | null;
}

export interface ExecutionArtifactRecord {
  readonly id: string;
  readonly execution_id: ExecutionId;
  readonly workspace_id: WorkspaceId;
  readonly name: string;
  readonly content_sha256: string;
  readonly storage_uri: string;
  readonly byte_size: number;
  readonly mime_type: string;
  readonly created_at: string;
}

export interface WorkerLeaseRecord {
  readonly worker_id: string;
  readonly execution_id: ExecutionId | null;
  readonly workspace_id: WorkspaceId | null;
  readonly status: string;
  readonly heartbeat_at: string;
  readonly lease_expires_at: string;
  readonly created_at: string;
}

export interface CreateExecutionInput {
  readonly id?: ExecutionId | string | undefined;
  readonly workspace_id: WorkspaceId | string;
  readonly organization_id: OrganizationId | string;
  readonly scope_id?: ScopeId | string | null | undefined;
  readonly action: string;
  readonly target: string;
  readonly capability_uri: string;
  readonly state?: string | undefined;
  readonly requested_by: UserId | string;
  readonly command: { executable: string; args: readonly string[] };
  readonly resource_policy?: Record<string, unknown> | undefined;
  readonly execution_policy?: Record<string, unknown> | undefined;
  readonly worker_spec?: Record<string, unknown> | undefined;
}

export interface CreateAttemptInput {
  readonly id?: string | undefined;
  readonly execution_id: ExecutionId | string;
  readonly workspace_id: WorkspaceId | string;
  readonly attempt_number?: number | undefined;
  readonly worker_id: string;
  readonly state: string;
  readonly exit_code?: number | null | undefined;
  readonly termination_reason?: string | null | undefined;
  readonly started_at?: Date | string | undefined;
  readonly completed_at?: Date | string | null | undefined;
  readonly duration_ms?: number | null | undefined;
}

export interface CreateArtifactInput {
  readonly id?: string | undefined;
  readonly execution_id: ExecutionId | string;
  readonly workspace_id: WorkspaceId | string;
  readonly name: string;
  readonly content_sha256: string;
  readonly storage_uri: string;
  readonly byte_size: number;
  readonly mime_type?: string | undefined;
}

export interface TransitionStateUpdates {
  readonly result_payload?: unknown | undefined;
  readonly failure_details?: unknown | undefined;
  readonly stdout_summary?: string | undefined;
  readonly stderr_summary?: string | undefined;
  readonly raw_output_sha256?: string | undefined;
  readonly started_at?: Date | string | undefined;
  readonly completed_at?: Date | string | undefined;
}

export class ExecutionRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async createExecution(input: CreateExecutionInput): Promise<ExecutionRecord> {
    if (input.id !== undefined && !isValidUUID(input.id)) {
      throw new Error(`Invalid ExecutionId: ${String(input.id)}`);
    }
    if (!isValidUUID(input.workspace_id)) {
      throw new Error(`Invalid WorkspaceId: ${String(input.workspace_id)}`);
    }
    if (!isValidUUID(input.organization_id)) {
      throw new Error(`Invalid OrganizationId: ${String(input.organization_id)}`);
    }
    if (!isValidUUID(input.requested_by)) {
      throw new Error(`Invalid UserId: ${String(input.requested_by)}`);
    }
    if (input.scope_id && !isValidUUID(input.scope_id)) {
      throw new Error(`Invalid ScopeId: ${String(input.scope_id)}`);
    }

    const state = input.state || 'CREATED';
    const query = input.id
      ? `INSERT INTO execution.executions (
           id, workspace_id, organization_id, scope_id, action, target,
           capability_uri, state, requested_by, command, resource_policy,
           execution_policy, worker_spec
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING *;`
      : `INSERT INTO execution.executions (
           workspace_id, organization_id, scope_id, action, target,
           capability_uri, state, requested_by, command, resource_policy,
           execution_policy, worker_spec
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING *;`;

    const params = input.id
      ? [
          input.id,
          input.workspace_id,
          input.organization_id,
          input.scope_id ?? null,
          input.action,
          input.target,
          input.capability_uri,
          state,
          input.requested_by,
          JSON.stringify(input.command),
          JSON.stringify(input.resource_policy || {}),
          JSON.stringify(input.execution_policy || {}),
          JSON.stringify(input.worker_spec || {}),
        ]
      : [
          input.workspace_id,
          input.organization_id,
          input.scope_id ?? null,
          input.action,
          input.target,
          input.capability_uri,
          state,
          input.requested_by,
          JSON.stringify(input.command),
          JSON.stringify(input.resource_policy || {}),
          JSON.stringify(input.execution_policy || {}),
          JSON.stringify(input.worker_spec || {}),
        ];

    const res = await this.db.query<ExecutionRecord>(query, params);
    const row = res.rows[0];
    if (!row) throw new Error('Failed to create execution record: empty result set');
    return row;
  }

  async findById(
    id: ExecutionId | string,
    workspaceId: WorkspaceId | string
  ): Promise<ExecutionRecord | null> {
    if (!isValidUUID(id) || !isValidUUID(workspaceId)) {
      return null;
    }

    const query = `
      SELECT *
      FROM execution.executions
      WHERE id = $1 AND workspace_id = $2;
    `;
    const res = await this.db.query<ExecutionRecord>(query, [id, workspaceId]);
    return res.rows[0] ?? null;
  }

  async transitionState(
    id: ExecutionId | string,
    workspaceId: WorkspaceId | string,
    fromState: string | string[],
    toState: string,
    updates: TransitionStateUpdates = {}
  ): Promise<ExecutionRecord | null> {
    if (!isValidUUID(id) || !isValidUUID(workspaceId)) {
      return null;
    }

    const fromStates = Array.isArray(fromState) ? fromState : [fromState];
    const startedAt = updates.started_at
      ? updates.started_at instanceof Date
        ? updates.started_at.toISOString()
        : updates.started_at
      : undefined;
    const completedAt = updates.completed_at
      ? updates.completed_at instanceof Date
        ? updates.completed_at.toISOString()
        : updates.completed_at
      : undefined;

    const query = `
      UPDATE execution.executions
      SET state = $1,
          version = version + 1,
          updated_at = clock_timestamp(),
          result_payload = COALESCE($2, result_payload),
          failure_details = COALESCE($3, failure_details),
          stdout_summary = COALESCE($4, stdout_summary),
          stderr_summary = COALESCE($5, stderr_summary),
          raw_output_sha256 = COALESCE($6, raw_output_sha256),
          started_at = COALESCE($7, started_at),
          completed_at = COALESCE($8, completed_at)
      WHERE id = $9
        AND workspace_id = $10
        AND state = ANY($11)
      RETURNING *;
    `;

    const params = [
      toState,
      updates.result_payload !== undefined ? JSON.stringify(updates.result_payload) : null,
      updates.failure_details !== undefined ? JSON.stringify(updates.failure_details) : null,
      updates.stdout_summary ?? null,
      updates.stderr_summary ?? null,
      updates.raw_output_sha256 ?? null,
      startedAt ?? null,
      completedAt ?? null,
      id,
      workspaceId,
      fromStates,
    ];

    const res = await this.db.query<ExecutionRecord>(query, params);
    return res.rows[0] ?? null;
  }

  async listByWorkspace(
    workspaceId: WorkspaceId | string,
    limit = 50,
    offset = 0
  ): Promise<ExecutionRecord[]> {
    if (!isValidUUID(workspaceId)) return [];

    const query = `
      SELECT *
      FROM execution.executions
      WHERE workspace_id = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3;
    `;
    const res = await this.db.query<ExecutionRecord>(query, [workspaceId, limit, offset]);
    return res.rows;
  }

  async recordAttempt(input: CreateAttemptInput): Promise<ExecutionAttemptRecord> {
    if (input.id !== undefined && !isValidUUID(input.id)) {
      throw new Error(`Invalid AttemptId: ${String(input.id)}`);
    }
    if (!isValidUUID(input.execution_id) || !isValidUUID(input.workspace_id)) {
      throw new Error('Invalid ExecutionId or WorkspaceId for Attempt');
    }

    const startedAt = input.started_at
      ? input.started_at instanceof Date
        ? input.started_at.toISOString()
        : input.started_at
      : new Date().toISOString();
    const completedAt = input.completed_at
      ? input.completed_at instanceof Date
        ? input.completed_at.toISOString()
        : input.completed_at
      : null;

    const query = input.id
      ? `INSERT INTO execution.execution_attempts (
           id, execution_id, workspace_id, attempt_number, worker_id,
           state, exit_code, termination_reason, started_at, completed_at, duration_ms
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING *;`
      : `INSERT INTO execution.execution_attempts (
           execution_id, workspace_id, attempt_number, worker_id,
           state, exit_code, termination_reason, started_at, completed_at, duration_ms
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *;`;

    const params = input.id
      ? [
          input.id,
          input.execution_id,
          input.workspace_id,
          input.attempt_number ?? 1,
          input.worker_id,
          input.state,
          input.exit_code ?? null,
          input.termination_reason ?? null,
          startedAt,
          completedAt,
          input.duration_ms ?? null,
        ]
      : [
          input.execution_id,
          input.workspace_id,
          input.attempt_number ?? 1,
          input.worker_id,
          input.state,
          input.exit_code ?? null,
          input.termination_reason ?? null,
          startedAt,
          completedAt,
          input.duration_ms ?? null,
        ];

    const res = await this.db.query<ExecutionAttemptRecord>(query, params);
    const row = res.rows[0];
    if (!row) throw new Error('Failed to record attempt: empty result set');
    return row;
  }

  async listAttempts(
    executionId: ExecutionId | string,
    workspaceId: WorkspaceId | string
  ): Promise<ExecutionAttemptRecord[]> {
    if (!isValidUUID(executionId) || !isValidUUID(workspaceId)) return [];

    const query = `
      SELECT *
      FROM execution.execution_attempts
      WHERE execution_id = $1 AND workspace_id = $2
      ORDER BY attempt_number ASC;
    `;
    const res = await this.db.query<ExecutionAttemptRecord>(query, [executionId, workspaceId]);
    return res.rows;
  }

  async recordArtifact(input: CreateArtifactInput): Promise<ExecutionArtifactRecord> {
    return this.createArtifact(input);
  }

  async createArtifact(input: CreateArtifactInput): Promise<ExecutionArtifactRecord> {
    if (input.id !== undefined && !isValidUUID(input.id)) {
      throw new Error(`Invalid ArtifactId: ${String(input.id)}`);
    }
    if (!isValidUUID(input.execution_id) || !isValidUUID(input.workspace_id)) {
      throw new Error('Invalid ExecutionId or WorkspaceId for Artifact');
    }

    const query = input.id
      ? `INSERT INTO execution.execution_artifacts (
           id, execution_id, workspace_id, name, content_sha256,
           storage_uri, byte_size, mime_type
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *;`
      : `INSERT INTO execution.execution_artifacts (
           execution_id, workspace_id, name, content_sha256,
           storage_uri, byte_size, mime_type
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *;`;

    const params = input.id
      ? [
          input.id,
          input.execution_id,
          input.workspace_id,
          input.name,
          input.content_sha256,
          input.storage_uri,
          input.byte_size,
          input.mime_type || 'application/octet-stream',
        ]
      : [
          input.execution_id,
          input.workspace_id,
          input.name,
          input.content_sha256,
          input.storage_uri,
          input.byte_size,
          input.mime_type || 'application/octet-stream',
        ];

    const res = await this.db.query(query, params);
    const row = res.rows[0] as {
      id: string;
      execution_id: ExecutionId;
      workspace_id: WorkspaceId;
      name: string;
      content_sha256: string;
      storage_uri: string;
      byte_size: string | number;
      mime_type: string;
      created_at: string;
    };
    return {
      ...row,
      byte_size: Number(row.byte_size),
    };
  }

  async listArtifacts(
    executionId: ExecutionId | string,
    workspaceId: WorkspaceId | string
  ): Promise<ExecutionArtifactRecord[]> {
    if (!isValidUUID(executionId) || !isValidUUID(workspaceId)) return [];

    const query = `
      SELECT *
      FROM execution.execution_artifacts
      WHERE execution_id = $1 AND workspace_id = $2
      ORDER BY created_at ASC;
    `;
    const res = await this.db.query(query, [executionId, workspaceId]);
    return (res.rows as Array<{
      id: string;
      execution_id: ExecutionId;
      workspace_id: WorkspaceId;
      name: string;
      content_sha256: string;
      storage_uri: string;
      byte_size: string | number;
      mime_type: string;
      created_at: string;
    }>).map((r) => ({
      ...r,
      byte_size: Number(r.byte_size),
    }));
  }

  async acquireWorkerLease(
    workerId: string,
    executionId: ExecutionId | string,
    workspaceId: WorkspaceId | string,
    ttlMs: number
  ): Promise<boolean> {
    if (!isValidUUID(executionId) || !isValidUUID(workspaceId)) return false;

    const expiresAt = new Date(Date.now() + ttlMs).toISOString();
    const query = `
      INSERT INTO execution.worker_leases (
        worker_id, execution_id, workspace_id, status, heartbeat_at, lease_expires_at
      )
      VALUES ($1, $2, $3, 'BUSY', clock_timestamp(), $4)
      ON CONFLICT (worker_id) DO UPDATE
      SET execution_id = EXCLUDED.execution_id,
          workspace_id = EXCLUDED.workspace_id,
          status = 'BUSY',
          heartbeat_at = clock_timestamp(),
          lease_expires_at = EXCLUDED.lease_expires_at
      WHERE execution.worker_leases.status IN ('IDLE', 'TERMINATED')
         OR execution.worker_leases.lease_expires_at < clock_timestamp();
    `;
    const res = await this.db.query(query, [workerId, executionId, workspaceId, expiresAt]);
    return (res.rowCount ?? 0) > 0;
  }

  async renewWorkerLease(workerId: string, ttlMs: number): Promise<boolean> {
    const expiresAt = new Date(Date.now() + ttlMs).toISOString();
    const query = `
      UPDATE execution.worker_leases
      SET heartbeat_at = clock_timestamp(),
          lease_expires_at = $1
      WHERE worker_id = $2 AND status = 'BUSY';
    `;
    const res = await this.db.query(query, [expiresAt, workerId]);
    return (res.rowCount ?? 0) > 0;
  }

  async heartbeatWorker(workerId: string, ttlMs: number = 30_000): Promise<boolean> {
    return this.renewWorkerLease(workerId, ttlMs);
  }

  async releaseWorkerLease(workerId: string): Promise<void> {
    const query = `
      UPDATE execution.worker_leases
      SET status = 'IDLE',
          execution_id = NULL
      WHERE worker_id = $1;
    `;
    await this.db.query(query, [workerId]);
  }

  async reapExpiredLeases(now: Date = new Date()): Promise<number> {
    const query = `
      UPDATE execution.worker_leases
      SET status = 'TERMINATED'
      WHERE status = 'BUSY'
        AND lease_expires_at < $1;
    `;
    const res = await this.db.query(query, [now.toISOString()]);
    return res.rowCount ?? 0;
  }
}
