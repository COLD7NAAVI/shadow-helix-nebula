/**
 * Shadow : Helix Nebula (SHN) — Nominal Entity Identifiers
 *
 * Enforces strong compile-time type boundaries across domain IDs.
 */

import { randomUUID } from 'node:crypto';
import { ok, err, type Result } from '../result/result.js';

declare const brand: unique symbol;
export type Brand<T, B extends string> = T & { readonly [brand]: B };

export type OrganizationId = Brand<string, 'OrganizationId'>;
export type WorkspaceId = Brand<string, 'WorkspaceId'>;
export type EngagementId = Brand<string, 'EngagementId'>;
export type AssetId = Brand<string, 'AssetId'>;
export type FindingId = Brand<string, 'FindingId'>;
export type TaskId = Brand<string, 'TaskId'>;
export type RunId = Brand<string, 'RunId'>;
export type EventId = Brand<string, 'EventId'>;
export type CorrelationId = Brand<string, 'CorrelationId'>;
export type CausationId = Brand<string, 'CausationId'>;
export type TraceId = Brand<string, 'TraceId'>;
export type UserId = Brand<string, 'UserId'>;
export type RoleId = Brand<string, 'RoleId'>;
export type PermissionId = Brand<string, 'PermissionId'>;
export type SecretId = Brand<string, 'SecretId'>;
export type SessionId = Brand<string, 'SessionId'>;
export type SecretVersionId = Brand<string, 'SecretVersionId'>;
export type ScopeId = Brand<string, 'ScopeId'>;
export type ExecutionId = Brand<string, 'ExecutionId'>;
export type WorkerId = Brand<string, 'WorkerId'>;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidUUID(id: string): boolean {
  return UUID_REGEX.test(id);
}

export function parseUUID<T extends string>(id: string, entityName: string): Result<T, string> {
  if (!isValidUUID(id)) {
    return err(`Invalid ${entityName}: must be a valid UUID format (received '${id}')`);
  }
  return ok(id as T);
}

/**
 * Generates a standard UUIDv4.
 */
export function generateUUIDv4(): string {
  return randomUUID();
}

/**
 * Generates a time-ordered UUIDv7 matching Phase 0.14 Canonical Envelope specs.
 */
export function generateUUIDv7(): string {
  const now = Date.now();
  const timeHex = now.toString(16).padStart(12, '0');
  const randHex = randomUUID().replace(/-/g, '').slice(12);

  // Layout: 48 bits time, 4 bits version (7), 12 bits rand, 2 bits variant (10xx), 62 bits rand
  const part1 = timeHex.slice(0, 8);
  const part2 = timeHex.slice(8, 12);
  const part3 = '7' + randHex.slice(0, 3);
  const variant = ((parseInt(randHex.slice(3, 4), 16) & 0x3) | 0x8).toString(16);
  const part4 = variant + randHex.slice(4, 7);
  const part5 = randHex.slice(7, 19);

  return `${part1}-${part2}-${part3}-${part4}-${part5}`;
}

export function createWorkspaceId(id?: string): Result<WorkspaceId, string> {
  return parseUUID<WorkspaceId>(id ?? generateUUIDv4(), 'WorkspaceId');
}

export function createOrganizationId(id?: string): Result<OrganizationId, string> {
  return parseUUID<OrganizationId>(id ?? generateUUIDv4(), 'OrganizationId');
}

export function createEngagementId(id?: string): Result<EngagementId, string> {
  return parseUUID<EngagementId>(id ?? generateUUIDv4(), 'EngagementId');
}

export function createFindingId(id?: string): Result<FindingId, string> {
  return parseUUID<FindingId>(id ?? generateUUIDv4(), 'FindingId');
}

export function createTaskId(id?: string): Result<TaskId, string> {
  return parseUUID<TaskId>(id ?? generateUUIDv4(), 'TaskId');
}

export function createRunId(id?: string): Result<RunId, string> {
  return parseUUID<RunId>(id ?? generateUUIDv4(), 'RunId');
}

export function createEventId(id?: string): Result<EventId, string> {
  return parseUUID<EventId>(id ?? generateUUIDv7(), 'EventId');
}

export function createCorrelationId(id?: string): Result<CorrelationId, string> {
  return parseUUID<CorrelationId>(id ?? generateUUIDv4(), 'CorrelationId');
}

export function createCausationId(id?: string): Result<CausationId, string> {
  return parseUUID<CausationId>(id ?? generateUUIDv4(), 'CausationId');
}

export function createUserId(id?: string): Result<UserId, string> {
  return parseUUID<UserId>(id ?? generateUUIDv4(), 'UserId');
}

export function createRoleId(id?: string): Result<RoleId, string> {
  return parseUUID<RoleId>(id ?? generateUUIDv4(), 'RoleId');
}

export function createPermissionId(id?: string): Result<PermissionId, string> {
  return parseUUID<PermissionId>(id ?? generateUUIDv4(), 'PermissionId');
}

export function createSecretId(id?: string): Result<SecretId, string> {
  return parseUUID<SecretId>(id ?? generateUUIDv4(), 'SecretId');
}

export function createSessionId(id?: string): Result<SessionId, string> {
  return parseUUID<SessionId>(id ?? generateUUIDv4(), 'SessionId');
}

export function createSecretVersionId(id?: string): Result<SecretVersionId, string> {
  return parseUUID<SecretVersionId>(id ?? generateUUIDv4(), 'SecretVersionId');
}

export function createScopeId(id?: string): Result<ScopeId, string> {
  return parseUUID<ScopeId>(id ?? generateUUIDv7(), 'ScopeId');
}

export function createExecutionId(id?: string): Result<ExecutionId, string> {
  return parseUUID<ExecutionId>(id ?? generateUUIDv7(), 'ExecutionId');
}

export function createWorkerId(id?: string): Result<WorkerId, string> {
  return parseUUID<WorkerId>(id ?? generateUUIDv4(), 'WorkerId');
}
