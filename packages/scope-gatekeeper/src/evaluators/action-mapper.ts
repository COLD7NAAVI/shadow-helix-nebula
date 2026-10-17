/**
 * Shadow : Helix Nebula (SHN) — Canonical Action Mapping & Scope Evaluator
 *
 * Provides authoritative mapping between capability-level operational actions
 * (e.g. 'http:probe', 'network:scan'), canonical scope boundary categories
 * (e.g. 'PROBING_ACTIVE', 'PORT_SCAN'), and cryptographic RBAC PermissionBits.
 *
 * Enforces Phase 0.4 Invariants (INV-01, INV-06, SEC-INV-01, SEC-INV-05).
 */

import { PermissionBit } from '@shn/auth-rbac';

export const CanonicalScopeAction = {
  RECON_PASSIVE: 'RECON_PASSIVE',
  PROBING_ACTIVE: 'PROBING_ACTIVE',
  PORT_SCAN: 'PORT_SCAN',
  SCAN_INVASIVE: 'SCAN_INVASIVE',
  WORKFLOW_EXECUTE: 'WORKFLOW_EXECUTE',
  SCOPE_ADMIN: 'SCOPE_ADMIN',
  SCOPE_READ: 'SCOPE_READ',
} as const;

export type CanonicalScopeActionType = (typeof CanonicalScopeAction)[keyof typeof CanonicalScopeAction];

/**
 * Normalized action equivalence groups.
 * Any action belonging to an equivalence group matches the corresponding
 * canonical scope policy category and its synonyms.
 */
const ACTION_EQUIVALENCE_GROUPS: ReadonlyArray<ReadonlySet<string>> = [
  // Active probing: HTTP service discovery, web probes, banner grabs
  new Set([
    'probing_active',
    'probing',
    'probe',
    'http:probe',
    'http_probe',
    'http-probe',
    'web:probe',
    'http:discovery',
    'http_get',
  ]),

  // Port scanning & network probe scanning
  new Set([
    'port_scan',
    'port-scan',
    'port:scan',
    'scan_tcp_port',
    'scan_invasive',
    'scan',
    'network:scan',
    'network_scan',
  ]),

  // Passive reconnaissance
  new Set([
    'recon_passive',
    'recon:passive',
    'passive',
    'recon',
  ]),

  // Workflow / supervised execution
  new Set([
    'workflow_execute',
    'workflow:execute',
    'execute',
  ]),

  // Scope administration
  new Set([
    'scope_admin',
    'create_scope',
    'update_scope',
    'admin',
  ]),

  // Scope read
  new Set([
    'scope_read',
    'view_scope',
    'read',
  ]),
];

/**
 * Normalizes an action string for deterministic, case-insensitive comparison.
 */
export function normalizeAction(action: string): string {
  return String(action ?? '').trim().toLowerCase();
}

/**
 * Evaluates whether two action representations match, either via exact
 * string equality or by belonging to the same canonical equivalence group.
 */
export function actionsMatch(actionA: string, actionB: string): boolean {
  const normA = normalizeAction(actionA);
  const normB = normalizeAction(actionB);
  if (!normA || !normB) return false;
  if (normA === normB) return true;

  for (const group of ACTION_EQUIVALENCE_GROUPS) {
    if (group.has(normA) && group.has(normB)) {
      return true;
    }
  }
  return false;
}

/**
 * Evaluates whether a requested capability action is authorized by a scope's
 * allowedActions declaration.
 *
 * Fail-closed: If allowedActions is non-empty, the action must match at least one
 * declared allowed action.
 */
export function isActionAllowedByScope(
  requestedAction: string,
  allowedActions: readonly string[]
): boolean {
  if (!allowedActions || allowedActions.length === 0) {
    return true;
  }
  return allowedActions.some((allowed) => actionsMatch(requestedAction, allowed));
}

/**
 * Evaluates whether a requested capability action is explicitly forbidden by a
 * scope's disallowedActions declaration.
 *
 * Fail-closed: If any disallowed action matches the requested action, evaluation
 * fails immediately.
 */
export function isActionDisallowedByScope(
  requestedAction: string,
  disallowedActions?: readonly string[] | undefined
): boolean {
  if (!disallowedActions || disallowedActions.length === 0) {
    return false;
  }
  return disallowedActions.some((disallowed) => actionsMatch(requestedAction, disallowed));
}

/**
 * Maps any recognized action string to its required RBAC PermissionBit mask.
 */
export function mapActionToPermissionBit(action: string): number | undefined {
  const normalized = normalizeAction(action);
  switch (normalized) {
    case 'read':
    case 'view_scope':
    case 'scope_read':
      return PermissionBit.SCOPE_READ;

    case 'admin':
    case 'create_scope':
    case 'update_scope':
    case 'scope_admin':
      return PermissionBit.SCOPE_ADMIN;

    case 'execute':
    case 'workflow_execute':
    case 'workflow:execute':
      return PermissionBit.WORKFLOW_EXECUTE;

    case 'recon_passive':
    case 'recon:passive':
    case 'passive':
    case 'recon':
      return PermissionBit.RECON_PASSIVE;

    case 'probing_active':
    case 'probing':
    case 'probe':
    case 'http:probe':
    case 'http_probe':
    case 'http-probe':
    case 'web:probe':
    case 'http:discovery':
    case 'http_get':
      return PermissionBit.PROBING_ACTIVE;

    case 'scan_invasive':
    case 'scan':
    case 'network:scan':
    case 'network_scan':
    case 'port_scan':
    case 'port:scan':
    case 'port-scan':
    case 'scan_tcp_port':
      return PermissionBit.SCAN_INVASIVE;

    default:
      return undefined;
  }
}
