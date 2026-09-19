/**
 * Shadow : Helix Nebula (SHN) — Security Context Token DTO
 *
 * Enforces API-INV-01 & SEC-INV-01: Stateless cryptographic authorization context propagation.
 */

import type { WorkspaceId } from '../primitives/identifiers.js';
import type { IsoTimestamp } from '../primitives/timestamps.js';

export interface SecurityContextToken {
  /** Unique operator subject ID (UUID) */
  readonly subject_id: string;
  /** Subject type: OPERATOR, SYSTEM, WORKER, AUTOMATION */
  readonly subject_type: 'OPERATOR' | 'SYSTEM' | 'WORKER' | 'AUTOMATION';
  /** Bounded tenant workspace ID */
  readonly workspace_id: WorkspaceId;
  /** Granted RBAC roles within this workspace */
  readonly roles: readonly string[];
  /** Numeric permission bitmask for microsecond-fast evaluation */
  readonly permission_mask: number;
  /** UTC ISO 8601 issuance timestamp */
  readonly issued_at: IsoTimestamp;
  /** UTC ISO 8601 expiration timestamp (Max 15 minutes) */
  readonly expires_at: IsoTimestamp;
  /** Cryptographic HMAC signature over context claims */
  readonly signature: string;
}

export function isSecurityContextExpired(token: SecurityContextToken, now = Date.now()): boolean {
  return new Date(token.expires_at).getTime() <= now;
}
