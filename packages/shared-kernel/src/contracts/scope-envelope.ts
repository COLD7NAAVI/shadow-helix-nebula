/**
 * Shadow : Helix Nebula (SHN) — Scope Envelope Contract
 *
 * Enforces API-INV-02 & INV-06: Immutable target scope propagation.
 */

import type { CidrBlock, Hostname, IPv4Address, PortRange } from '../primitives/network.js';
import type { IsoTimestamp } from '../primitives/timestamps.js';
import type { WorkspaceId } from '../primitives/identifiers.js';

export interface ScopeEnvelope {
  /** Unique scope boundary ID (UUID) */
  readonly scope_id: string;
  /** Bounded tenant workspace ID */
  readonly workspace_id: WorkspaceId;
  /** Explicit authorized target CIDRs / IPs */
  readonly target_inclusions: readonly (CidrBlock | IPv4Address | Hostname)[];
  /** Explicit excluded target CIDRs / IPs */
  readonly target_exclusions: readonly (CidrBlock | IPv4Address | Hostname)[];
  /** Authorized TCP/UDP port boundaries */
  readonly port_ranges: readonly PortRange[];
  /** Operational execution window start */
  readonly valid_from: IsoTimestamp;
  /** Operational execution window end */
  readonly valid_until: IsoTimestamp;
  /** Cryptographic SHA-256 hash sealing this exact scope representation */
  readonly scope_sha256: string;
}

export function isScopeWindowActive(scope: ScopeEnvelope, now = Date.now()): boolean {
  const start = new Date(scope.valid_from).getTime();
  const end = new Date(scope.valid_until).getTime();
  return now >= start && now <= end;
}
