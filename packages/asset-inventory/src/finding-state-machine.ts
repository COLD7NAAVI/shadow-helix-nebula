/**
 * Shadow : Helix Nebula (SHN) — Finding Lifecycle State Machine
 *
 * Authoritative Spec: Phase 0.3 Section 2.8 (BC-FND), Phase 0.7 Section 4.3.5 (mod_finding_lifecycle)
 * Enforces formal state transitions:
 * Draft -> Under Review -> Confirmed -> Remediated / False Positive / Accepted Risk
 */

import { ok, err, type Result } from '@shn/shared-kernel';
import type { FindingStatus } from '@shn/data-access';

export const ALLOWED_FINDING_TRANSITIONS: Record<FindingStatus, readonly FindingStatus[]> = {
  DRAFT: ['UNDER_REVIEW'],
  UNDER_REVIEW: ['CONFIRMED', 'FALSE_POSITIVE', 'DRAFT'],
  CONFIRMED: ['REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'UNDER_REVIEW'],
  REMEDIATED: ['UNDER_REVIEW', 'CONFIRMED'],
  FALSE_POSITIVE: ['UNDER_REVIEW'],
  ACCEPTED_RISK: ['UNDER_REVIEW', 'CONFIRMED'],
};

export function isValidFindingStateTransition(
  fromStatus: FindingStatus,
  toStatus: FindingStatus
): boolean {
  if (fromStatus === toStatus) return true; // Idempotent same-state
  const allowed = ALLOWED_FINDING_TRANSITIONS[fromStatus];
  return allowed ? allowed.includes(toStatus) : false;
}

export function assertValidFindingStateTransition(
  fromStatus: FindingStatus,
  toStatus: FindingStatus
): Result<void, string> {
  if (!isValidFindingStateTransition(fromStatus, toStatus)) {
    return err(
      `Illegal finding status transition from "${fromStatus}" to "${toStatus}". Allowed targets: [${(
        ALLOWED_FINDING_TRANSITIONS[fromStatus] || []
      ).join(', ')}]`
    );
  }
  return ok(undefined);
}
