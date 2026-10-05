/**
 * Shadow : Helix Nebula (SHN) — Scope Composition & Downward Narrowing
 *
 * Enforces INV-06, API-INV-02, and SEC-INV-01:
 * - Downward-narrowing scope intersection
 * - Inclusions: Strict intersection
 * - Exclusions: Union
 * - Port ranges: Overlap intersection
 * - Actions: Allowed actions intersect, disallowed actions union
 * - Temporal window: max(valid_from) and min(valid_until)
 * - Cryptographic SHA-256 sealing of canonical representation
 */

import { createHash } from 'node:crypto';
import {
  ok,
  err,
  type Result,
  type IsoTimestamp,
  createScopeId,
  generateUUIDv7,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import type {
  ScopeDefinition,
  PortRange,
  ScopeInclusions,
  ScopeExclusions,
} from '../contracts.js';
import { makeScopeProblem } from '../errors.js';
import { isTargetContainedInCidr } from './cidr-evaluator.js';
import { isHostnameContainedInScope } from './hostname-evaluator.js';
import { isUrlContainedInScope } from './url-evaluator.js';

export function calculateCanonicalScopeSha256(scope: {
  readonly inclusions: ScopeInclusions;
  readonly exclusions: ScopeExclusions;
  readonly allowedActions: readonly string[];
  readonly disallowedActions?: readonly string[];
  readonly portRanges: readonly PortRange[];
  readonly validFrom: IsoTimestamp;
  readonly validUntil: IsoTimestamp;
}): string {
  // Sort and canonicalize all elements
  const canonicalInclusions = {
    cidrs: [...(scope.inclusions.cidrs || [])].sort(),
    hostnames: [...(scope.inclusions.hostnames || [])].sort(),
    urls: [...(scope.inclusions.urls || [])].sort(),
    resources: [...(scope.inclusions.resources || [])].sort(),
  };

  const canonicalExclusions = {
    cidrs: [...(scope.exclusions.cidrs || [])].sort(),
    hostnames: [...(scope.exclusions.hostnames || [])].sort(),
    urls: [...(scope.exclusions.urls || [])].sort(),
    resources: [...(scope.exclusions.resources || [])].sort(),
  };

  const canonicalAllowedActions = [...scope.allowedActions].sort();
  const canonicalDisallowedActions = [...(scope.disallowedActions || [])].sort();

  const canonicalPortRanges = [...scope.portRanges]
    .map((r) => ({ start: r.start, end: r.end }))
    .sort((a, b) => a.start - b.start || a.end - b.end);

  const payload = {
    allowedActions: canonicalAllowedActions,
    disallowedActions: canonicalDisallowedActions,
    exclusions: canonicalExclusions,
    inclusions: canonicalInclusions,
    portRanges: canonicalPortRanges,
    validFrom: scope.validFrom,
    validUntil: scope.validUntil,
  };

  const canonicalJson = JSON.stringify(payload);
  return createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
}

/**
 * Intersects two PortRange lists, producing only overlapping port intervals.
 */
export function intersectPortRanges(
  parentRanges: readonly PortRange[],
  childRanges: readonly PortRange[]
): PortRange[] {
  const result: PortRange[] = [];

  for (const p of parentRanges) {
    for (const c of childRanges) {
      const overlapStart = Math.max(p.start, c.start);
      const overlapEnd = Math.min(p.end, c.end);
      if (overlapStart <= overlapEnd) {
        result.push({ start: overlapStart, end: overlapEnd });
      }
    }
  }

  // Sort and merge overlapping/adjacent intervals
  if (result.length === 0) return [];
  result.sort((a, b) => a.start - b.start || a.end - b.end);

  const merged: PortRange[] = [result[0]!];
  for (let i = 1; i < result.length; i++) {
    const last = merged[merged.length - 1]!;
    const current = result[i]!;
    if (current.start <= last.end + 1) {
      merged[merged.length - 1] = {
        start: last.start,
        end: Math.max(last.end, current.end),
      };
    } else {
      merged.push(current);
    }
  }

  return merged;
}

/**
 * Intersects two ScopeDefinitions in accordance with downward-narrowing zero-trust rules.
 */
export function intersectScopes(
  parent: ScopeDefinition,
  child: ScopeDefinition
): Result<ScopeDefinition, ProblemDetails> {
  // Tenancy match check
  if (parent.organizationId !== child.organizationId) {
    return err(
      makeScopeProblem(
        ErrorCode.AUTH_CROSS_ORG_DENIED,
        `Cannot intersect scopes across different organizations: parent '${parent.organizationId}' vs child '${child.organizationId}'`
      )
    );
  }

  if (parent.workspaceId !== child.workspaceId) {
    return err(
      makeScopeProblem(
        ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
        `Cannot intersect scopes across different workspaces: parent '${parent.workspaceId}' vs child '${child.workspaceId}'`
      )
    );
  }

  // Time window intersection
  const pStart = new Date(parent.validFrom).getTime();
  const pEnd = new Date(parent.validUntil).getTime();
  const cStart = new Date(child.validFrom).getTime();
  const cEnd = new Date(child.validUntil).getTime();

  const intStart = Math.max(pStart, cStart);
  const intEnd = Math.min(pEnd, cEnd);

  if (intStart > intEnd) {
    return err(
      makeScopeProblem(
        ErrorCode.SCOPE_WINDOW_CLOSED,
        `Scope intersection yields empty temporal window: start (${new Date(intStart).toISOString()}) exceeds end (${new Date(intEnd).toISOString()})`
      )
    );
  }

  // Allowed actions intersection (child can only do what both allow)
  const parentAllowed = new Set(parent.allowedActions);
  const intersectedAllowed = child.allowedActions.filter((a) => parentAllowed.has(a));

  // Disallowed actions union (forbidden if either forbids)
  const combinedDisallowed = Array.from(
    new Set([...parent.disallowedActions, ...child.disallowedActions])
  );

  // Port ranges intersection
  const intersectedPorts = intersectPortRanges(parent.portRanges, child.portRanges);

  // Inclusions: child items must be contained in at least one parent inclusion
  const intersectedCidrs: string[] = [];
  for (const childCidr of child.inclusions.cidrs || []) {
    for (const parentCidr of parent.inclusions.cidrs || []) {
      if (isTargetContainedInCidr(childCidr, parentCidr)) {
        intersectedCidrs.push(childCidr);
        break;
      }
    }
  }

  const intersectedHostnames: string[] = [];
  for (const childHost of child.inclusions.hostnames || []) {
    for (const parentHost of parent.inclusions.hostnames || []) {
      if (isHostnameContainedInScope(childHost, parentHost)) {
        intersectedHostnames.push(childHost);
        break;
      }
    }
  }

  const intersectedUrls: string[] = [];
  for (const childUrl of child.inclusions.urls || []) {
    for (const parentUrl of parent.inclusions.urls || []) {
      if (isUrlContainedInScope(childUrl, parentUrl)) {
        intersectedUrls.push(childUrl);
        break;
      }
    }
  }

  const parentResources = new Set(parent.inclusions.resources || []);
  const intersectedResources = (child.inclusions.resources || []).filter((r) =>
    parentResources.has(r)
  );

  // Exclusions: Union of parent and child exclusions
  const combinedExclusions: ScopeExclusions = {
    cidrs: Array.from(new Set([...(parent.exclusions.cidrs || []), ...(child.exclusions.cidrs || [])])),
    hostnames: Array.from(new Set([...(parent.exclusions.hostnames || []), ...(child.exclusions.hostnames || [])])),
    urls: Array.from(new Set([...(parent.exclusions.urls || []), ...(child.exclusions.urls || [])])),
    resources: Array.from(new Set([...(parent.exclusions.resources || []), ...(child.exclusions.resources || [])])),
  };

  const inclusions: ScopeInclusions = {
    cidrs: Array.from(new Set(intersectedCidrs)),
    hostnames: Array.from(new Set(intersectedHostnames)),
    urls: Array.from(new Set(intersectedUrls)),
    resources: Array.from(new Set(intersectedResources)),
  };

  const validFrom = new Date(intStart).toISOString() as IsoTimestamp;
  const validUntil = new Date(intEnd).toISOString() as IsoTimestamp;

  const scopeSha256 = calculateCanonicalScopeSha256({
    inclusions,
    exclusions: combinedExclusions,
    allowedActions: intersectedAllowed,
    disallowedActions: combinedDisallowed,
    portRanges: intersectedPorts,
    validFrom,
    validUntil,
  });

  const scopeIdRes = createScopeId(generateUUIDv7());
  if (scopeIdRes.isErr) {
    return err(makeScopeProblem(ErrorCode.INTERNAL_FAULT, scopeIdRes.error));
  }

  const resultScope: ScopeDefinition = {
    id: scopeIdRes.value,
    workspaceId: parent.workspaceId,
    organizationId: parent.organizationId,
    name: `${child.name} [Narrowed]`,
    description: `Intersected from parent '${parent.name}' and child '${child.name}'`,
    inclusions,
    exclusions: combinedExclusions,
    allowedActions: intersectedAllowed,
    disallowedActions: combinedDisallowed,
    portRanges: intersectedPorts,
    validFrom,
    validUntil,
    scopeSha256,
    status: 'active',
    version: 1,
  };

  return ok(resultScope);
}
