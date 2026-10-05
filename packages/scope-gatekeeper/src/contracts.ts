/**
 * Shadow : Helix Nebula (SHN) — Tenancy & Scope Gatekeeper Contracts
 *
 * Authoritative Spec: Phase 0.1 Section 18 ("Scope as a Security Boundary"),
 *                    Phase 0.3 Context 3 (BC-SCP),
 *                    Phase 0.4 Invariants (INV-01, INV-06, INV-09, INV-11, INV-19, SEC-INV-01, SEC-INV-08),
 *                    Phase 0.7 Section 4.1.1 (mod_scope_gatekeeper),
 *                    Phase 0.10 Section 4.2 (SCOPE_BOUNDARY),
 *                    Phase 0.14 Section 20 (ScopeEnvelope, API-INV-02).
 */

import type {
  ScopeId,
  WorkspaceId,
  OrganizationId,
  UserId,
  SecurityContextToken,
  Result,
  IsoTimestamp,
} from '@shn/shared-kernel';
import type { ProblemDetails } from '@shn/error-catalog';

export type ScopeTargetType = 'ipv4' | 'ipv6' | 'cidr4' | 'cidr6' | 'hostname' | 'url' | 'resource';

export interface PortRange {
  readonly start: number;
  readonly end: number;
}

export interface ScopeInclusions {
  readonly cidrs?: readonly string[] | undefined;
  readonly hostnames?: readonly string[] | undefined;
  readonly urls?: readonly string[] | undefined;
  readonly resources?: readonly string[] | undefined;
}

export interface ScopeExclusions {
  readonly cidrs?: readonly string[] | undefined;
  readonly hostnames?: readonly string[] | undefined;
  readonly urls?: readonly string[] | undefined;
  readonly resources?: readonly string[] | undefined;
}

export type ScopeStatus = 'active' | 'revoked' | 'expired';

export interface ScopeDefinition {
  readonly id: ScopeId;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly name: string;
  readonly description?: string | undefined;
  readonly inclusions: ScopeInclusions;
  readonly exclusions: ScopeExclusions;
  readonly allowedActions: readonly string[];
  readonly disallowedActions: readonly string[];
  readonly portRanges: readonly PortRange[];
  readonly validFrom: IsoTimestamp;
  readonly validUntil: IsoTimestamp;
  readonly rateLimits?: Record<string, number> | undefined;
  readonly scopeSha256: string;
  readonly status: ScopeStatus;
  readonly version: number;
}

export type ScopeToken = string & { readonly __brand: 'ScopeToken' };

export interface ScopeTokenClaims {
  readonly scope_id: ScopeId;
  readonly organization_id: OrganizationId;
  readonly workspace_id: WorkspaceId;
  readonly actor_id: UserId;
  readonly inclusions: ScopeInclusions;
  readonly exclusions: ScopeExclusions;
  readonly allowed_actions: readonly string[];
  readonly disallowed_actions?: readonly string[] | undefined;
  readonly port_ranges: readonly PortRange[];
  readonly valid_from: IsoTimestamp;
  readonly valid_until: IsoTimestamp;
  readonly scope_sha256: string;
  readonly version: number;
  readonly nonce: string;
  readonly issued_at: IsoTimestamp;
}

export interface NormalizedTarget {
  readonly original: string;
  readonly type: ScopeTargetType;
  readonly canonical: string;
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly scheme?: string | undefined;
  readonly path?: string | undefined;
}

export interface TargetVerdict {
  readonly allowed: boolean;
  readonly reason: string;
  readonly errorCode?: string | undefined;
  readonly matchedInclusion?: string | undefined;
  readonly matchedExclusion?: string | undefined;
  readonly normalizedTarget?: NormalizedTarget | undefined;
  readonly scopeId?: ScopeId | undefined;
  readonly evaluatedAt: IsoTimestamp;
}

export interface EvaluateTargetParams {
  readonly context: SecurityContextToken;
  readonly target: string;
  readonly action: string;
  readonly port?: number | undefined;
  readonly scopeId?: ScopeId | undefined;
  readonly scopeToken?: ScopeToken | string | undefined;
  readonly scopeOverride?: ScopeDefinition | undefined;
  readonly allowMetadata?: boolean | undefined;
}

export interface MintScopeTokenParams {
  readonly scope: ScopeDefinition;
  readonly actorId: UserId;
  readonly ttlSeconds?: number | undefined;
}

export interface IScopeGatekeeper {
  evaluateTarget(params: EvaluateTargetParams): Promise<Result<TargetVerdict, ProblemDetails>>;
  mintScopeToken(params: MintScopeTokenParams): Result<ScopeToken, ProblemDetails>;
  verifyScopeToken(token: ScopeToken | string): Result<ScopeTokenClaims, ProblemDetails>;
  canonicalizeTarget(rawTarget: string, defaultPort?: number): Result<NormalizedTarget, ProblemDetails>;
  calculateScopeSha256(scope: Omit<ScopeDefinition, 'id' | 'scopeSha256' | 'status' | 'version'>): string;
  intersectScopes(parent: ScopeDefinition, child: ScopeDefinition): Result<ScopeDefinition, ProblemDetails>;
}
