/**
 * Shadow : Helix Nebula (SHN) — Canonical Tenancy & Zero-Trust Scope Gatekeeper
 *
 * Implements Phase 0.7 Section 4.1.1: mod_scope_gatekeeper
 * Enforces SEC-INV-01, SEC-INV-08, SEC-INV-05, INV-01, INV-06, INV-09, INV-11, INV-19, API-INV-02.
 */

import {
  type ScopeId,
  type WorkspaceId,
  type OrganizationId,
  type IsoTimestamp,
  ok,
  err,
  type Result,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import type {
  ScopeRepository,
  WorkspaceRepository,
  OrganizationRepository,
  ScopeRecord,
} from '@shn/data-access';
import type { IEventPublisher } from '@shn/event-bus';
import type { ILogger, ITracer } from '@shn/telemetry';
import { PermissionBit } from '@shn/auth-rbac';

import type {
  IScopeGatekeeper,
  ScopeDefinition,
  ScopeToken,
  ScopeTokenClaims,
  TargetVerdict,
  EvaluateTargetParams,
  MintScopeTokenParams,
  NormalizedTarget,
  PortRange,
  ScopeInclusions,
} from '../contracts.js';
import { makeScopeProblem } from '../errors.js';
import {
  isBlacklistedIpOrCidr,
  isTargetContainedInCidr,
  parseIPv4Address,
  parseIPv6Address,
  parseCidrBlock,
} from '../evaluators/cidr-evaluator.js';
import {
  canonicalizeHostname,
  isHostnameContainedInScope,
  isBlacklistedHostname,
} from '../evaluators/hostname-evaluator.js';
import {
  parseAndNormalizeUrl,
  isUrlContainedInScope,
} from '../evaluators/url-evaluator.js';
import {
  calculateCanonicalScopeSha256,
  intersectScopes,
} from '../evaluators/scope-composition.js';
import { ScopeTokenSigner } from '../tokens/scope-token-signer.js';
import { TenancyValidator } from '../tenancy/tenancy-validator.js';

export interface ScopeGatekeeperOptions {
  readonly scopeRepo?: ScopeRepository | undefined;
  readonly workspaceRepo?: WorkspaceRepository | undefined;
  readonly orgRepo?: OrganizationRepository | undefined;
  readonly tokenSigner?: ScopeTokenSigner | undefined;
  readonly tenancyValidator?: TenancyValidator | undefined;
  readonly eventPublisher?: IEventPublisher | undefined;
  readonly logger?: ILogger | undefined;
  readonly tracer?: ITracer | undefined;
}

function normalizeBoundaries(b: unknown): ScopeInclusions {
  if (!b) return {};
  if (Array.isArray(b)) {
    const cidrs: string[] = [];
    const hostnames: string[] = [];
    const urls: string[] = [];
    const resources: string[] = [];

    for (const item of b) {
      if (typeof item !== 'string') continue;
      const s = item.trim();
      if (s.startsWith('http://') || s.startsWith('https://')) {
        urls.push(s);
      } else if (s.includes('/') || /^\d+\.\d+\.\d+\.\d+$/.test(s) || s.includes(':')) {
        cidrs.push(s);
      } else if (s.includes('.') || s.startsWith('*.')) {
        hostnames.push(s);
      } else {
        resources.push(s);
      }
    }
    return {
      cidrs: cidrs.length > 0 ? cidrs : undefined,
      hostnames: hostnames.length > 0 ? hostnames : undefined,
      urls: urls.length > 0 ? urls : undefined,
      resources: resources.length > 0 ? resources : undefined,
    };
  }
  if (typeof b === 'object') {
    const obj = b as Record<string, unknown>;
    return {
      cidrs: Array.isArray(obj['cidrs']) ? (obj['cidrs'] as string[]) : undefined,
      hostnames: Array.isArray(obj['hostnames']) ? (obj['hostnames'] as string[]) : undefined,
      urls: Array.isArray(obj['urls']) ? (obj['urls'] as string[]) : undefined,
      resources: Array.isArray(obj['resources']) ? (obj['resources'] as string[]) : undefined,
    };
  }
  return {};
}

export class ScopeGatekeeper implements IScopeGatekeeper {
  private readonly scopeRepo?: ScopeRepository | undefined;
  private readonly workspaceRepo?: WorkspaceRepository | undefined;
  private readonly tokenSigner: ScopeTokenSigner;
  private readonly tenancyValidator: TenancyValidator;
  private readonly eventPublisher?: IEventPublisher | undefined;
  private readonly logger?: ILogger | undefined;
  private readonly tracer?: ITracer | undefined;

  constructor(options: ScopeGatekeeperOptions = {}) {
    this.scopeRepo = options.scopeRepo;
    this.workspaceRepo = options.workspaceRepo;
    this.tokenSigner =
      options.tokenSigner ??
      new ScopeTokenSigner(process.env.SHN_SCOPE_SIGNING_KEY || 'default-insecure-shn-scope-secret-key-32b');
    this.tenancyValidator =
      options.tenancyValidator ??
      new TenancyValidator(options.workspaceRepo, options.orgRepo);
    this.eventPublisher = options.eventPublisher;
    this.logger = options.logger;
    this.tracer = options.tracer;
  }

  getTenancyValidator(): TenancyValidator {
    return this.tenancyValidator;
  }

  getTokenSigner(): ScopeTokenSigner {
    return this.tokenSigner;
  }

  getEventPublisher(): IEventPublisher | undefined {
    return this.eventPublisher;
  }

  getLogger(): ILogger | undefined {
    return this.logger;
  }

  getTracer(): ITracer | undefined {
    return this.tracer;
  }

  canonicalizeTarget(rawTarget: string, defaultPort?: number): Result<NormalizedTarget, ProblemDetails> {
    const trimmed = rawTarget.trim();
    if (!trimmed) {
      return err(
        makeScopeProblem(ErrorCode.SCOPE_MALFORMED, 'Target string cannot be empty')
      );
    }

    // 1. URL target
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      const urlRes = parseAndNormalizeUrl(trimmed);
      if (urlRes.isErr) {
        const isBlacklist = urlRes.error.toLowerCase().includes('blacklisted');
        return err(
          makeScopeProblem(
            isBlacklist ? ErrorCode.SCOPE_METADATA_PROHIBITED : ErrorCode.SCOPE_MALFORMED,
            urlRes.error
          )
        );
      }
      return ok({
        original: trimmed,
        type: 'url',
        canonical: urlRes.value.canonical,
        host: urlRes.value.host,
        port: urlRes.value.port,
        scheme: urlRes.value.scheme,
        path: urlRes.value.path,
      });
    }

    // 2. CIDR target
    if (trimmed.includes('/')) {
      const cidrRes = parseCidrBlock(trimmed);
      if (cidrRes.isErr) {
        return err(makeScopeProblem(ErrorCode.SCOPE_MALFORMED, cidrRes.error));
      }
      return ok({
        original: trimmed,
        type: cidrRes.value.version === 4 ? 'cidr4' : 'cidr6',
        canonical: cidrRes.value.canonical,
        port: defaultPort,
      });
    }

    // 3. IPv4 host
    if (trimmed.includes('.') && /^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) {
      const ipRes = parseIPv4Address(trimmed);
      if (ipRes.isErr) {
        return err(makeScopeProblem(ErrorCode.SCOPE_MALFORMED, ipRes.error));
      }
      return ok({
        original: trimmed,
        type: 'ipv4',
        canonical: trimmed,
        host: trimmed,
        port: defaultPort,
      });
    }

    // 4. IPv6 host
    if (trimmed.includes(':')) {
      const ip6Res = parseIPv6Address(trimmed);
      if (ip6Res.isErr) {
        return err(makeScopeProblem(ErrorCode.SCOPE_MALFORMED, ip6Res.error));
      }
      return ok({
        original: trimmed,
        type: 'ipv6',
        canonical: trimmed,
        host: trimmed,
        port: defaultPort,
      });
    }

    // 5. Hostname
    const hostRes = canonicalizeHostname(trimmed);
    if (hostRes.isErr) {
      const isBlacklist = hostRes.error.toLowerCase().includes('blacklisted');
      return err(
        makeScopeProblem(
          isBlacklist ? ErrorCode.SCOPE_METADATA_PROHIBITED : ErrorCode.SCOPE_MALFORMED,
          hostRes.error
        )
      );
    }
    return ok({
      original: trimmed,
      type: 'hostname',
      canonical: hostRes.value,
      host: hostRes.value,
      port: defaultPort,
    });
  }

  mintScopeToken(params: MintScopeTokenParams): Result<ScopeToken, ProblemDetails> {
    return this.tokenSigner.mintScopeToken(params);
  }

  verifyScopeToken(token: ScopeToken | string): Result<ScopeTokenClaims, ProblemDetails> {
    return this.tokenSigner.verifyScopeToken(token);
  }

  calculateScopeSha256(
    scope: Omit<ScopeDefinition, 'id' | 'scopeSha256' | 'status' | 'version'>
  ): string {
    return calculateCanonicalScopeSha256(scope);
  }

  intersectScopes(
    parent: ScopeDefinition,
    child: ScopeDefinition
  ): Result<ScopeDefinition, ProblemDetails> {
    return intersectScopes(parent, child);
  }

  /**
   * Evaluates if target is authorized under security context, tenancy, capability, and scope.
   */
  async evaluateTarget(params: EvaluateTargetParams): Promise<Result<TargetVerdict, ProblemDetails>> {
    const now = Date.now();
    const evaluatedAt = new Date(now).toISOString() as IsoTimestamp;

    const { context, target, action, port, scopeId, scopeToken, scopeOverride, allowMetadata } =
      params;

    // 1. Tenancy validation on SecurityContext
    if (!context || typeof context !== 'object') {
      return ok({
        allowed: false,
        reason: 'Security context is missing or null',
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        evaluatedAt,
      });
    }

    // Context must have valid workspace_id
    if (!context.workspace_id) {
      return ok({
        allowed: false,
        reason: 'Security context workspace_id is missing',
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        evaluatedAt,
      });
    }

    // 2. Action RBAC Permission validation
    const permBit = this.mapActionToPermission(action);
    if (permBit !== undefined) {
      if ((context.permission_mask & permBit) !== permBit) {
        return ok({
          allowed: false,
          reason: `Actor lacks required permission bit for action '${action}'`,
          errorCode: ErrorCode.AUTH_FORBIDDEN,
          evaluatedAt,
        });
      }
    }

    // 3. Resolve Scope Boundaries
    let activeScope: {
      inclusions: ScopeDefinition['inclusions'];
      exclusions: ScopeDefinition['exclusions'];
      allowedActions: readonly string[];
      disallowedActions?: readonly string[] | undefined;
      portRanges: readonly PortRange[];
      validFrom: string;
      validUntil: string;
      scopeId?: ScopeId | undefined;
      workspaceId: WorkspaceId;
      organizationId: OrganizationId;
    };

    if (scopeOverride) {
      // Validate tenancy match
      if (scopeOverride.workspaceId !== context.workspace_id) {
        return ok({
          allowed: false,
          reason: `Scope override workspace '${scopeOverride.workspaceId}' does not match context workspace '${context.workspace_id}'`,
          errorCode: ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          evaluatedAt,
        });
      }
      activeScope = {
        inclusions: normalizeBoundaries(scopeOverride.inclusions),
        exclusions: normalizeBoundaries(scopeOverride.exclusions),
        allowedActions: scopeOverride.allowedActions,
        disallowedActions: scopeOverride.disallowedActions,
        portRanges: scopeOverride.portRanges,
        validFrom: scopeOverride.validFrom,
        validUntil: scopeOverride.validUntil,
        scopeId: scopeOverride.id,
        workspaceId: scopeOverride.workspaceId,
        organizationId: scopeOverride.organizationId,
      };
    } else if (scopeToken) {
      const verifyRes = this.tokenSigner.verifyScopeToken(scopeToken, now);
      if (verifyRes.isErr) {
        return ok({
          allowed: false,
          reason: `Scope token verification failed: ${verifyRes.error.detail}`,
          errorCode: verifyRes.error.error_code,
          evaluatedAt,
        });
      }
      const claims = verifyRes.value;

      // Cross-tenant token defense
      if (claims.workspace_id !== context.workspace_id) {
        return ok({
          allowed: false,
          reason: `Scope token workspace '${claims.workspace_id}' does not match context workspace '${context.workspace_id}'`,
          errorCode: ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          evaluatedAt,
        });
      }
      if (claims.actor_id !== context.subject_id) {
        return ok({
          allowed: false,
          reason: `Scope token actor '${claims.actor_id}' does not match context subject '${context.subject_id}'`,
          errorCode: ErrorCode.AUTH_FORBIDDEN,
          evaluatedAt,
        });
      }

      // If workspaceRepo is wired, verify organization matches workspace's actual organization
      if (this.workspaceRepo) {
        const ws = await this.workspaceRepo.findById(context.workspace_id);
        if (!ws) {
          return ok({
            allowed: false,
            reason: `Workspace '${context.workspace_id}' not found in persistence`,
            errorCode: ErrorCode.STORAGE_NOT_FOUND,
            evaluatedAt,
          });
        }
        if (ws.organization_id !== claims.organization_id) {
          return ok({
            allowed: false,
            reason: `Scope token organization '${claims.organization_id}' does not match workspace organization '${ws.organization_id}'`,
            errorCode: ErrorCode.AUTH_CROSS_ORG_DENIED,
            evaluatedAt,
          });
        }
      }

      activeScope = {
        inclusions: normalizeBoundaries(claims.inclusions),
        exclusions: normalizeBoundaries(claims.exclusions),
        allowedActions: claims.allowed_actions,
        disallowedActions: claims.disallowed_actions,
        portRanges: claims.port_ranges,
        validFrom: claims.valid_from,
        validUntil: claims.valid_until,
        scopeId: claims.scope_id,
        workspaceId: claims.workspace_id,
        organizationId: claims.organization_id,
      };
    } else if (scopeId) {
      if (!this.scopeRepo) {
        return err(
          makeScopeProblem(
            ErrorCode.INTERNAL_FAULT,
            'ScopeRepository is required when evaluating by scopeId'
          )
        );
      }
      // Scoped query: must query by (scopeId, workspace_id)
      const scopeRecord = await this.scopeRepo.findById(scopeId, context.workspace_id);
      if (!scopeRecord) {
        return ok({
          allowed: false,
          reason: `Scope '${scopeId}' not found in workspace '${context.workspace_id}'`,
          errorCode: ErrorCode.STORAGE_NOT_FOUND,
          evaluatedAt,
        });
      }
      if (scopeRecord.status !== 'ACTIVE') {
        return ok({
          allowed: false,
          reason: `Scope '${scopeId}' is not active (status: ${scopeRecord.status})`,
          errorCode: ErrorCode.SCOPE_METADATA_PROHIBITED,
          evaluatedAt,
        });
      }

      activeScope = this.mapRecordToScope(scopeRecord);
    } else {
      // Default: Fail closed when no scope context is provided (Zero-Trust)
      return ok({
        allowed: false,
        reason: 'Zero-trust evaluation failed: No scope boundary, token, or override declared',
        errorCode: ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS,
        evaluatedAt,
      });
    }

    // 4. Temporal Window Check
    const startMs = new Date(activeScope.validFrom).getTime();
    const endMs = new Date(activeScope.validUntil).getTime();
    if (now > endMs) {
      return ok({
        allowed: false,
        reason: `Scope window expired at ${activeScope.validUntil}`,
        errorCode: ErrorCode.SCOPE_WINDOW_CLOSED,
        scopeId: activeScope.scopeId,
        evaluatedAt,
      });
    }
    if (now < startMs) {
      return ok({
        allowed: false,
        reason: `Scope window not yet active (starts at ${activeScope.validFrom})`,
        errorCode: ErrorCode.SCOPE_METADATA_PROHIBITED,
        scopeId: activeScope.scopeId,
        evaluatedAt,
      });
    }

    // 5. Action check against scope definition
    if (activeScope.allowedActions.length > 0 && !activeScope.allowedActions.includes(action)) {
      return ok({
        allowed: false,
        reason: `Action '${action}' is not in scope allowedActions: [${activeScope.allowedActions.join(', ')}]`,
        errorCode: ErrorCode.SCOPE_ACTION_DISALLOWED,
        scopeId: activeScope.scopeId,
        evaluatedAt,
      });
    }
    if (activeScope.disallowedActions && activeScope.disallowedActions.includes(action)) {
      return ok({
        allowed: false,
        reason: `Action '${action}' is explicitly in scope disallowedActions`,
        errorCode: ErrorCode.SCOPE_ACTION_DISALLOWED,
        scopeId: activeScope.scopeId,
        evaluatedAt,
      });
    }

    // 6. Target Canonicalization
    const canonRes = this.canonicalizeTarget(target, port);
    if (canonRes.isErr) {
      return ok({
        allowed: false,
        reason: `Failed to canonicalize target: ${canonRes.error.detail}`,
        errorCode: canonRes.error.error_code,
        scopeId: activeScope.scopeId,
        evaluatedAt,
      });
    }
    const normTarget = canonRes.value;

    // 7. Security Restrictions / Blacklist Checks
    if (!allowMetadata) {
      if (
        isBlacklistedIpOrCidr(normTarget.canonical) ||
        (normTarget.host && isBlacklistedHostname(normTarget.host))
      ) {
        return ok({
          allowed: false,
          reason: `Prohibited target '${target}' is blacklisted (SEC-INV-08 metadata/loopback protection)`,
          errorCode: ErrorCode.SCOPE_METADATA_PROHIBITED,
          normalizedTarget: normTarget,
          scopeId: activeScope.scopeId,
          evaluatedAt,
        });
      }
    }

    // 8. Port Range Evaluation
    const effectivePort = port ?? normTarget.port;
    if (effectivePort !== undefined && activeScope.portRanges.length > 0) {
      const portAllowed = activeScope.portRanges.some(
        (r) => effectivePort >= r.start && effectivePort <= r.end
      );
      if (!portAllowed) {
        return ok({
          allowed: false,
          reason: `Port ${effectivePort} is not within authorized port ranges`,
          errorCode: ErrorCode.SCOPE_PORT_DISALLOWED,
          normalizedTarget: normTarget,
          scopeId: activeScope.scopeId,
          evaluatedAt,
        });
      }
    }

    // 9. Exclusions Evaluation (Fail closed if target matches ANY exclusion)
    const exclusionMatch = this.checkTargetMatches(normTarget, activeScope.exclusions);
    if (exclusionMatch) {
      return ok({
        allowed: false,
        reason: `Target matches explicit scope exclusion: '${exclusionMatch}'`,
        errorCode: ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS,
        matchedExclusion: exclusionMatch,
        normalizedTarget: normTarget,
        scopeId: activeScope.scopeId,
        evaluatedAt,
      });
    }

    // 10. Inclusions Evaluation (Target MUST match at least ONE inclusion)
    const inclusionMatch = this.checkTargetMatches(normTarget, activeScope.inclusions);
    if (!inclusionMatch) {
      return ok({
        allowed: false,
        reason: `Target '${normTarget.canonical}' does not match any declared scope inclusion (Zero-Trust deny)`,
        errorCode: ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS,
        normalizedTarget: normTarget,
        scopeId: activeScope.scopeId,
        evaluatedAt,
      });
    }

    // Target is explicitly authorized!
    return ok({
      allowed: true,
      reason: `Target explicitly authorized by inclusion '${inclusionMatch}'`,
      matchedInclusion: inclusionMatch,
      normalizedTarget: normTarget,
      scopeId: activeScope.scopeId,
      evaluatedAt,
    });
  }

  private checkTargetMatches(
    target: NormalizedTarget,
    boundaries: {
      readonly cidrs?: readonly string[] | undefined;
      readonly hostnames?: readonly string[] | undefined;
      readonly urls?: readonly string[] | undefined;
      readonly resources?: readonly string[] | undefined;
    }
  ): string | undefined {
    // 1. Check URLs if target is URL
    if (target.type === 'url' && boundaries.urls) {
      for (const scopeUrl of boundaries.urls) {
        if (isUrlContainedInScope(target.canonical, scopeUrl)) {
          return scopeUrl;
        }
      }
    }

    // 2. Check CIDRs if target is IP or CIDR
    if (
      (target.type === 'ipv4' ||
        target.type === 'ipv6' ||
        target.type === 'cidr4' ||
        target.type === 'cidr6') &&
      boundaries.cidrs
    ) {
      for (const scopeCidr of boundaries.cidrs) {
        if (isTargetContainedInCidr(target.canonical, scopeCidr)) {
          return scopeCidr;
        }
      }
    }

    // 3. Check Hostnames if target has a host
    if (target.host && boundaries.hostnames) {
      for (const scopeHost of boundaries.hostnames) {
        if (isHostnameContainedInScope(target.host, scopeHost)) {
          return scopeHost;
        }
      }
    }

    // 4. Exact resource match
    if (boundaries.resources && boundaries.resources.includes(target.original)) {
      return target.original;
    }

    return undefined;
  }

  private mapActionToPermission(action: string): number | undefined {
    const act = action.toLowerCase();
    switch (act) {
      case 'read':
      case 'view_scope':
        return PermissionBit.SCOPE_READ;
      case 'admin':
      case 'create_scope':
      case 'update_scope':
        return PermissionBit.SCOPE_ADMIN;
      case 'execute':
      case 'workflow_execute':
        return PermissionBit.WORKFLOW_EXECUTE;
      case 'recon_passive':
      case 'passive':
        return PermissionBit.RECON_PASSIVE;
      case 'probing_active':
      case 'probe':
        return PermissionBit.PROBING_ACTIVE;
      case 'scan_invasive':
      case 'scan':
        return PermissionBit.SCAN_INVASIVE;
      default:
        return undefined;
    }
  }

  private mapRecordToScope(record: ScopeRecord): {
    inclusions: ScopeDefinition['inclusions'];
    exclusions: ScopeDefinition['exclusions'];
    allowedActions: readonly string[];
    disallowedActions?: readonly string[] | undefined;
    portRanges: readonly PortRange[];
    validFrom: string;
    validUntil: string;
    scopeId?: ScopeId | undefined;
    workspaceId: WorkspaceId;
    organizationId: OrganizationId;
  } {
    const validFrom =
      typeof record.valid_from === 'string'
        ? record.valid_from
        : new Date(record.valid_from).toISOString();
    const validUntil =
      typeof record.valid_until === 'string'
        ? record.valid_until
        : new Date(record.valid_until).toISOString();

    return {
      scopeId: record.id as ScopeId,
      workspaceId: record.workspace_id as WorkspaceId,
      organizationId: record.organization_id as OrganizationId,
      inclusions: normalizeBoundaries(record.inclusions),
      exclusions: normalizeBoundaries(record.exclusions),
      allowedActions: record.allowed_actions || [],
      disallowedActions: record.disallowed_actions || [],
      portRanges: (record.port_ranges as PortRange[]) || [],
      validFrom,
      validUntil,
    };
  }
}
