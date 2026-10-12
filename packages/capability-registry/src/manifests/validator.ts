/**
 * Shadow : Helix Nebula (SHN) — Capability & Tool Adapter Manifest Validator
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Phase 0.4 (INV-01, INV-03, INV-14),
 *                    Phase 0.8 (Declarative Contracts), Phase 0.9 (Tool Integration Architecture)
 */

import {
  ok,
  err,
  parseCapabilityId,
  parseAdapterId,
  type Result,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { makeCapabilityProblem } from '../errors.js';
import { parseSemVer, isValidVersionConstraint } from '../versioning/semver.js';
import type {
  CapabilityDefinition,
  ToolAdapterDefinition,
  CapabilityCategory,
  RiskClassification,
  TargetType,
  PlatformType,
} from '../contracts.js';

const VALID_CATEGORIES: ReadonlySet<string> = new Set([
  'RECONNAISSANCE',
  'DISCOVERY',
  'VULNERABILITY_SCAN',
  'EXPLOITATION',
  'ANALYSIS',
  'REPORTING',
  'UTILITY',
]);

const VALID_RISK_LEVELS: ReadonlySet<string> = new Set([
  'INFORMATIONAL',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
  'INVASIVE',
]);

const VALID_TARGET_TYPES: ReadonlySet<string> = new Set([
  'IP',
  'CIDR',
  'DOMAIN',
  'URL',
  'HOST',
]);

const VALID_PLATFORMS: ReadonlySet<string> = new Set(['linux', 'darwin', 'win32']);

const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i;
const DANGEROUS_BINARY_PATTERNS = /[;&|`$\x00\r\n<>]/;
const PATH_TRAVERSAL_PATTERN = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
const BATCH_SCRIPT_EXTENSION_REGEX = /\.(bat|cmd)$/i;

export function validateCapabilityManifest(
  raw: unknown
): Result<CapabilityDefinition, ProblemDetails> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        'Capability manifest must be a non-null object'
      )
    );
  }

  const obj = raw as Record<string, unknown>;

  // 1. ID Validation
  const idResult = parseCapabilityId(String(obj['id'] ?? ''));
  if (idResult.isErr) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        `Invalid capability manifest 'id': ${idResult.error}`
      )
    );
  }

  // 2. Name & Version Validation
  const name = String(obj['name'] ?? '').trim();
  if (!name || name.length > 128) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'name' must be between 1 and 128 characters"
      )
    );
  }

  const version = String(obj['version'] ?? '').trim();
  const versionResult = parseSemVer(version);
  if (versionResult.isErr) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        `Capability manifest 'version' invalid: ${versionResult.error}`
      )
    );
  }

  // 3. Display Name & Description
  const displayName = String(obj['displayName'] ?? '').trim();
  if (!displayName || displayName.length > 255) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'displayName' must be between 1 and 255 characters"
      )
    );
  }

  const description = String(obj['description'] ?? '').trim();
  if (!description || description.length > 4096) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'description' must be between 1 and 4096 characters"
      )
    );
  }

  // 4. Category & Risk Level
  const category = String(obj['category'] ?? '').toUpperCase();
  if (!VALID_CATEGORIES.has(category)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        `Capability category '${category}' is invalid. Allowed: ${Array.from(VALID_CATEGORIES).join(', ')}`
      )
    );
  }

  const riskLevel = String(obj['riskLevel'] ?? 'INFORMATIONAL').toUpperCase();
  if (!VALID_RISK_LEVELS.has(riskLevel)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        `Capability riskLevel '${riskLevel}' is invalid. Allowed: ${Array.from(VALID_RISK_LEVELS).join(', ')}`
      )
    );
  }

  // 5. Supported Targets
  const rawTargets = obj['supportedTargets'];
  if (!Array.isArray(rawTargets) || rawTargets.length === 0) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'supportedTargets' must be a non-empty array"
      )
    );
  }

  const supportedTargets: TargetType[] = [];
  for (const t of rawTargets) {
    const norm = String(t).toUpperCase();
    if (!VALID_TARGET_TYPES.has(norm)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_MALFORMED_MANIFEST,
          `Invalid target type '${t}' in capability manifest`
        )
      );
    }
    supportedTargets.push(norm as TargetType);
  }

  // 6. Permissions & Scope Action
  const requiredPermissions = Number(obj['requiredPermissions'] ?? 0);
  if (Number.isNaN(requiredPermissions) || requiredPermissions < 0) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'requiredPermissions' must be a valid non-negative integer"
      )
    );
  }

  const requiredScopeAction = String(obj['requiredScopeAction'] ?? '').trim();
  if (!requiredScopeAction || requiredScopeAction.length > 64) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'requiredScopeAction' must be between 1 and 64 characters"
      )
    );
  }

  // 7. Platform Compatibility
  const rawPlatforms = obj['platformCompatibility'] ?? ['linux', 'darwin', 'win32'];
  if (!Array.isArray(rawPlatforms) || rawPlatforms.length === 0) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'platformCompatibility' must be a non-empty array"
      )
    );
  }

  const platformCompatibility: PlatformType[] = [];
  for (const p of rawPlatforms) {
    const norm = String(p).toLowerCase();
    if (!VALID_PLATFORMS.has(norm)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_MALFORMED_MANIFEST,
          `Invalid platform '${p}' in capability manifest`
        )
      );
    }
    platformCompatibility.push(norm as PlatformType);
  }

  // 8. Integrity Digest
  const integrityDigest = String(obj['integrityDigest'] ?? '').trim();
  if (!SHA256_HEX_REGEX.test(integrityDigest)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.CAP_MALFORMED_MANIFEST,
        "Capability manifest 'integrityDigest' must be a 64-character hex SHA-256 string"
      )
    );
  }

  return ok({
    id: idResult.value,
    name,
    version,
    displayName,
    description,
    category: category as CapabilityCategory,
    riskLevel: riskLevel as RiskClassification,
    supportedTargets,
    requiredPermissions,
    requiredScopeAction,
    argumentSchema: (obj['argumentSchema'] ?? {}) as Record<string, unknown>,
    outputSchema: (obj['outputSchema'] ?? {}) as Record<string, unknown>,
    environmentRequirements: (obj['environmentRequirements'] ?? undefined) as Record<string, unknown> | undefined,
    resourceRequirements: (obj['resourceRequirements'] ?? undefined) as any,
    platformCompatibility,
    lifecycleState: (obj['lifecycleState'] ?? 'ACTIVE') as any,
    integrityDigest,
    workspaceId: (obj['workspaceId'] ?? undefined) as any,
    metadata: (obj['metadata'] ?? {}) as Record<string, unknown>,
  });
}

export function validateToolAdapterManifest(
  raw: unknown
): Result<ToolAdapterDefinition, ProblemDetails> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        'Tool adapter manifest must be a non-null object'
      )
    );
  }

  const obj = raw as Record<string, unknown>;

  // 1. Adapter ID
  const idResult = parseAdapterId(String(obj['id'] ?? ''));
  if (idResult.isErr) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        `Invalid adapter manifest 'id': ${idResult.error}`
      )
    );
  }

  // 2. Name & Version
  const name = String(obj['name'] ?? '').trim();
  if (!name || name.length > 128) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        "Adapter manifest 'name' must be between 1 and 128 characters"
      )
    );
  }

  const version = String(obj['version'] ?? '').trim();
  const versionResult = parseSemVer(version);
  if (versionResult.isErr) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        `Adapter manifest 'version' invalid: ${versionResult.error}`
      )
    );
  }

  // 3. Binary Path Security Sanitization
  const binaryPath = String(obj['binaryPath'] ?? '').trim();
  if (!binaryPath || binaryPath.length > 512) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        "Adapter manifest 'binaryPath' must be between 1 and 512 characters"
      )
    );
  }

  if (DANGEROUS_BINARY_PATTERNS.test(binaryPath)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.EXEC_COMMAND_INJECTION_REJECTED,
        "Adapter manifest 'binaryPath' contains forbidden shell metacharacters or control bytes"
      )
    );
  }

  if (PATH_TRAVERSAL_PATTERN.test(binaryPath) || binaryPath.includes('..')) {
    return err(
      makeCapabilityProblem(
        ErrorCode.EXEC_COMMAND_INJECTION_REJECTED,
        "Adapter manifest 'binaryPath' contains forbidden path traversal sequence ('..')"
      )
    );
  }

  if (BATCH_SCRIPT_EXTENSION_REGEX.test(binaryPath)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.EXEC_COMMAND_INJECTION_REJECTED,
        "Adapter manifest 'binaryPath' must not reference Windows batch scripts (.bat or .cmd)"
      )
    );
  }

  // 4. Supported Capabilities
  const rawCapabilities = obj['supportedCapabilities'];
  if (!Array.isArray(rawCapabilities) || rawCapabilities.length === 0) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        "Adapter manifest 'supportedCapabilities' must be a non-empty array of bindings"
      )
    );
  }

  const supportedCapabilities = [];
  for (const item of rawCapabilities) {
    if (!item || typeof item !== 'object') {
      return err(
        makeCapabilityProblem(
          ErrorCode.ADAPTER_INCOMPATIBLE,
          'Adapter capability binding must be an object'
        )
      );
    }
    const b = item as Record<string, unknown>;
    const capIdResult = parseCapabilityId(String(b['capabilityId'] ?? ''));
    if (capIdResult.isErr) {
      return err(
        makeCapabilityProblem(
          ErrorCode.ADAPTER_INCOMPATIBLE,
          `Invalid capabilityId in binding: ${capIdResult.error}`
        )
      );
    }

    const versionConstraint = String(b['versionConstraint'] ?? '*').trim();
    if (!isValidVersionConstraint(versionConstraint)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.ADAPTER_INCOMPATIBLE,
          `Invalid versionConstraint '${versionConstraint}' in adapter binding`
        )
      );
    }
    supportedCapabilities.push({
      capabilityId: capIdResult.value,
      versionConstraint,
      priority: Number(b['priority'] ?? 0),
    });
  }

  // 5. Platform Compatibility
  const rawPlatforms = obj['platformCompatibility'] ?? ['linux', 'darwin', 'win32'];
  if (!Array.isArray(rawPlatforms) || rawPlatforms.length === 0) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        "Adapter manifest 'platformCompatibility' must be a non-empty array"
      )
    );
  }

  const platformCompatibility: PlatformType[] = [];
  for (const p of rawPlatforms) {
    const norm = String(p).toLowerCase();
    if (!VALID_PLATFORMS.has(norm)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.ADAPTER_INCOMPATIBLE,
          `Invalid platform '${p}' in adapter manifest`
        )
      );
    }
    platformCompatibility.push(norm as PlatformType);
  }

  // 6. Manifest Digest
  const manifestDigest = String(obj['manifestDigest'] ?? '').trim();
  if (!SHA256_HEX_REGEX.test(manifestDigest)) {
    return err(
      makeCapabilityProblem(
        ErrorCode.ADAPTER_INCOMPATIBLE,
        "Adapter manifest 'manifestDigest' must be a 64-character hex SHA-256 string"
      )
    );
  }

  return ok({
    id: idResult.value,
    name,
    version,
    lifecycleState: (obj['lifecycleState'] ?? 'REGISTERED') as any,
    supportedCapabilities,
    platformCompatibility,
    binaryPath,
    manifestDigest,
    workspaceId: (obj['workspaceId'] ?? undefined) as any,
    metadata: (obj['metadata'] ?? {}) as Record<string, unknown>,
  });
}
