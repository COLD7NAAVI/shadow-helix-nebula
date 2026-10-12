/**
 * Shadow : Helix Nebula (SHN) — Strict SemVer Parsing and Range Compatibility Engine
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Phase 0.8 Section 4, Phase 0.9 Section 9
 */

import { ok, err, type Result } from '@shn/shared-kernel';
import type { CapabilityLifecycleState, AdapterLifecycleState } from '../contracts.js';

export interface SemVer {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease?: string | undefined;
  readonly build?: string | undefined;
}

export type VersionCompatibility =
  | 'EXACT'
  | 'COMPATIBLE'
  | 'INCOMPATIBLE'
  | 'DEPRECATED'
  | 'REVOKED'
  | 'UNSUPPORTED';

const SEMVER_REGEX = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

export function parseSemVer(versionStr: string): Result<SemVer, string> {
  if (!versionStr || typeof versionStr !== 'string') {
    return err('Version string must not be empty');
  }

  const clean = versionStr.trim().replace(/^v/, '');
  const match = SEMVER_REGEX.exec(clean);

  if (!match) {
    return err(`Invalid SemVer format: '${versionStr}'`);
  }

  const major = parseInt(match[1]!, 10);
  const minor = parseInt(match[2]!, 10);
  const patch = parseInt(match[3]!, 10);

  if (Number.isNaN(major) || Number.isNaN(minor) || Number.isNaN(patch)) {
    return err(`Invalid SemVer numeric segments in '${versionStr}'`);
  }

  return ok({
    major,
    minor,
    patch,
    prerelease: match[4] || undefined,
    build: match[5] || undefined,
  });
}

export function formatSemVer(v: SemVer): string {
  let res = `${v.major}.${v.minor}.${v.patch}`;
  if (v.prerelease) {
    res += `-${v.prerelease}`;
  }
  if (v.build) {
    res += `+${v.build}`;
  }
  return res;
}

export function compareSemVer(a: SemVer, b: SemVer): -1 | 0 | 1 {
  if (a.major !== b.major) {
    return a.major > b.major ? 1 : -1;
  }
  if (a.minor !== b.minor) {
    return a.minor > b.minor ? 1 : -1;
  }
  if (a.patch !== b.patch) {
    return a.patch > b.patch ? 1 : -1;
  }

  // Pre-release versions have lower precedence than normal version
  if (a.prerelease && !b.prerelease) return -1;
  if (!a.prerelease && b.prerelease) return 1;
  if (a.prerelease && b.prerelease) {
    if (a.prerelease === b.prerelease) return 0;
    return a.prerelease > b.prerelease ? 1 : -1;
  }

  return 0;
}

function matchesCaret(v: SemVer, target: SemVer): boolean {
  if (target.major > 0) {
    // ^1.2.3: >=1.2.3 <2.0.0
    if (v.major !== target.major) return false;
    if (v.minor < target.minor) return false;
    if (v.minor === target.minor && v.patch < target.patch) return false;
    return true;
  }
  if (target.minor > 0) {
    // ^0.2.3: >=0.2.3 <0.3.0
    if (v.major !== 0 || v.minor !== target.minor) return false;
    return v.patch >= target.patch;
  }
  // ^0.0.3: =0.0.3
  return v.major === 0 && v.minor === 0 && v.patch === target.patch;
}

function matchesTilde(v: SemVer, target: SemVer): boolean {
  // ~1.2.3: >=1.2.3 <1.3.0
  if (v.major !== target.major || v.minor !== target.minor) return false;
  return v.patch >= target.patch;
}

export function satisfiesVersion(versionStr: string, constraintStr: string): boolean {
  const parsed = parseSemVer(versionStr);
  if (parsed.isErr) return false;
  const v = parsed.value;

  const rawConstraint = constraintStr.trim();
  if (rawConstraint === '*' || rawConstraint.toLowerCase() === 'x' || rawConstraint === 'latest' || rawConstraint === '') {
    return true;
  }

  // Multiple clauses (e.g. ">=1.0.0 <2.0.0")
  const clauses = rawConstraint.split(/\s+/).filter(Boolean);
  if (clauses.length > 1) {
    return clauses.every(clause => satisfiesVersion(versionStr, clause));
  }

  const clause = clauses[0] ?? rawConstraint;

  // Caret ^
  if (clause.startsWith('^')) {
    const targetParsed = parseSemVer(clause.slice(1));
    if (targetParsed.isErr) return false;
    return matchesCaret(v, targetParsed.value);
  }

  // Tilde ~
  if (clause.startsWith('~')) {
    const targetParsed = parseSemVer(clause.slice(1));
    if (targetParsed.isErr) return false;
    return matchesTilde(v, targetParsed.value);
  }

  // Comparison >=
  if (clause.startsWith('>=')) {
    const targetParsed = parseSemVer(clause.slice(2));
    if (targetParsed.isErr) return false;
    return compareSemVer(v, targetParsed.value) >= 0;
  }

  // Comparison <=
  if (clause.startsWith('<=')) {
    const targetParsed = parseSemVer(clause.slice(2));
    if (targetParsed.isErr) return false;
    return compareSemVer(v, targetParsed.value) <= 0;
  }

  // Comparison >
  if (clause.startsWith('>')) {
    const targetParsed = parseSemVer(clause.slice(1));
    if (targetParsed.isErr) return false;
    return compareSemVer(v, targetParsed.value) > 0;
  }

  // Comparison <
  if (clause.startsWith('<')) {
    const targetParsed = parseSemVer(clause.slice(1));
    if (targetParsed.isErr) return false;
    return compareSemVer(v, targetParsed.value) < 0;
  }

  // Exact match (with or without =)
  const exactTarget = clause.startsWith('=') ? clause.slice(1) : clause;
  const targetParsed = parseSemVer(exactTarget);
  if (targetParsed.isErr) return false;
  return compareSemVer(v, targetParsed.value) === 0;
}

export function evaluateCompatibility(
  capabilityVersion: string,
  adapterConstraint: string,
  capabilityState?: CapabilityLifecycleState,
  adapterState?: AdapterLifecycleState
): VersionCompatibility {
  if (capabilityState === 'REVOKED' || adapterState === 'REVOKED') {
    return 'REVOKED';
  }

  if (capabilityState === 'DISABLED' || adapterState === 'DISABLED') {
    return 'UNSUPPORTED';
  }

  if (capabilityState === 'DEPRECATED') {
    return 'DEPRECATED';
  }

  if (!satisfiesVersion(capabilityVersion, adapterConstraint)) {
    return 'INCOMPATIBLE';
  }

  const parsedCap = parseSemVer(capabilityVersion);
  const cleanConstraint = adapterConstraint.trim().replace(/^=/, '');
  const parsedConst = parseSemVer(cleanConstraint);

  if (parsedCap.isOk && parsedConst.isOk && compareSemVer(parsedCap.value, parsedConst.value) === 0) {
    return 'EXACT';
  }

  return 'COMPATIBLE';
}

export function isValidVersionConstraint(constraintStr: string): boolean {
  const rawConstraint = constraintStr.trim();
  if (!rawConstraint || rawConstraint === '*' || rawConstraint.toLowerCase() === 'x' || rawConstraint === 'latest') {
    return true;
  }
  const clauses = rawConstraint.split(/\s+/).filter(Boolean);
  for (const clause of clauses) {
    let clean = clause;
    if (clean.startsWith('>=') || clean.startsWith('<=')) {
      clean = clean.slice(2);
    } else if (clean.startsWith('^') || clean.startsWith('~') || clean.startsWith('=') || clean.startsWith('>') || clean.startsWith('<')) {
      clean = clean.slice(1);
    }
    if (parseSemVer(clean).isErr) {
      return false;
    }
  }
  return true;
}
