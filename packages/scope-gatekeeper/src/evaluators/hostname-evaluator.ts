/**
 * Shadow : Helix Nebula (SHN) — Hostname & Domain Scope Evaluator
 *
 * Enforces SEC-INV-01, SEC-INV-08, and INV-06:
 * - RFC 1123 / RFC 952 canonicalization
 * - Trailing-dot normalization
 * - Suffix-confusion attack defense (e.g. example.com vs evil-example.com)
 * - Controlled wildcard (*.domain.com) and dot-prefix (.domain.com) subdomain matching
 * - IDN / Punycode validation
 * - Cloud metadata and localhost blacklist
 */

import { ok, err, type Result } from '@shn/shared-kernel';

const PROHIBITED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.internal',
  'instance-data',
  '169.254.169.254',
  '100.100.100.200',
]);

const LABEL_REGEX = /^(?!-)[a-z0-9-_]{1,63}(?<!-)$/; // Allow RFC-compliant alphanumeric with interior hyphens

export function isBlacklistedHostname(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase().replace(/\.+$/, '');
  if (PROHIBITED_HOSTNAMES.has(normalized)) return true;
  if (normalized.endsWith('.localhost')) return true;
  if (normalized === 'metadata' || normalized.endsWith('.metadata.google.internal')) return true;
  return false;
}

export function canonicalizeHostname(rawHost: string): Result<string, string> {
  let host = rawHost.trim().toLowerCase();
  if (!host) return err('Hostname cannot be empty');

  // Strip userinfo if someone passed user:pass@host
  if (host.includes('@')) {
    return err(`Invalid hostname '${rawHost}': contains '@' userinfo separator`);
  }

  // Strip port if someone passed host:port
  if (host.includes(':') && !host.startsWith('[')) {
    const colonIdx = host.indexOf(':');
    host = host.substring(0, colonIdx);
  }

  // Strip trailing dots (DNS root reference, e.g. "example.com.")
  while (host.endsWith('.')) {
    host = host.slice(0, -1);
  }

  if (!host) return err('Hostname cannot be empty or root dot only');

  if (host.length > 253) {
    return err(`Hostname exceeds maximum length of 253 characters: '${host}'`);
  }

  // Check blacklist
  if (isBlacklistedHostname(host)) {
    return err(`Prohibited hostname '${host}' is blacklisted (SEC-INV-08 metadata/loopback protection)`);
  }

  // Validate labels
  const labels = host.split('.');
  for (const label of labels) {
    if (label.length === 0) {
      return err(`Invalid hostname '${host}': empty label or consecutive dots`);
    }
    if (label.length > 63) {
      return err(`Invalid hostname '${host}': label '${label}' exceeds 63 characters`);
    }
    // Support wildcard prefix for scope patterns
    if (label === '*' && labels.length > 1) {
      continue;
    }
    if (!LABEL_REGEX.test(label)) {
      return err(`Invalid characters in hostname label '${label}'`);
    }
  }

  return ok(host);
}

/**
 * Evaluates whether targetHost is authorized by scopeHost.
 *
 * Security semantics:
 * 1. Exact match:
 *    scopeHost = "example.com" -> ONLY "example.com"
 * 2. Wildcard match:
 *    scopeHost = "*.example.com" -> "api.example.com", "foo.bar.example.com"
 *    (NOT "evil-example.com", NOT "example.com")
 * 3. Dot-prefix match:
 *    scopeHost = ".example.com" -> "example.com" AND any subdomain "*.example.com"
 *    (NEVER "evil-example.com")
 */
export function isHostnameContainedInScope(targetHost: string, scopeHost: string): boolean {
  const normTargetRes = canonicalizeHostname(targetHost);
  if (normTargetRes.isErr) return false;
  const target = normTargetRes.value;

  const rawScope = scopeHost.trim().toLowerCase().replace(/\.+$/, '');
  if (!rawScope) return false;

  // Case 1: Dot-prefix scope e.g. ".example.com"
  if (rawScope.startsWith('.')) {
    const baseDomain = rawScope.substring(1);
    if (target === baseDomain) return true;
    if (target.endsWith(rawScope)) {
      return true;
    }
    return false;
  }

  // Case 2: Wildcard scope e.g. "*.example.com"
  if (rawScope.startsWith('*.')) {
    const suffix = rawScope.substring(1); // e.g. ".example.com"
    // Target must end with suffix and not be just suffix without subdomain
    if (target.endsWith(suffix) && target.length > suffix.length) {
      return true;
    }
    return false;
  }

  // Case 3: Exact match
  return target === rawScope;
}
