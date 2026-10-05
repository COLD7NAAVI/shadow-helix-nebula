/**
 * Shadow : Helix Nebula (SHN) — URL Scope Evaluator
 *
 * Enforces SEC-INV-01, SEC-INV-08, and INV-06:
 * - Scheme restriction (http/https only)
 * - Anti-userinfo defense (@ bypass prevention)
 * - Canonical port resolution (80/443 default normalization)
 * - Hostname normalization & blacklist check
 * - Segment-aware path containment (prevents /api vs /api-evil bypasses)
 * - Traversal resolution & escape prevention
 */

import { ok, err, type Result } from '@shn/shared-kernel';
import { canonicalizeHostname, isHostnameContainedInScope } from './hostname-evaluator.js';
import { isBlacklistedIpOrCidr } from './cidr-evaluator.js';

export interface ParsedScopeUrl {
  readonly scheme: string;
  readonly host: string;
  readonly port: number;
  readonly path: string;
  readonly query?: string | undefined;
  readonly canonical: string;
}

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

export function parseAndNormalizeUrl(rawUrl: string): Result<ParsedScopeUrl, string> {
  const trimmed = rawUrl.trim();
  if (!trimmed) return err('URL cannot be empty');

  // Defense against raw userinfo (@ bypass)
  // Check if '@' appears before the first '/' after the scheme
  const schemeSplit = trimmed.split('://');
  if (schemeSplit.length !== 2) {
    return err(`Invalid URL '${trimmed}': missing or malformed '://' scheme delimiter`);
  }

  const scheme = schemeSplit[0]!.toLowerCase() + ':';
  if (!ALLOWED_SCHEMES.has(scheme)) {
    return err(`Unsupported or dangerous URL scheme '${scheme}': only http and https are permitted`);
  }

  const authorityAndPath = schemeSplit[1]!;
  const firstSlashIdx = authorityAndPath.indexOf('/');
  const authority = firstSlashIdx === -1 ? authorityAndPath : authorityAndPath.substring(0, firstSlashIdx);
  const rawPath = firstSlashIdx === -1 ? '/' : authorityAndPath.substring(firstSlashIdx);

  // Reject userinfo in authority
  if (authority.includes('@')) {
    return err(`Dangerous URL '${trimmed}': userinfo (@) is prohibited for target security authorization`);
  }

  // Parse host and port
  let hostPart: string;
  let port: number;

  if (authority.startsWith('[')) {
    // IPv6 literal: [::1]:8080 or [::1]
    const closeBracketIdx = authority.indexOf(']');
    if (closeBracketIdx === -1) {
      return err(`Malformed IPv6 URL authority: '${authority}'`);
    }
    const ipv6Host = authority.substring(1, closeBracketIdx);
    hostPart = ipv6Host;
    const rest = authority.substring(closeBracketIdx + 1);
    if (rest.startsWith(':')) {
      const portStr = rest.substring(1);
      const parsedPort = parseInt(portStr, 10);
      if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        return err(`Invalid port in URL: '${portStr}'`);
      }
      port = parsedPort;
    } else if (rest.length > 0) {
      return err(`Malformed IPv6 URL authority trailing characters: '${rest}'`);
    } else {
      port = scheme === 'https:' ? 443 : 80;
    }
  } else if (authority.includes(':')) {
    const colonIdx = authority.lastIndexOf(':');
    hostPart = authority.substring(0, colonIdx);
    const portStr = authority.substring(colonIdx + 1);
    const parsedPort = parseInt(portStr, 10);
    if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      return err(`Invalid port in URL: '${portStr}'`);
    }
    port = parsedPort;
  } else {
    hostPart = authority;
    port = scheme === 'https:' ? 443 : 80;
  }

  // Check if hostPart is an IP address
  if (hostPart.includes('.') || hostPart.includes(':')) {
    if (isBlacklistedIpOrCidr(hostPart)) {
      return err(`Prohibited IP target in URL '${hostPart}' is blacklisted`);
    }
  }

  // Support dot-prefix scope host in URL (e.g. https://.example.com/v1)
  let hostForValidation = hostPart;
  let isDotPrefix = false;
  if (hostPart.startsWith('.') && hostPart.length > 1 && !hostPart.startsWith('..')) {
    isDotPrefix = true;
    hostForValidation = hostPart.substring(1);
  }

  // Canonicalize host
  const normHostRes = canonicalizeHostname(hostForValidation);
  if (normHostRes.isErr) {
    return err(`Invalid host in URL: ${normHostRes.error}`);
  }
  const host = isDotPrefix ? '.' + normHostRes.value : normHostRes.value;

  // Normalize path: resolve '.' and '..'
  // Strip fragment (#...)
  const hashIdx = rawPath.indexOf('#');
  const pathWithoutHash = hashIdx === -1 ? rawPath : rawPath.substring(0, hashIdx);

  // Extract query if present
  let pathOnly: string;
  let query: string | undefined;
  const questionIdx = pathWithoutHash.indexOf('?');
  if (questionIdx !== -1) {
    pathOnly = pathWithoutHash.substring(0, questionIdx);
    query = pathWithoutHash.substring(questionIdx + 1);
  } else {
    pathOnly = pathWithoutHash;
  }

  // Normalize path segments
  const rawSegments = pathOnly.split('/');
  const resolvedSegments: string[] = [];

  for (const seg of rawSegments) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (resolvedSegments.length === 0) {
        return err(`Path traversal detected in URL '${trimmed}': '..' escapes root`);
      }
      resolvedSegments.pop();
    } else {
      // Decode encoded characters safely, reject null bytes
      if (seg.includes('%00') || seg.includes('\0')) {
        return err(`Null byte injection detected in URL path segment '${seg}'`);
      }
      resolvedSegments.push(seg);
    }
  }

  const normalizedPath = '/' + resolvedSegments.join('/');
  // Preserve trailing slash if original path ended with '/' and path has more than just '/'
  const finalPath =
    pathOnly.endsWith('/') && normalizedPath !== '/' ? normalizedPath + '/' : normalizedPath;

  const defaultPort = scheme === 'https:' ? 443 : 80;
  const canonicalPort = port === defaultPort ? '' : `:${port}`;
  const canonicalQuery = query ? `?${query}` : '';
  const canonical = `${scheme}//${host}${canonicalPort}${finalPath}${canonicalQuery}`;

  return ok({
    scheme,
    host,
    port,
    path: finalPath,
    query,
    canonical,
  });
}

/**
 * Evaluates whether targetUrl is authorized under scopeUrl.
 *
 * Rules:
 * 1. Scheme must match.
 * 2. Port must match.
 * 3. Host must be contained within scope host (exact or subdomain).
 * 4. Path must be a segment-level prefix of target path:
 *    - Scope path "/api" matches target "/api", "/api/", "/api/v1"
 *    - Scope path "/api" DOES NOT match target "/api-evil"
 */
export function isUrlContainedInScope(targetUrl: string, scopeUrl: string): boolean {
  const normTarget = parseAndNormalizeUrl(targetUrl);
  if (normTarget.isErr) return false;

  const normScope = parseAndNormalizeUrl(scopeUrl);
  if (normScope.isErr) return false;

  const target = normTarget.value;
  const scope = normScope.value;

  // 1. Scheme match
  if (target.scheme !== scope.scheme) return false;

  // 2. Port match
  if (target.port !== scope.port) return false;

  // 3. Host containment
  if (!isHostnameContainedInScope(target.host, scope.host)) return false;

  // 4. Path containment
  const scopePath = scope.path;
  const targetPath = target.path;

  if (scopePath === '/' || scopePath === '') {
    return true;
  }

  // Ensure segment-based containment
  if (targetPath === scopePath) {
    return true;
  }

  const scopeWithSlash = scopePath.endsWith('/') ? scopePath : scopePath + '/';
  if (targetPath.startsWith(scopeWithSlash)) {
    return true;
  }

  return false;
}
