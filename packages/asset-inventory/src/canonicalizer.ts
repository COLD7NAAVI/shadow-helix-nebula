/**
 * Shadow : Helix Nebula (SHN) — Target Canonicalizer & Normalizer
 *
 * Authoritative Spec: Phase 0.3 (BC-NRM), Phase 0.10 Section 6
 * Enforces canonical, deduplicated network identifiers for assets.
 */

import { ok, err, type Result } from '@shn/shared-kernel';
import type { AssetType } from '@shn/data-access';

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$/;
const CIDR_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/;
const FQDN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const HOST_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

export function detectTargetType(raw: string): AssetType {
  const trimmed = raw.trim();
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return 'URL';
  }
  if (CIDR_REGEX.test(trimmed)) {
    return 'CIDR';
  }
  if (IPV4_REGEX.test(trimmed)) {
    return 'IPV4';
  }
  if (trimmed.includes(':') && (IPV6_REGEX.test(trimmed) || trimmed.split(':').length >= 3)) {
    return 'IPV6';
  }
  if (FQDN_REGEX.test(trimmed)) {
    return 'FQDN';
  }
  return 'HOST';
}

export function canonicalizeTarget(type: AssetType, raw: string): Result<string, string> {
  const trimmed = raw.trim();
  if (!trimmed) {
    return err('Target value cannot be empty');
  }

  switch (type as string) {
    case 'IPV4':
    case 'IPV4_ADDRESS': {
      if (!IPV4_REGEX.test(trimmed)) {
        return err(`Invalid IPv4 address format: "${trimmed}"`);
      }
      const octets = trimmed.split('.').map((o) => parseInt(o, 10));
      return ok(octets.join('.'));
    }

    case 'IPV6': {
      // Basic normalization: lowercased hex
      const lower = trimmed.toLowerCase();
      return ok(lower);
    }

    case 'CIDR': {
      const match = CIDR_REGEX.exec(trimmed);
      if (!match) {
        return err(`Invalid CIDR subnet format: "${trimmed}"`);
      }
      const parts = trimmed.split('/');
      const ip = parts[0];
      const prefixStr = parts[1];
      if (!ip || !prefixStr) {
        return err(`Invalid CIDR subnet format: "${trimmed}"`);
      }
      const prefix = parseInt(prefixStr, 10);
      const octetStrs = ip.split('.');
      if (octetStrs.length !== 4) {
        return err(`Invalid CIDR subnet format: "${trimmed}"`);
      }
      const octets = octetStrs.map((o) => parseInt(o, 10));
      const o0 = octets[0] ?? 0;
      const o1 = octets[1] ?? 0;
      const o2 = octets[2] ?? 0;
      const o3 = octets[3] ?? 0;
      const ipNum = ((o0 << 24) | (o1 << 16) | (o2 << 8) | o3) >>> 0;
      const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
      const netNum = (ipNum & mask) >>> 0;
      const netOctets = [
        (netNum >>> 24) & 255,
        (netNum >>> 16) & 255,
        (netNum >>> 8) & 255,
        netNum & 255,
      ];
      return ok(`${netOctets.join('.')}/${prefix}`);
    }

    case 'FQDN':
    case 'DOMAIN': {
      const lower = trimmed.toLowerCase().replace(/\.$/, '');
      if (!FQDN_REGEX.test(lower)) {
        return err(`Invalid FQDN domain format: "${trimmed}"`);
      }
      return ok(lower);
    }

    case 'URL': {
      try {
        const parsed = new URL(trimmed);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          return err(`Unsupported URL protocol "${parsed.protocol}". Must be http: or https:`);
        }
        // Normalize hostname to lowercase
        parsed.hostname = parsed.hostname.toLowerCase();
        // Remove standard default ports
        if (
          (parsed.protocol === 'http:' && parsed.port === '80') ||
          (parsed.protocol === 'https:' && parsed.port === '443')
        ) {
          parsed.port = '';
        }
        return ok(parsed.toString());
      } catch {
        return err(`Invalid URL format: "${trimmed}"`);
      }
    }

    case 'HOST': {
      const lower = trimmed.toLowerCase();
      if (!HOST_REGEX.test(lower) && !FQDN_REGEX.test(lower)) {
        return err(`Invalid Hostname identifier format: "${trimmed}"`);
      }
      return ok(lower);
    }

    default:
      return err(`Unknown asset type "${type}"`);
  }
}

export function normalizeTarget(raw: string): Result<{ type: AssetType; canonicalValue: string }, string> {
  const detectedType = detectTargetType(raw);
  const canonicalResult = canonicalizeTarget(detectedType, raw);
  if (canonicalResult.isErr) {
    return err(canonicalResult.error);
  }
  return ok({
    type: detectedType,
    canonicalValue: canonicalResult.value,
  });
}
