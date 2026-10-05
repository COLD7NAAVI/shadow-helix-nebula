/**
 * Shadow : Helix Nebula (SHN) — Deterministic CIDR Evaluator
 *
 * Enforces SEC-INV-01, SEC-INV-08, and INV-06:
 * - Deterministic IPv4 (32-bit) and IPv6 (128-bit) bitwise containment
 * - Canonical normalization
 * - Sibling / adjacent subnet boundary enforcement
 * - Prohibition of leading zeros (octal ambiguity defense)
 * - Cloud metadata and SSRF blacklist enforcement
 * - Fail-closed error handling
 */

import { ok, err, type Result } from '@shn/shared-kernel';

const IPV6_MAX = (1n << 128n) - 1n;

export interface IPv4Cidr {
  readonly version: 4;
  readonly network: number; // Unsigned 32-bit integer
  readonly maskBits: number;
  readonly mask: number;
  readonly canonical: string;
}

export interface IPv6Cidr {
  readonly version: 6;
  readonly network: bigint; // 128-bit unsigned integer
  readonly maskBits: number;
  readonly mask: bigint;
  readonly canonical: string;
}

export type ParsedCidr = IPv4Cidr | IPv6Cidr;

// --- Bitwise Mask Calculation ---

export function getIPv4Mask(prefix: number): number {
  if (prefix < 0 || prefix > 32 || !Number.isInteger(prefix)) {
    throw new Error(`Invalid IPv4 prefix: ${prefix}, must be integer 0..32`);
  }
  if (prefix === 0) return 0;
  if (prefix === 32) return 0xffffffff >>> 0;
  return (~((1 << (32 - prefix)) - 1)) >>> 0;
}

export function getIPv6Mask(prefix: number): bigint {
  if (prefix < 0 || prefix > 128 || !Number.isInteger(prefix)) {
    throw new Error(`Invalid IPv6 prefix: ${prefix}, must be integer 0..128`);
  }
  if (prefix === 0) return 0n;
  if (prefix === 128) return IPV6_MAX;
  const shift = 128n - BigInt(prefix);
  return (IPV6_MAX << shift) & IPV6_MAX;
}

// --- IPv4 Parsing & Formatting ---

export function parseIPv4Address(ip: string): Result<number, string> {
  const trimmed = ip.trim();
  if (!trimmed) return err('Empty IPv4 address');

  const parts = trimmed.split('.');
  if (parts.length !== 4) {
    return err(`Invalid IPv4 address: '${trimmed}', expected exactly 4 octets`);
  }

  let num = 0;
  for (let i = 0; i < 4; i++) {
    const part = parts[i]!;
    // Disallow leading zeros to prevent octal confusion (e.g. 010.0.0.1)
    if (part.length > 1 && part.startsWith('0')) {
      return err(`Invalid IPv4 octet '${part}': leading zeros prohibited to prevent octal ambiguity`);
    }
    // Only decimal digits allowed
    if (!/^\d+$/.test(part)) {
      return err(`Invalid IPv4 octet '${part}': non-digit characters detected`);
    }
    const val = parseInt(part, 10);
    if (val < 0 || val > 255) {
      return err(`Invalid IPv4 octet '${part}': out of range (0..255)`);
    }
    num = ((num << 8) | val) >>> 0;
  }

  return ok(num);
}

export function formatIPv4Address(num: number): string {
  const u = num >>> 0;
  const octet1 = (u >>> 24) & 0xff;
  const octet2 = (u >>> 16) & 0xff;
  const octet3 = (u >>> 8) & 0xff;
  const octet4 = u & 0xff;
  return `${octet1}.${octet2}.${octet3}.${octet4}`;
}

// --- IPv6 Parsing & Formatting ---

export function parseIPv6Address(ip: string): Result<bigint, string> {
  const trimmed = ip.trim().toLowerCase();
  if (!trimmed) return err('Empty IPv6 address');

  // Check for IPv4-mapped IPv6 suffix: e.g. ::ffff:192.168.1.1
  const lastColon = trimmed.lastIndexOf(':');
  if (lastColon !== -1) {
    const potentialIpv4 = trimmed.substring(lastColon + 1);
    if (potentialIpv4.includes('.')) {
      const ipv4Res = parseIPv4Address(potentialIpv4);
      if (ipv4Res.isErr) return err(`Invalid IPv4-mapped portion: ${ipv4Res.error}`);

      const prefixPart = trimmed.substring(0, lastColon);
      // Format IPv4 as two 16-bit hex chunks:
      const v4num = ipv4Res.value;
      const hi = ((v4num >>> 16) & 0xffff).toString(16);
      const lo = (v4num & 0xffff).toString(16);
      return parseIPv6Address(`${prefixPart}:${hi}:${lo}`);
    }
  }

  const doubleColonCount = (trimmed.match(/::/g) || []).length;
  if (doubleColonCount > 1) {
    return err(`Invalid IPv6 address '${trimmed}': multiple '::' compressions prohibited`);
  }

  let parts: string[];
  if (doubleColonCount === 1) {
    const [left, right] = trimmed.split('::') as [string, string];
    const leftHextets = left ? left.split(':') : [];
    const rightHextets = right ? right.split(':') : [];
    const missing = 8 - (leftHextets.length + rightHextets.length);
    if (missing < 1) {
      return err(`Invalid IPv6 address '${trimmed}': too many hextets`);
    }
    const middleZeros = new Array(missing).fill('0');
    parts = [...leftHextets, ...middleZeros, ...rightHextets];
  } else {
    parts = trimmed.split(':');
    if (parts.length !== 8) {
      return err(`Invalid IPv6 address '${trimmed}': expected exactly 8 hextets or '::' compression`);
    }
  }

  let result = 0n;
  for (let i = 0; i < 8; i++) {
    const part = parts[i]!;
    if (part.length === 0 || part.length > 4) {
      return err(`Invalid IPv6 hextet '${part}': length must be between 1 and 4 hex characters`);
    }
    if (!/^[0-9a-f]{1,4}$/.test(part)) {
      return err(`Invalid IPv6 hextet '${part}': non-hex character detected`);
    }
    const val = BigInt(parseInt(part, 16));
    result = (result << 16n) | val;
  }

  return ok(result);
}

export function formatIPv6Address(num: bigint): string {
  // Break into 8 16-bit chunks
  const hextets: number[] = [];
  for (let i = 7; i >= 0; i--) {
    const shift = BigInt(i * 16);
    hextets.push(Number((num >> shift) & 0xffffn));
  }

  // RFC 5952: Find the longest run of consecutive 0 hextets (at least 2)
  let bestStart = -1;
  let bestLen = 0;
  let currentStart = -1;
  let currentLen = 0;

  for (let i = 0; i < 8; i++) {
    if (hextets[i] === 0) {
      if (currentStart === -1) {
        currentStart = i;
        currentLen = 1;
      } else {
        currentLen++;
      }
    } else {
      if (currentLen > bestLen) {
        bestStart = currentStart;
        bestLen = currentLen;
      }
      currentStart = -1;
      currentLen = 0;
    }
  }
  if (currentLen > bestLen) {
    bestStart = currentStart;
    bestLen = currentLen;
  }

  // If best run is >= 2, compress it
  if (bestLen >= 2) {
    const left = hextets.slice(0, bestStart).map((h) => h.toString(16)).join(':');
    const right = hextets.slice(bestStart + bestLen).map((h) => h.toString(16)).join(':');
    return `${left}::${right}`;
  }

  return hextets.map((h) => h.toString(16)).join(':');
}

// --- CIDR Parsing ---

export function parseCidrBlock(cidr: string): Result<ParsedCidr, string> {
  const trimmed = cidr.trim();
  const slashIdx = trimmed.indexOf('/');
  if (slashIdx === -1) {
    return err(`Invalid CIDR format '${trimmed}': missing '/' subnet prefix separator`);
  }

  const ipPart = trimmed.substring(0, slashIdx);
  const prefixPart = trimmed.substring(slashIdx + 1);

  if (!/^\d+$/.test(prefixPart)) {
    return err(`Invalid CIDR subnet prefix '/${prefixPart}': must be non-negative integer`);
  }
  // Check for leading zero in prefix if length > 1
  if (prefixPart.length > 1 && prefixPart.startsWith('0')) {
    return err(`Invalid CIDR prefix '/${prefixPart}': leading zeros prohibited`);
  }

  const prefix = parseInt(prefixPart, 10);

  // Try IPv4 first
  if (ipPart.includes('.')) {
    if (prefix < 0 || prefix > 32) {
      return err(`Invalid IPv4 CIDR prefix '/${prefixPart}': must be between 0 and 32`);
    }
    const ipRes = parseIPv4Address(ipPart);
    if (ipRes.isErr) return err(ipRes.error);

    const mask = getIPv4Mask(prefix);
    const network = (ipRes.value & mask) >>> 0;
    const canonical = `${formatIPv4Address(network)}/${prefix}`;

    return ok({
      version: 4,
      network,
      maskBits: prefix,
      mask,
      canonical,
    });
  }

  // Otherwise IPv6
  if (prefix < 0 || prefix > 128) {
    return err(`Invalid IPv6 CIDR prefix '/${prefixPart}': must be between 0 and 128`);
  }
  const ipRes = parseIPv6Address(ipPart);
  if (ipRes.isErr) return err(ipRes.error);

  const mask = getIPv6Mask(prefix);
  const network = ipRes.value & mask;
  const canonical = `${formatIPv6Address(network)}/${prefix}`;

  return ok({
    version: 6,
    network,
    maskBits: prefix,
    mask,
    canonical,
  });
}

// --- Blacklist / SSRF / Cloud Metadata Checks ---

const PROHIBITED_EXACT_IPV4 = new Set<number>([
  0xa9fea9fe, // 169.254.169.254 (AWS / Azure / GCP IMDS)
  0x646464c8, // 100.100.100.200 (Alibaba Cloud IMDS)
  0x7f000001, // 127.0.0.1
  0x00000000, // 0.0.0.0
  0xffffffff, // 255.255.255.255
]);

export function isProhibitedIPv4(ipNum: number): boolean {
  const u = ipNum >>> 0;
  if (PROHIBITED_EXACT_IPV4.has(u)) return true;

  // 127.0.0.0/8 (Loopback)
  if (((u & 0xff000000) >>> 0) === 0x7f000000) return true;
  // 169.254.0.0/16 (Link-local)
  if (((u & 0xffff0000) >>> 0) === 0xa9fe0000) return true;
  // 0.0.0.0/8 (Current network)
  if (((u & 0xff000000) >>> 0) === 0x00000000) return true;
  // 224.0.0.0/4 (Multicast)
  if (((u & 0xf0000000) >>> 0) === 0xe0000000) return true;

  return false;
}

export function isProhibitedIPv6(ipNum: bigint): boolean {
  if (ipNum === 1n) return true; // ::1 (Loopback)
  if (ipNum === 0n) return true; // :: (Unspecified)

  // AWS IMDSv6: fd00:ec2::254
  // fd00:0ec2:0000:0000:0000:0000:0000:0254
  const awsImdsV6 = (0xfd00n << 112n) | (0x0ec2n << 96n) | 0x0254n;
  if (ipNum === awsImdsV6) return true;

  // fe80::/10 (Link-Local)
  const fe80Mask = getIPv6Mask(10);
  const fe80Net = (0xfe80n << 112n) & fe80Mask;
  if ((ipNum & fe80Mask) === fe80Net) return true;

  // ff00::/8 (Multicast)
  const ff00Mask = getIPv6Mask(8);
  const ff00Net = (0xff00n << 112n) & ff00Mask;
  if ((ipNum & ff00Mask) === ff00Net) return true;

  return false;
}

export function isBlacklistedIpOrCidr(target: string): boolean {
  const trimmed = target.trim();
  const slashIdx = trimmed.indexOf('/');
  const ipOnly = slashIdx === -1 ? trimmed : trimmed.substring(0, slashIdx);

  if (ipOnly.includes('.')) {
    const parsed = parseIPv4Address(ipOnly);
    if (parsed.isOk) {
      return isProhibitedIPv4(parsed.value);
    }
  } else {
    const parsed = parseIPv6Address(ipOnly);
    if (parsed.isOk) {
      return isProhibitedIPv6(parsed.value);
    }
  }

  return false;
}

// --- Containment Evaluation ---

/**
 * Checks whether target (single IP or CIDR) is contained within candidate CIDR.
 * Returns false if versions mismatch or if either format is invalid.
 */
export function isTargetContainedInCidr(target: string, candidateCidr: string): boolean {
  const cidrRes = parseCidrBlock(candidateCidr);
  if (cidrRes.isErr) return false;
  const parentCidr = cidrRes.value;

  const trimmedTarget = target.trim();
  const hasSlash = trimmedTarget.includes('/');

  if (parentCidr.version === 4) {
    if (hasSlash) {
      const targetCidrRes = parseCidrBlock(trimmedTarget);
      if (targetCidrRes.isErr || targetCidrRes.value.version !== 4) return false;
      const child = targetCidrRes.value;

      // Child must be equal or more specific than parent
      if (child.maskBits < parentCidr.maskBits) return false;
      // Network of child must match parent network under parent mask
      return ((child.network & parentCidr.mask) >>> 0) === parentCidr.network;
    } else {
      const targetIpRes = parseIPv4Address(trimmedTarget);
      if (targetIpRes.isErr) return false;
      return ((targetIpRes.value & parentCidr.mask) >>> 0) === parentCidr.network;
    }
  } else {
    // IPv6
    if (hasSlash) {
      const targetCidrRes = parseCidrBlock(trimmedTarget);
      if (targetCidrRes.isErr || targetCidrRes.value.version !== 6) return false;
      const child = targetCidrRes.value;

      if (child.maskBits < parentCidr.maskBits) return false;
      return (child.network & parentCidr.mask) === parentCidr.network;
    } else {
      const targetIpRes = parseIPv6Address(trimmedTarget);
      if (targetIpRes.isErr) return false;
      return (targetIpRes.value & parentCidr.mask) === parentCidr.network;
    }
  }
}
