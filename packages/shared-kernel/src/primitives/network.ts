/**
 * Shadow : Helix Nebula (SHN) — Network Target Primitives
 *
 * Enforces SEC-INV-01 & SEC-INV-08: Target scope parsing, boundary verification, and anti-SSRF defenses.
 */

import { ok, err, type Result } from '../result/result.js';

export type IPv4Address = string & { readonly __brand: 'IPv4Address' };
export type IPv6Address = string & { readonly __brand: 'IPv6Address' };
export type CidrBlock = string & { readonly __brand: 'CidrBlock' };
export type Hostname = string & { readonly __brand: 'Hostname' };
export type Port = number & { readonly __brand: 'Port' };

export interface PortRange {
  readonly start: Port;
  readonly end: Port;
}

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$/;
const HOSTNAME_REGEX = /^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$/;

/**
 * Permanent Cloud Metadata & Loopback Blacklist (SEC-INV-08)
 */
const PROHIBITED_TARGETS = new Set([
  '169.254.169.254', // AWS / Azure / GCP metadata
  '127.0.0.1',       // IPv4 loopback
  '::1',             // IPv6 loopback
  'localhost',
  'metadata.google.internal',
  '100.100.100.200', // Alibaba Cloud metadata
]);

export function isProhibitedTarget(target: string): boolean {
  const normalized = target.trim().toLowerCase();
  if (PROHIBITED_TARGETS.has(normalized)) return true;
  if (normalized.startsWith('127.')) return true;
  if (normalized.startsWith('169.254.')) return true;
  return false;
}

export function parseIPv4(ip: string): Result<IPv4Address, string> {
  const trimmed = ip.trim();
  if (isProhibitedTarget(trimmed)) {
    return err(`Prohibited target IP: '${trimmed}' is blacklisted (SEC-INV-08 cloud metadata/loopback protection).`);
  }
  if (!IPV4_REGEX.test(trimmed)) {
    return err(`Invalid IPv4 address format: '${trimmed}'`);
  }
  return ok(trimmed as IPv4Address);
}

export function parseIPv6(ip: string): Result<IPv6Address, string> {
  const trimmed = ip.trim();
  if (isProhibitedTarget(trimmed)) {
    return err(`Prohibited target IPv6: '${trimmed}' is blacklisted (SEC-INV-08 loopback protection).`);
  }
  if (!IPV6_REGEX.test(trimmed)) {
    return err(`Invalid IPv6 address format: '${trimmed}'`);
  }
  return ok(trimmed as IPv6Address);
}

export function parseCidr(cidr: string): Result<CidrBlock, string> {
  const trimmed = cidr.trim();
  const parts = trimmed.split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return err(`Invalid CIDR format: '${trimmed}', expected 'ip/mask'`);
  }

  const [ipPart, maskStr] = parts;
  const mask = parseInt(maskStr, 10);

  if (isNaN(mask) || mask < 0 || mask > 32) {
    return err(`Invalid CIDR subnet mask: '/${maskStr}', must be integer 0..32`);
  }

  const ipResult = parseIPv4(ipPart);
  if (ipResult.isErr) {
    return err(ipResult.error);
  }

  return ok(trimmed as CidrBlock);
}

export function parsePort(port: number): Result<Port, string> {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return err(`Invalid TCP/UDP port: ${port}, must be integer 1..65535`);
  }
  return ok(port as Port);
}

export function parsePortRange(start: number, end: number): Result<PortRange, string> {
  const startRes = parsePort(start);
  if (startRes.isErr) return err(startRes.error);

  const endRes = parsePort(end);
  if (endRes.isErr) return err(endRes.error);

  if (start > end) {
    return err(`Invalid port range: start (${start}) cannot exceed end (${end})`);
  }

  return ok({ start: startRes.value, end: endRes.value });
}

export function parseHostname(host: string): Result<Hostname, string> {
  const trimmed = host.trim().toLowerCase();
  if (isProhibitedTarget(trimmed)) {
    return err(`Prohibited target hostname: '${trimmed}' is blacklisted (SEC-INV-08 cloud metadata protection).`);
  }
  if (!HOSTNAME_REGEX.test(trimmed)) {
    return err(`Invalid FQDN hostname: '${trimmed}'`);
  }
  return ok(trimmed as Hostname);
}
