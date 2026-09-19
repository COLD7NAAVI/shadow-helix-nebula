/**
 * Shadow : Helix Nebula (SHN) — Timestamp Primitives
 *
 * Enforces ISO 8601 UTC format across all audit trails and events.
 */

import { ok, err, type Result } from '../result/result.js';

export type IsoTimestamp = string & { readonly __brand: 'IsoTimestamp' };

const ISO_TIMESTAMP_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

export function nowIso(): IsoTimestamp {
  return new Date().toISOString() as IsoTimestamp;
}

export function parseIsoTimestamp(iso: string): Result<IsoTimestamp, string> {
  const trimmed = iso.trim();
  if (!ISO_TIMESTAMP_REGEX.test(trimmed)) {
    return err(`Invalid ISO timestamp: '${trimmed}', must be UTC format YYYY-MM-DDTHH:mm:ss.sssZ`);
  }
  const date = new Date(trimmed);
  if (isNaN(date.getTime())) {
    return err(`Invalid calendar date in timestamp: '${trimmed}'`);
  }
  return ok(trimmed as IsoTimestamp);
}
