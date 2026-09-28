/**
 * Shadow : Helix Nebula (SHN) — Security-Aware Redaction & Sanitization Engine
 *
 * Implements centralized deep redaction for credentials, tokens, private keys,
 * database URLs, and untrusted multiline content to prevent credential leakage
 * and log injection (0.11 SEC-INV-05, SEC-INV-06, 0.14 Section 25).
 */

export interface RedactionOptions {
  readonly maxDepth?: number | undefined;
  readonly maxStringLength?: number | undefined;
  readonly maxArrayLength?: number | undefined;
  readonly maxKeys?: number | undefined;
  readonly additionalSensitiveKeys?: readonly string[] | undefined;
}

const DEFAULT_SENSITIVE_KEYS = new Set<string>([
  'password',
  'passwd',
  'secret',
  'client_secret',
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'api_key',
  'apikey',
  'private_key',
  'privatekey',
  'privkey',
  'authorization',
  'cookie',
  'set-cookie',
  'connection_string',
  'database_url',
  'postgres_url',
  'db_password',
  'session_token',
  'auth_header',
  'sig',
  'signature',
  'hmac_key',
  'credential',
  'credentials',
]);

const REGEX_BEARER = /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi;
const REGEX_BASIC_AUTH = /Basic\s+[A-Za-z0-9+/=]+/gi;
const REGEX_DB_URL = /postgres(?:ql)?:\/\/([^:\s/@]+):([^/\s]+)@/gi;
const REGEX_PRIVATE_KEY = /-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]*PRIVATE KEY-----/gi;

/**
 * Checks whether a property key matches sensitive name heuristics.
 */
function isSensitiveKey(key: string, additionalKeys?: readonly string[]): boolean {
  const lower = key.toLowerCase();
  if (DEFAULT_SENSITIVE_KEYS.has(lower)) {
    return true;
  }
  if (additionalKeys) {
    for (const add of additionalKeys) {
      if (lower === add.toLowerCase()) return true;
    }
  }

  // Substring checks for compound names like "userPassword", "client_secret_key"
  for (const pattern of DEFAULT_SENSITIVE_KEYS) {
    if (lower.includes(pattern)) {
      return true;
    }
  }
  return false;
}

/**
 * Redacts known sensitive string patterns (Bearer tokens, DB URLs, Private keys).
 */
export function sanitizeString(val: string, maxLength: number = 4096): string {
  let sanitized = val
    .replace(REGEX_BEARER, 'Bearer [REDACTED]')
    .replace(REGEX_BASIC_AUTH, 'Basic [REDACTED]')
    .replace(REGEX_DB_URL, 'postgres://$1:[REDACTED]@')
    .replace(REGEX_PRIVATE_KEY, '[REDACTED_PRIVATE_KEY]');

  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength) + '...[TRUNCATED]';
  }

  return sanitized;
}

/**
 * Deeply sanitizes and redacts an arbitrary value, returning a safe clone.
 * Never mutates input values.
 */
export function redactSensitiveData(value: unknown, options?: RedactionOptions): unknown {
  const maxDepth = options?.maxDepth ?? 8;
  const maxStringLength = options?.maxStringLength ?? 4096;
  const maxArrayLength = options?.maxArrayLength ?? 100;
  const maxKeys = options?.maxKeys ?? 200;
  const additionalKeys = options?.additionalSensitiveKeys;

  const seen = new WeakSet<object>();

  function recurse(val: unknown, depth: number): unknown {
    if (val === null || val === undefined) {
      return val;
    }

    if (typeof val === 'string') {
      return sanitizeString(val, maxStringLength);
    }

    if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'symbol') {
      return val;
    }

    if (typeof val === 'bigint') {
      return val.toString();
    }

    if (typeof val === 'function') {
      return '[FUNCTION]';
    }

    if (typeof val === 'object') {
      if (depth >= maxDepth) {
        return '[MAX_DEPTH_EXCEEDED]';
      }

      if (seen.has(val)) {
        return '[CIRCULAR]';
      }
      seen.add(val);

      if (val instanceof Date) {
        return val.toISOString();
      }

      if (val instanceof RegExp) {
        return val.toString();
      }

      if (val instanceof Error) {
        const errorObj: Record<string, unknown> = {
          name: val.name,
          message: sanitizeString(val.message, maxStringLength),
        };
        if ('code' in val && val.code) {
          errorObj['code'] = val.code;
        }
        if (val.stack) {
          errorObj['stack'] = sanitizeString(val.stack, maxStringLength);
        }
        if (val.cause) {
          errorObj['cause'] = recurse(val.cause, depth + 1);
        }
        return errorObj;
      }

      if (Array.isArray(val)) {
        const length = Math.min(val.length, maxArrayLength);
        const clonedArr: unknown[] = [];
        for (let i = 0; i < length; i++) {
          clonedArr.push(recurse(val[i], depth + 1));
        }
        if (val.length > maxArrayLength) {
          clonedArr.push(`[...TRUNCATED ${val.length - maxArrayLength} ITEMS]`);
        }
        return clonedArr;
      }

      // Plain or structured object
      const clonedObj: Record<string, unknown> = {};
      const entries = Object.entries(val);
      const count = Math.min(entries.length, maxKeys);

      for (let i = 0; i < count; i++) {
        const [k, v] = entries[i]!;
        if (isSensitiveKey(k, additionalKeys)) {
          clonedObj[k] = '[REDACTED]';
        } else {
          clonedObj[k] = recurse(v, depth + 1);
        }
      }

      if (entries.length > maxKeys) {
        clonedObj['[TRUNCATED_KEYS]'] = `[MAX_KEYS_EXCEEDED: ${entries.length - maxKeys} omitted]`;
      }

      return clonedObj;
    }

    return String(val);
  }

  return recurse(value, 0);
}
