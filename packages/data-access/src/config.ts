/**
 * Shadow : Helix Nebula (SHN) — Database Configuration
 *
 * Implements the PostgreSQL configuration boundary adhering to PlatformConfigContract
 * and fail-closed validation rules (MOD-INV-01, SEC-INV-14, INV-09).
 */

import {
  type Result,
  ok,
  err,
  type DatabaseConfigContract,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
} from '@shn/error-catalog';

export interface DatabaseConfig extends DatabaseConfigContract {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly password?: string;
  readonly ssl: boolean;
  readonly maxConnections: number;
  readonly minConnections: number;
  readonly idleTimeoutMs: number;
  readonly connectionTimeoutMs: number;
}

export interface RedactedDatabaseConfig {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly hasPassword: boolean;
  readonly ssl: boolean;
  readonly maxConnections: number;
  readonly minConnections: number;
  readonly idleTimeoutMs: number;
  readonly connectionTimeoutMs: number;
}

/**
 * Redacts sensitive credentials from database configuration for safe logging/telemetry.
 */
export function redactDatabaseConfig(config: DatabaseConfig): RedactedDatabaseConfig {
  return Object.freeze({
    host: config.host,
    port: config.port,
    database: config.database,
    user: config.user,
    hasPassword: Boolean(config.password && config.password.length > 0),
    ssl: config.ssl,
    maxConnections: config.maxConnections,
    minConnections: config.minConnections,
    idleTimeoutMs: config.idleTimeoutMs,
    connectionTimeoutMs: config.connectionTimeoutMs,
  });
}

/**
 * Parses a standard PostgreSQL connection URL (e.g. postgres://user:pass@host:5432/dbname).
 */
export function parseDatabaseUrl(
  urlStr: string
): Result<Partial<Record<string, unknown>>, ProblemDetails> {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: `Invalid database connection URL protocol: "${parsed.protocol}". Expected "postgres:" or "postgresql:".`,
          instance: '/config/database/url',
          correlationId: 'system.config.validation',
          customStatus: 400,
        })
      );
    }

    const host = parsed.hostname;
    const port = parsed.port ? parseInt(parsed.port, 10) : 5432;
    const database = parsed.pathname.replace(/^\//, '');
    const user = decodeURIComponent(parsed.username || '');
    const password = parsed.password ? decodeURIComponent(parsed.password) : undefined;
    const sslMode = parsed.searchParams.get('sslmode');
    const ssl = sslMode === 'require' || sslMode === 'verify-full' || sslMode === 'verify-ca' || parsed.searchParams.get('ssl') === 'true';

    return ok({
      host: host || undefined,
      port,
      database: database || undefined,
      user: user || undefined,
      password,
      ssl,
    });
  } catch {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INTERNAL_FAULT,
        detail: `Malformed database connection URL. Secret values have been suppressed.`,
        instance: '/config/database/url',
        correlationId: 'system.config.validation',
        customStatus: 400,
      })
    );
  }
}

/**
 * Parses and validates discrete or merged database configuration parameters.
 */
export function parseDatabaseConfig(
  raw: Partial<Record<string, unknown>>
): Result<DatabaseConfig, ProblemDetails> {
  // If a connection URL was supplied in raw.url or raw.connectionString, merge it
  let merged = { ...raw };
  const rawUrl = raw.url ?? raw.connectionString;
  if (typeof rawUrl === 'string' && rawUrl.trim().length > 0) {
    const urlResult = parseDatabaseUrl(rawUrl.trim());
    if (urlResult.isErr) {
      return urlResult as Result<never, ProblemDetails>;
    }
    // Explicit discrete fields in raw take precedence over URL fields
    merged = {
      ...urlResult.value,
      ...raw,
    };
  }

  const host = typeof merged.host === 'string' && merged.host.trim().length > 0 ? merged.host.trim() : null;
  if (!host) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INTERNAL_FAULT,
        detail: 'Database host must be a non-empty string.',
        instance: '/config/database/host',
        correlationId: 'system.config.validation',
        invalidParams: [{ name: 'host', reason: 'Missing or empty host' }],
        customStatus: 400,
      })
    );
  }

  const port = typeof merged.port === 'number' && Number.isInteger(merged.port) && merged.port >= 1 && merged.port <= 65535
    ? merged.port
    : merged.port === undefined
      ? 5432
      : null;

  if (port === null) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INTERNAL_FAULT,
        detail: 'Database port must be an integer between 1 and 65535.',
        instance: '/config/database/port',
        correlationId: 'system.config.validation',
        invalidParams: [{ name: 'port', reason: 'Out of range or invalid type' }],
        customStatus: 400,
      })
    );
  }

  const database = typeof merged.database === 'string' && merged.database.trim().length > 0 ? merged.database.trim() : null;
  if (!database) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INTERNAL_FAULT,
        detail: 'Database name must be a non-empty string.',
        instance: '/config/database/database',
        correlationId: 'system.config.validation',
        invalidParams: [{ name: 'database', reason: 'Missing or empty database name' }],
        customStatus: 400,
      })
    );
  }

  const user = typeof merged.user === 'string' && merged.user.trim().length > 0 ? merged.user.trim() : null;
  if (!user) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INTERNAL_FAULT,
        detail: 'Database user must be a non-empty string.',
        instance: '/config/database/user',
        correlationId: 'system.config.validation',
        invalidParams: [{ name: 'user', reason: 'Missing or empty user' }],
        customStatus: 400,
      })
    );
  }

  const password = typeof merged.password === 'string' ? merged.password : undefined;
  const ssl = typeof merged.ssl === 'boolean' ? merged.ssl : false;

  const maxConnections = typeof merged.maxConnections === 'number' && merged.maxConnections > 0
    ? Math.floor(merged.maxConnections)
    : 20;

  const minConnections = typeof merged.minConnections === 'number' && merged.minConnections >= 0
    ? Math.floor(merged.minConnections)
    : 2;

  if (maxConnections < minConnections) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INTERNAL_FAULT,
        detail: `Database maxConnections (${maxConnections}) cannot be less than minConnections (${minConnections}).`,
        instance: '/config/database/maxConnections',
        correlationId: 'system.config.validation',
        invalidParams: [{ name: 'maxConnections', reason: 'maxConnections < minConnections' }],
        customStatus: 400,
      })
    );
  }

  const idleTimeoutMs = typeof merged.idleTimeoutMs === 'number' && merged.idleTimeoutMs >= 0
    ? merged.idleTimeoutMs
    : 10000;

  const connectionTimeoutMs = typeof merged.connectionTimeoutMs === 'number' && merged.connectionTimeoutMs >= 0
    ? merged.connectionTimeoutMs
    : 5000;

  const config: DatabaseConfig = Object.freeze({
    host,
    port,
    database,
    user,
    ...(password !== undefined ? { password } : {}),
    ssl,
    maxConnections,
    minConnections,
    idleTimeoutMs,
    connectionTimeoutMs,
  });

  return ok(config);
}

/**
 * Loads database configuration from process.env with precedence:
 * 1. SHN_DATABASE_URL / DATABASE_URL
 * 2. SHN_DB_* variables
 * 3. PG* fallback variables
 */
export function loadDatabaseConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  mode: 'development' | 'testing' | 'production' = 'production'
): Result<DatabaseConfig, ProblemDetails> {
  const url = env.SHN_DATABASE_URL || env.DATABASE_URL;
  const host = env.SHN_DB_HOST || env.PGHOST || (mode === 'testing' ? '127.0.0.1' : undefined);
  const portStr = env.SHN_DB_PORT || env.PGPORT || (mode === 'testing' ? '54329' : undefined);
  const database = env.SHN_DB_NAME || env.SHN_DB_DATABASE || env.PGDATABASE || (mode === 'testing' ? 'shn_test' : undefined);
  const user = env.SHN_DB_USER || env.PGUSER || (mode === 'testing' ? 'postgres' : undefined);
  const password = env.SHN_DB_PASSWORD || env.PGPASSWORD;
  const ssl = env.SHN_DB_SSL === 'true' || env.PGSSLMODE === 'require';

  const maxConnStr = env.SHN_DB_MAX_CONNECTIONS;
  const minConnStr = env.SHN_DB_MIN_CONNECTIONS;
  const idleTimeoutStr = env.SHN_DB_IDLE_TIMEOUT_MS;
  const connTimeoutStr = env.SHN_DB_CONNECTION_TIMEOUT_MS;

  const raw: Partial<Record<string, unknown>> = {
    url,
    host,
    port: portStr ? parseInt(portStr, 10) : undefined,
    database,
    user,
    password,
    ssl,
    maxConnections: maxConnStr ? parseInt(maxConnStr, 10) : (mode === 'testing' ? 10 : undefined),
    minConnections: minConnStr ? parseInt(minConnStr, 10) : (mode === 'testing' ? 1 : undefined),
    idleTimeoutMs: idleTimeoutStr ? parseInt(idleTimeoutStr, 10) : (mode === 'testing' ? 5000 : undefined),
    connectionTimeoutMs: connTimeoutStr ? parseInt(connTimeoutStr, 10) : (mode === 'testing' ? 5000 : undefined),
  };

  return parseDatabaseConfig(raw);
}
