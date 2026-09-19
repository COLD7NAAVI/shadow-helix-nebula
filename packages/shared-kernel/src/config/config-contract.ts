/**
 * Shadow : Helix Nebula (SHN) — Platform Configuration Contract
 *
 * Enforces INV-09: Abstract configuration boundaries decoupled from concrete infrastructure environments.
 */

export interface DatabaseConfigContract {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly maxConnections: number;
  readonly idleTimeoutMs: number;
  readonly ssl: boolean;
}

export interface RedisConfigContract {
  readonly host: string;
  readonly port: number;
  readonly dbIndex: number;
  readonly maxRetries: number;
}

export interface SecurityConfigContract {
  readonly jwtIssuer: string;
  readonly tokenTtlSeconds: number;
  readonly masterKeyId: string;
}

export interface TelemetryConfigContract {
  readonly serviceName: string;
  readonly environment: 'development' | 'testing' | 'staging' | 'production';
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Master Platform Configuration Boundary.
 * Defines the required configuration contract without binding to environment variables.
 */
export interface PlatformConfigContract {
  readonly database: DatabaseConfigContract;
  readonly redis: RedisConfigContract;
  readonly security: SecurityConfigContract;
  readonly telemetry: TelemetryConfigContract;
}
