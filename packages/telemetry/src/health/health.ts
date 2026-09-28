/**
 * Shadow : Helix Nebula (SHN) — Operational Health & Diagnostics Substrate
 *
 * Implements strict separation of liveness (/healthz) and readiness (/readyz)
 * with non-leaky error sanitization (OBS-HLT-001, 0.14 Section 25).
 */

import { nowIso } from '@shn/shared-kernel';
import { redactSensitiveData, sanitizeString } from '../redaction/redactor.js';

export type HealthStatus = 'UP' | 'DOWN' | 'DEGRADED';

export interface ComponentHealth {
  readonly status: HealthStatus;
  readonly latencyMs?: number | undefined;
  readonly message?: string | undefined;
  readonly checkedAt: string;
  readonly details?: Readonly<Record<string, unknown>> | undefined;
}

export interface CompositeHealthReport {
  readonly status: HealthStatus;
  readonly checkedAt: string;
  readonly totalChecked: number;
  readonly components: Readonly<Record<string, ComponentHealth>>;
}

export type HealthCheckFn = () => Promise<ComponentHealth>;

export interface IHealthRegistry {
  registerLiveness(name: string, check: HealthCheckFn): void;
  registerReadiness(name: string, check: HealthCheckFn): void;
  checkLiveness(timeoutMs?: number): Promise<CompositeHealthReport>;
  checkReadiness(timeoutMs?: number): Promise<CompositeHealthReport>;
}

export class HealthRegistry implements IHealthRegistry {
  private readonly livenessChecks = new Map<string, HealthCheckFn>();
  private readonly readinessChecks = new Map<string, HealthCheckFn>();

  registerLiveness(name: string, check: HealthCheckFn): void {
    if (!name || typeof name !== 'string') {
      throw new Error('Health check name must be a non-empty string');
    }
    this.livenessChecks.set(name, check);
  }

  registerReadiness(name: string, check: HealthCheckFn): void {
    if (!name || typeof name !== 'string') {
      throw new Error('Health check name must be a non-empty string');
    }
    this.readinessChecks.set(name, check);
  }

  private async executeChecks(
    checks: Map<string, HealthCheckFn>,
    timeoutMs: number = 3000
  ): Promise<CompositeHealthReport> {
    const results: Record<string, ComponentHealth> = {};
    let overallStatus: HealthStatus = 'UP';

    const checkPromises = Array.from(checks.entries()).map(async ([name, checkFn]) => {
      const start = Date.now();
      try {
        let timer: NodeJS.Timeout | undefined;
        const timeoutPromise = new Promise<ComponentHealth>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`Health check timed out after ${timeoutMs}ms`)), timeoutMs);
        });

        const health = await Promise.race([checkFn(), timeoutPromise]).finally(() => {
          if (timer) clearTimeout(timer);
        });

        const latencyMs = Date.now() - start;
        results[name] = {
          status: health.status,
          latencyMs,
          message: health.message ? sanitizeString(health.message) : undefined,
          checkedAt: nowIso(),
          details: health.details
            ? (redactSensitiveData(health.details) as Record<string, unknown>)
            : undefined,
        };

        if (health.status === 'DOWN') {
          overallStatus = 'DOWN';
        } else if (health.status === 'DEGRADED' && overallStatus !== 'DOWN') {
          overallStatus = 'DEGRADED';
        }
      } catch (error) {
        const latencyMs = Date.now() - start;
        const rawMsg = error instanceof Error ? error.message : 'Health check failed';
        // Redact any credentials or internal details
        const safeMsg = sanitizeString(rawMsg);

        results[name] = {
          status: 'DOWN',
          latencyMs,
          message: safeMsg,
          checkedAt: nowIso(),
        };
        overallStatus = 'DOWN';
      }
    });

    await Promise.all(checkPromises);

    return {
      status: overallStatus,
      checkedAt: nowIso(),
      totalChecked: checks.size,
      components: results,
    };
  }

  async checkLiveness(timeoutMs: number = 2000): Promise<CompositeHealthReport> {
    return this.executeChecks(this.livenessChecks, timeoutMs);
  }

  async checkReadiness(timeoutMs: number = 3000): Promise<CompositeHealthReport> {
    return this.executeChecks(this.readinessChecks, timeoutMs);
  }
}

export function createHealthRegistry(): IHealthRegistry {
  return new HealthRegistry();
}
