/**
 * Shadow : Helix Nebula (SHN) — Operational Health & Metrics Controller
 *
 * Authoritative Spec: Phase 0.14 Section 25.
 * Exposes liveness, readiness, and OpenTelemetry / Prometheus diagnostic probes.
 */

import type { DatabasePool } from '@shn/data-access';
import type { IngressRequest, IngressResponse } from '../contracts.js';

export interface HealthControllerOptions {
  pool?: DatabasePool | undefined;
}

export class HealthController {
  private readonly pool?: DatabasePool | undefined;

  constructor(options?: HealthControllerOptions) {
    this.pool = options?.pool;
  }

  async getLiveness(_req: IngressRequest, res: IngressResponse): Promise<void> {
    res.status(200).json({
      status: 'UP',
      component: 'shn-ingress-gateway',
      timestamp: new Date().toISOString(),
    });
  }

  async getReadiness(_req: IngressRequest, res: IngressResponse): Promise<void> {
    let dbStatus = 'UNKNOWN';
    let isReady = true;

    if (this.pool) {
      try {
        await this.pool.query('SELECT 1;');
        dbStatus = 'UP';
      } catch {
        dbStatus = 'DOWN';
        isReady = false;
      }
    } else {
      dbStatus = 'NOT_CONFIGURED';
    }

    const statusCode = isReady ? 200 : 503;
    res.status(statusCode).json({
      status: isReady ? 'UP' : 'DOWN',
      checks: {
        database: dbStatus,
        gateway: 'UP',
      },
      timestamp: new Date().toISOString(),
    });
  }

  async getMetrics(_req: IngressRequest, res: IngressResponse): Promise<void> {
    const memory = process.memoryUsage();
    const metricsText = [
      '# HELP process_resident_memory_bytes Resident memory size in bytes.',
      '# TYPE process_resident_memory_bytes gauge',
      `process_resident_memory_bytes ${memory.rss}`,
      '# HELP process_heap_used_bytes Process heap used size in bytes.',
      '# TYPE process_heap_used_bytes gauge',
      `process_heap_used_bytes ${memory.heapUsed}`,
      '# HELP shn_gateway_up Status of SHN gateway.',
      '# TYPE shn_gateway_up gauge',
      'shn_gateway_up 1',
    ].join('\n') + '\n';

    res.text(metricsText, 'text/plain; version=0.0.4; charset=utf-8');
  }
}
