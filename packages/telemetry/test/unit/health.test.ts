/**
 * Shadow : Helix Nebula (SHN) — Operational Health & Diagnostics Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHealthRegistry } from '../../dist/index.js';

describe('Operational Health & Diagnostics (Pure Unit Tests)', () => {
  it('should evaluate and aggregate UP component health for liveness and readiness', async () => {
    const registry = createHealthRegistry();

    registry.registerLiveness('memory', async () => ({
      status: 'UP',
      details: { heapUsedMb: 120 },
      checkedAt: new Date().toISOString(),
    }));

    registry.registerReadiness('database', async () => ({
      status: 'UP',
      details: { poolAvailable: 8 },
      checkedAt: new Date().toISOString(),
    }));

    const liveness = await registry.checkLiveness();
    assert.equal(liveness.status, 'UP');
    assert.equal(liveness.totalChecked, 1);
    assert.equal(liveness.components['memory']?.status, 'UP');

    const readiness = await registry.checkReadiness();
    assert.equal(readiness.status, 'UP');
    assert.equal(readiness.totalChecked, 1);
    assert.equal(readiness.components['database']?.status, 'UP');
  });

  it('should aggregate overall DOWN status if any readiness probe fails', async () => {
    const registry = createHealthRegistry();

    registry.registerReadiness('healthy-service', async () => ({
      status: 'UP',
      checkedAt: new Date().toISOString(),
    }));

    registry.registerReadiness('failing-dependency', async () => ({
      status: 'DOWN',
      message: 'Connection refused on socket',
      checkedAt: new Date().toISOString(),
    }));

    const report = await registry.checkReadiness();
    assert.equal(report.status, 'DOWN');
    assert.equal(report.components['healthy-service']?.status, 'UP');
    assert.equal(report.components['failing-dependency']?.status, 'DOWN');
  });

  it('should mask thrown exceptions and redact sensitive credentials in error messages', async () => {
    const registry = createHealthRegistry();

    registry.registerReadiness('leaky-component', async () => {
      throw new Error('Postgres error connecting to postgres://admin:SuperSecretPass!@10.0.0.5:5432/db');
    });

    const report = await registry.checkReadiness();
    assert.equal(report.status, 'DOWN');

    const comp = report.components['leaky-component']!;
    assert.equal(comp.status, 'DOWN');
    assert.ok(comp.message);
    assert.ok(!comp.message.includes('SuperSecretPass!'));
    assert.ok(comp.message.includes('postgres://admin:[REDACTED]@10.0.0.5:5432/db'));
  });

  it('should handle timeout when a health check hangs', async () => {
    const registry = createHealthRegistry();

    registry.registerLiveness('hanging-probe', async () => {
      await new Promise(resolve => setTimeout(resolve, 5000));
      return { status: 'UP', checkedAt: new Date().toISOString() };
    });

    const report = await registry.checkLiveness(100); // 100ms timeout
    assert.equal(report.status, 'DOWN');
    assert.ok(report.components['hanging-probe']?.message?.includes('timed out'));
  });
});
