/**
 * Shadow : Helix Nebula (SHN) — Prometheus Metrics Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createMeter,
  createStandardPlatformMetrics,
} from '../../dist/index.js';

describe('Prometheus Metrics & Cardinality Protection (Pure Unit Tests)', () => {
  it('should record Counter increments and serialize to Prometheus format', () => {
    const meter = createMeter();
    const counter = meter.createCounter('shn_test_counter_total', 'Test counter description');

    counter.inc({ status: 'ok' });
    counter.add(4, { status: 'ok' });
    counter.inc({ status: 'error' });

    assert.equal(counter.getValue({ status: 'ok' }), 5);
    assert.equal(counter.getValue({ status: 'error' }), 1);

    const promOutput = meter.exportPrometheus();
    assert.ok(promOutput.includes('# HELP shn_test_counter_total Test counter description'));
    assert.ok(promOutput.includes('# TYPE shn_test_counter_total counter'));
    assert.ok(promOutput.includes('shn_test_counter_total{status="ok"} 5'));
    assert.ok(promOutput.includes('shn_test_counter_total{status="error"} 1'));
  });

  it('should record Gauge values, increments, and decrements', () => {
    const meter = createMeter();
    const gauge = meter.createGauge('shn_active_workers', 'Active worker count');

    gauge.set(10);
    assert.equal(gauge.getValue(), 10);

    gauge.inc(2);
    assert.equal(gauge.getValue(), 12);

    gauge.dec(5);
    assert.equal(gauge.getValue(), 7);

    const promOutput = meter.exportPrometheus();
    assert.ok(promOutput.includes('shn_active_workers 7'));
  });

  it('should record Histogram distributions and calculate bucket counts, sum, and count', () => {
    const meter = createMeter();
    const hist = meter.createHistogram('shn_request_duration_seconds', [0.1, 0.5, 1.0], 'Request latency');

    hist.record(0.05);
    hist.record(0.2);
    hist.record(0.8);
    hist.record(2.5);

    const snapshot = hist.getSnapshot();
    assert.equal(snapshot.count, 4);
    assert.equal(snapshot.sum, 3.55);
    assert.equal(snapshot.buckets.get(0.1), 1); // 0.05
    assert.equal(snapshot.buckets.get(0.5), 2); // 0.05, 0.2
    assert.equal(snapshot.buckets.get(1.0), 3); // 0.05, 0.2, 0.8

    const promOutput = meter.exportPrometheus();
    assert.ok(promOutput.includes('shn_request_duration_seconds_bucket{le="0.1"} 1'));
    assert.ok(promOutput.includes('shn_request_duration_seconds_bucket{le="0.5"} 2'));
    assert.ok(promOutput.includes('shn_request_duration_seconds_bucket{le="1"} 3'));
    assert.ok(promOutput.includes('shn_request_duration_seconds_bucket{le="+Inf"} 4'));
    assert.ok(promOutput.includes('shn_request_duration_seconds_sum 3.55'));
    assert.ok(promOutput.includes('shn_request_duration_seconds_count 4'));
  });

  it('should bound label cardinality to prevent memory leaks and cardinality explosion', () => {
    const meter = createMeter();
    const counter = meter.createCounter('shn_adversarial_counter');

    // Attempt to register 70 distinct label values (cap is 50)
    for (let i = 0; i < 70; i++) {
      counter.inc({ tenantId: `tenant-${i}` });
    }

    // Label values beyond 50 should be grouped into 'other'
    const otherValue = counter.getValue({ tenantId: 'other' });
    assert.equal(otherValue, 20); // 70 - 50 = 20
  });

  it('should instantiate the complete standard platform metrics suite', () => {
    const meter = createMeter();
    const suite = createStandardPlatformMetrics(meter);

    assert.ok(suite.eventsPublishedTotal);
    assert.ok(suite.eventsClaimedTotal);
    assert.ok(suite.eventsDispatchedTotal);
    assert.ok(suite.eventsRetriedTotal);
    assert.ok(suite.eventsDeadLetterTotal);
    assert.ok(suite.outboxPendingDepth);
    assert.ok(suite.outboxOldestAgeSeconds);
    assert.ok(suite.dispatchDurationSeconds);
    assert.ok(suite.handlerDurationSeconds);
    assert.ok(suite.workerConcurrencyActive);
    assert.ok(suite.databaseHealthStatus);
  });
});
