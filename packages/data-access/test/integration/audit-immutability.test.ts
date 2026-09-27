import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  createCanonicalEventEnvelope,
  nowIso,
  type CanonicalEventEnvelope,
  type TraceId,
} from '@shn/shared-kernel';
import {
  runMigrations,
  OrganizationRepository,
  WorkspaceRepository,
  AuditEventRepository,
  closeDatabasePool,
  type DatabasePool,
} from '../../dist/index.js';
import {
  createTestPool,
  resetDatabase,
  validOrgId,
  validWorkspaceId,
  validEventId,
  validCorrelationId,
  validCausationId,
} from '../test-helper.ts';

describe('Append-Only Audit Event Ledger & Mechanical Immutability (Integration)', () => {
  let pool: DatabasePool;
  let auditRepo: AuditEventRepository;
  let workspaceId: ReturnType<typeof validWorkspaceId>;

  before(async () => {
    pool = createTestPool('shn_test_audit');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);

    const orgRepo = new OrganizationRepository(pool);
    const wsRepo = new WorkspaceRepository(pool);
    auditRepo = new AuditEventRepository(pool);

    const orgId = validOrgId();
    await orgRepo.create({
      id: orgId,
      name: 'Audit Security Org',
      slug: 'audit-sec-org',
    });

    workspaceId = validWorkspaceId();
    await wsRepo.create({
      id: workspaceId,
      organization_id: orgId,
      name: 'Audit Sec Workspace',
      slug: 'audit-sec-ws',
    });
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  function createSampleEnvelope(overrides?: Partial<Parameters<typeof createCanonicalEventEnvelope>[0]>): CanonicalEventEnvelope {
    const eventId = validEventId();
    const correlationId = validCorrelationId();
    const causationId = validCausationId();

    return createCanonicalEventEnvelope({
      eventId,
      eventType: 'audit.test.created',
      schemaVersion: '1.0.0',
      occurredAt: nowIso(),
      producer: {
        module_name: 'mod_test_runner',
        node_id: 'node-01',
        environment: 'testing',
        build_version: '0.1.0',
      },
      workspaceId,
      correlationId,
      causationId,
      traceId: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' as TraceId,
      authorizationContext: {
        subject_id: 'usr_01955ef2-2253-7c5e-85a7-d868924ff9cb',
        organization_id: 'org_01955ef2-2253-7c5e-85a7-d868924ff9cb',
        workspace_id: workspaceId,
        roles: ['auditor'],
        scopes: ['audit:read', 'audit:write'],
        token_id: 'tok_01955ef2-2253-7c5e-85a7-d868924ff9cb',
        issued_at: '2026-09-19T12:00:00.000000Z',
        expires_at: '2026-09-19T13:00:00.000000Z',
      },
      scopeReference: {
        scope_id: 'scp_01955ef2-2253-7c5e-85a7-d868924ff9cb',
        scope_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      payload: { action: 'test_audit_event_logged', status: 'success' },
      integrity: {
        algorithm: 'HMAC-SHA256',
        signature: 'd9b3a6c1e5f8a2b4...',
        key_id: 'key-2026-q3',
      },
      ...overrides,
    });
  }

  it('should successfully append and retrieve a Canonical Event Envelope', async () => {
    const envelope = createSampleEnvelope();
    await auditRepo.append(envelope);

    const retrieved = await auditRepo.findByEventId(envelope.event_id);
    assert.ok(retrieved !== null);
    assert.equal(retrieved.event_id, envelope.event_id);
    assert.equal(retrieved.event_type, envelope.event_type);
    assert.equal(retrieved.schema_version, envelope.schema_version);
    assert.equal(retrieved.workspace_id, envelope.workspace_id);
    assert.equal(retrieved.correlation_id, envelope.correlation_id);
    assert.equal(retrieved.causation_id, envelope.causation_id);
    assert.equal(retrieved.trace_id, envelope.trace_id);
    assert.deepEqual(retrieved.producer, envelope.producer);
    assert.deepEqual(retrieved.authorization_context, envelope.authorization_context);
    assert.deepEqual(retrieved.scope_reference, envelope.scope_reference);
    assert.deepEqual(retrieved.payload, envelope.payload);
    assert.deepEqual(retrieved.integrity, envelope.integrity);
  });

  it('should mechanically reject UPDATE operations via database trigger (SEC-INV-11, DATA-INV-07)', async () => {
    const envelope = createSampleEnvelope();
    await auditRepo.append(envelope);

    await assert.rejects(
      async () => {
        await pool.query(
          `UPDATE audit.events
           SET payload = '{"tampered": true}'::jsonb
           WHERE event_id = $1;`,
          [envelope.event_id]
        );
      },
      (error: Error) => {
        return (
          error.message.includes('Forbidden: audit.events is an append-only immutable ledger') ||
          error.message.includes('Operation UPDATE rejected')
        );
      }
    );
  });

  it('should mechanically reject DELETE operations via database trigger (SEC-INV-11, DATA-INV-07)', async () => {
    const envelope = createSampleEnvelope();
    await auditRepo.append(envelope);

    await assert.rejects(
      async () => {
        await pool.query(
          `DELETE FROM audit.events WHERE event_id = $1;`,
          [envelope.event_id]
        );
      },
      (error: Error) => {
        return (
          error.message.includes('Forbidden: audit.events is an append-only immutable ledger') ||
          error.message.includes('Operation DELETE rejected')
        );
      }
    );
  });

  it('should mechanically reject TRUNCATE operations via database trigger', async () => {
    await assert.rejects(
      async () => {
        await pool.query(`TRUNCATE TABLE audit.events;`);
      },
      (error: Error) => {
        return (
          error.message.includes('Forbidden: audit.events is an append-only immutable ledger') ||
          error.message.includes('Operation TRUNCATE rejected')
        );
      }
    );
  });

  it('should list events by workspace and correlation ID', async () => {
    const correlationId = validCorrelationId();
    const env1 = createSampleEnvelope({ correlationId });
    const env2 = createSampleEnvelope({ correlationId });

    await auditRepo.append(env1);
    await auditRepo.append(env2);

    const byCorr = await auditRepo.listByCorrelation(correlationId);
    assert.equal(byCorr.length, 2);

    const byWs = await auditRepo.listByWorkspace(workspaceId, 10);
    assert.ok(byWs.length >= 2);
  });
});
