/**
 * Shadow : Helix Nebula (SHN) — Capability Repository Integration Tests
 *
 * Validates Migration 006 schema, CapabilityRepository CRUD, lifecycle transitions,
 * adapter registration, workspace bindings, and multi-tenant hermeticity (INV-01, DATA-INV-08).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  type WorkspaceId,
  type OrganizationId,
} from '@shn/shared-kernel';
import {
  runMigrations,
  closeDatabasePool,
  type DatabasePool,
  OrganizationRepository,
  WorkspaceRepository,
  CapabilityRepository,
} from '../../dist/index.js';
import { createTestPool, resetDatabase, ensureDatabase } from '../test-helper.ts';

describe('CapabilityRepository & Tool Adapter Persistence (Integration)', () => {
  let pool: DatabasePool;
  let orgRepo: OrganizationRepository;
  let workspaceRepo: WorkspaceRepository;
  let capabilityRepo: CapabilityRepository;

  let testOrgId: OrganizationId;
  let testWorkspaceId: WorkspaceId;
  let testWorkspaceId2: WorkspaceId;

  before(async () => {
    await ensureDatabase('shn_test_capability_repo');
    pool = createTestPool('shn_test_capability_repo');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);

    orgRepo = new OrganizationRepository(pool);
    workspaceRepo = new WorkspaceRepository(pool);
    capabilityRepo = new CapabilityRepository(pool);

    testOrgId = createOrganizationId(generateUUIDv7()).value;
    testWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
    testWorkspaceId2 = createWorkspaceId(generateUUIDv7()).value;

    await orgRepo.create({
      id: testOrgId,
      name: 'Capability Test Org',
      slug: `cap-org-${Date.now()}`,
    });

    await workspaceRepo.create({
      id: testWorkspaceId,
      organization_id: testOrgId,
      name: 'Primary Workspace',
      slug: `wks-1-${Date.now()}`,
    });

    await workspaceRepo.create({
      id: testWorkspaceId2,
      organization_id: testOrgId,
      name: 'Secondary Workspace',
      slug: `wks-2-${Date.now()}`,
    });
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  it('should register a system-wide capability and retrieve it by ID', async () => {
    const capId = 'shn://capabilities/network/port-scan';
    const record = await capabilityRepo.registerCapability({
      id: capId,
      name: 'network.port-scan',
      version: '1.0.0',
      displayName: 'Network TCP/UDP Port Scanner',
      description: 'Abstract network port scan capability supporting TCP syn and connect scans',
      category: 'RECONNAISSANCE',
      riskLevel: 'LOW',
      supportedTargets: ['IP', 'CIDR', 'HOSTNAME'],
      requiredPermissions: 1, // READ
      requiredScopeAction: 'SCAN_TCP_PORT',
      integrityDigest: 'a'.repeat(64),
    });

    assert.equal(record.id, capId);
    assert.equal(record.workspaceId, null);
    assert.equal(record.lifecycleState, 'ACTIVE');

    const fetched = await capabilityRepo.findCapabilityById(capId);
    assert.ok(fetched);
    assert.equal(fetched.id, capId);
    assert.equal(fetched.name, 'network.port-scan');
  });

  it('should register a workspace-scoped capability override taking precedence for that workspace', async () => {
    const capId = 'shn://capabilities/network/port-scan';
    const wsRecord = await capabilityRepo.registerCapability({
      id: capId,
      workspaceId: testWorkspaceId,
      name: 'network.port-scan',
      version: '1.1.0',
      displayName: 'Custom Workspace Port Scanner',
      description: 'Workspace-tuned custom port scan settings',
      category: 'RECONNAISSANCE',
      riskLevel: 'LOW',
      supportedTargets: ['IP', 'CIDR'],
      requiredPermissions: 1,
      requiredScopeAction: 'SCAN_TCP_PORT',
      integrityDigest: 'b'.repeat(64),
    });

    assert.equal(wsRecord.workspaceId, testWorkspaceId);
    assert.equal(wsRecord.version, '1.1.0');

    // Querying with testWorkspaceId gets the workspace override
    const fetchedWs = await capabilityRepo.findCapabilityById(capId, testWorkspaceId);
    assert.ok(fetchedWs);
    assert.equal(fetchedWs.workspaceId, testWorkspaceId);
    assert.equal(fetchedWs.displayName, 'Custom Workspace Port Scanner');

    // Querying with testWorkspaceId2 falls back to system capability
    const fetchedWs2 = await capabilityRepo.findCapabilityById(capId, testWorkspaceId2);
    assert.ok(fetchedWs2);
    assert.equal(fetchedWs2.workspaceId, null);
    assert.equal(fetchedWs2.displayName, 'Network TCP/UDP Port Scanner');
  });

  it('should list capabilities with filtering by category and lifecycle state', async () => {
    await capabilityRepo.registerCapability({
      id: 'shn://capabilities/web/http-discovery',
      name: 'web.http-discovery',
      version: '1.0.0',
      displayName: 'HTTP Service & Header Discovery',
      description: 'Discovers web application servers, TLS certificates, and headers',
      category: 'DISCOVERY',
      riskLevel: 'INFORMATIONAL',
      supportedTargets: ['URL', 'HOSTNAME'],
      requiredPermissions: 1,
      requiredScopeAction: 'HTTP_GET',
      integrityDigest: 'c'.repeat(64),
    });

    const reconList = await capabilityRepo.listCapabilities({ category: 'RECONNAISSANCE' });
    assert.ok(reconList.length >= 1);
    assert.ok(reconList.every(c => c.category === 'RECONNAISSANCE'));

    const discoveryList = await capabilityRepo.listCapabilities({ category: 'DISCOVERY' });
    assert.ok(discoveryList.length >= 1);
    assert.ok(discoveryList.every(c => c.category === 'DISCOVERY'));
  });

  it('should update capability lifecycle state deterministically', async () => {
    const capId = 'shn://capabilities/web/http-discovery';
    const updated = await capabilityRepo.updateCapabilityLifecycle(capId, 'DEPRECATED');
    assert.equal(updated, true);

    const fetched = await capabilityRepo.findCapabilityById(capId);
    assert.ok(fetched);
    assert.equal(fetched.lifecycleState, 'DEPRECATED');
  });

  it('should register tool adapter and retrieve it by ID', async () => {
    const adapterId = 'adapter:nmap-cli';
    const record = await capabilityRepo.registerAdapter({
      id: adapterId,
      name: 'nmap-cli',
      version: '7.94.0',
      binaryPath: '/usr/bin/nmap',
      manifestDigest: 'd'.repeat(64),
      supportedCapabilities: [
        { capabilityId: 'shn://capabilities/network/port-scan', versionConstraint: '^1.0.0' },
      ],
      platformCompatibility: ['linux', 'darwin', 'win32'],
    });

    assert.equal(record.id, adapterId);
    assert.equal(record.lifecycleState, 'REGISTERED');

    const fetched = await capabilityRepo.findAdapterById(adapterId);
    assert.ok(fetched);
    assert.equal(fetched.id, adapterId);
    assert.equal(fetched.binaryPath, '/usr/bin/nmap');
  });

  it('should list adapters filtering by supported capabilityId', async () => {
    const list = await capabilityRepo.listAdapters({
      capabilityId: 'shn://capabilities/network/port-scan',
    });
    assert.ok(list.length >= 1);
    assert.ok(list.some(a => a.id === 'adapter:nmap-cli'));
  });

  it('should update adapter lifecycle state', async () => {
    const adapterId = 'adapter:nmap-cli';
    const updated = await capabilityRepo.updateAdapterLifecycle(adapterId, 'ENABLED');
    assert.equal(updated, true);

    const fetched = await capabilityRepo.findAdapterById(adapterId);
    assert.ok(fetched);
    assert.equal(fetched.lifecycleState, 'ENABLED');
  });

  it('should set and retrieve workspace capability bindings with overrides', async () => {
    const capId = 'shn://capabilities/network/port-scan';
    const adapterId = 'adapter:nmap-cli';

    await capabilityRepo.setWorkspaceBinding(
      testWorkspaceId,
      capId,
      adapterId,
      true,
      { maxRate: 1000, timingProfile: 4 }
    );

    const binding = await capabilityRepo.getWorkspaceBinding(testWorkspaceId, capId);
    assert.ok(binding);
    assert.equal(binding.workspaceId, testWorkspaceId);
    assert.equal(binding.capabilityId, capId);
    assert.equal(binding.preferredAdapterId, adapterId);
    assert.equal(binding.isEnabled, true);
    assert.equal((binding.overrides as any).maxRate, 1000);

    // Other workspace has no binding
    const otherBinding = await capabilityRepo.getWorkspaceBinding(testWorkspaceId2, capId);
    assert.equal(otherBinding, null);
  });
});
