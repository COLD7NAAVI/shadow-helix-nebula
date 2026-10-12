/**
 * Shadow : Helix Nebula (SHN) — Asset Inventory Service Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createAssetId,
} from '@shn/shared-kernel';
import { AssetInventoryService } from '../../dist/index.js';
import type { AssetRepository, AssetRecord } from '@shn/data-access';

function createMockAssetRepo(): {
  repo: AssetRepository;
  records: Map<string, AssetRecord>;
} {
  const records = new Map<string, AssetRecord>();

  const repo: Partial<AssetRepository> = {
    async createAsset(params: any): Promise<AssetRecord> {
      const key = `${params.workspaceId}:${params.type}:${params.canonicalValue}`;
      for (const rec of records.values()) {
        if (rec.workspaceId === params.workspaceId && rec.type === params.type && rec.canonicalValue === params.canonicalValue) {
          const err: any = new Error('duplicate key value');
          err.code = '23505';
          throw err;
        }
      }
      const record: AssetRecord = {
        id: params.id,
        workspaceId: params.workspaceId,
        organizationId: params.organizationId,
        type: params.type,
        canonicalValue: params.canonicalValue,
        name: params.name,
        criticality: params.criticality,
        status: params.status,
        tags: params.tags,
        metadata: params.metadata,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      records.set(params.id, record);
      return record;
    },

    async findById(id: string, workspaceId: string): Promise<AssetRecord | null> {
      const rec = records.get(id);
      if (!rec || rec.workspaceId !== workspaceId) return null;
      return rec;
    },

    async findByCanonicalValue(workspaceId: string, type: any, canonicalValue: string): Promise<AssetRecord | null> {
      for (const rec of records.values()) {
        if (rec.workspaceId === workspaceId && rec.type === type && rec.canonicalValue === canonicalValue) {
          return rec;
        }
      }
      return null;
    },

    async updateAsset(id: string, workspaceId: string, params: any): Promise<AssetRecord | null> {
      const rec = records.get(id);
      if (!rec || rec.workspaceId !== workspaceId) return null;
      if (params.name) rec.name = params.name;
      if (params.criticality) rec.criticality = params.criticality;
      if (params.status) rec.status = params.status;
      if (params.tags) rec.tags = params.tags;
      if (params.metadata) rec.metadata = params.metadata;
      rec.updatedAt = new Date();
      return rec;
    },

    async listAssets(workspaceId: string, options?: any): Promise<AssetRecord[]> {
      const result: AssetRecord[] = [];
      for (const rec of records.values()) {
        if (rec.workspaceId !== workspaceId) continue;
        if (options?.type && rec.type !== options.type) continue;
        if (options?.status && rec.status !== options.status) continue;
        result.push(rec);
      }
      return result;
    },
  };

  return { repo: repo as AssetRepository, records };
}

describe('AssetInventoryService (Unit Tests)', () => {
  const orgId = createOrganizationId(generateUUIDv7()).value;
  const workspaceId = createWorkspaceId(generateUUIDv7()).value;

  it('should auto-detect and register an asset with canonicalization', async () => {
    const { repo } = createMockAssetRepo();
    const service = new AssetInventoryService({ assetRepository: repo });

    const result = await service.registerAsset({
      workspaceId,
      organizationId: orgId,
      rawTarget: '  192.168.01.01  ',
      criticality: 'HIGH',
    });

    assert.strictEqual(result.isOk, true);
    if (result.isOk) {
      assert.strictEqual(result.value.type, 'IPV4');
      assert.strictEqual(result.value.canonicalValue, '192.168.1.1');
      assert.strictEqual(result.value.criticality, 'HIGH');
    }
  });

  it('should reject invalid target format with RFC 7807 problem details', async () => {
    const { repo } = createMockAssetRepo();
    const service = new AssetInventoryService({ assetRepository: repo });

    const result = await service.registerAsset({
      workspaceId,
      organizationId: orgId,
      rawTarget: 'ftp://unsupported.service/resource',
      type: 'URL',
    });

    assert.strictEqual(result.isErr, true);
    if (result.isErr) {
      assert.strictEqual(result.error.status, 422);
      assert.strictEqual(result.error.error_code, 'ERR_ASSET_VALIDATION_FAILED');
    }
  });

  it('should reject duplicate asset within same workspace with 409 Conflict', async () => {
    const { repo } = createMockAssetRepo();
    const service = new AssetInventoryService({ assetRepository: repo });

    await service.registerAsset({
      workspaceId,
      organizationId: orgId,
      rawTarget: 'api.corp.internal',
      type: 'FQDN',
    });

    const dupResult = await service.registerAsset({
      workspaceId,
      organizationId: orgId,
      rawTarget: 'api.corp.internal',
      type: 'FQDN',
    });

    assert.strictEqual(dupResult.isErr, true);
    if (dupResult.isErr) {
      assert.strictEqual(dupResult.error.status, 409);
      assert.strictEqual(dupResult.error.error_code, 'ERR_ASSET_ALREADY_EXISTS');
    }
  });

  it('should retrieve asset by ID and canonical value and enforce tenant boundaries', async () => {
    const { repo } = createMockAssetRepo();
    const service = new AssetInventoryService({ assetRepository: repo });
    const foreignWks = createWorkspaceId(generateUUIDv7()).value;

    const regRes = await service.registerAsset({
      workspaceId,
      organizationId: orgId,
      rawTarget: '10.0.0.10',
    });
    assert.strictEqual(regRes.isOk, true);
    if (!regRes.isOk) return;
    const registered = regRes.value;

    const retrieved = await service.getAsset(registered.id, workspaceId);
    assert.strictEqual(retrieved.isOk, true);

    // Cross-workspace query should fail closed
    const crossRetrieved = await service.getAsset(registered.id, foreignWks);
    assert.strictEqual(crossRetrieved.isErr, true);
    if (crossRetrieved.isErr) {
      assert.strictEqual(crossRetrieved.error.status, 404);
    }
  });
});
