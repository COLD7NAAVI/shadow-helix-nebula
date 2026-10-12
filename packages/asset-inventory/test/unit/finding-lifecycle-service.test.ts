/**
 * Shadow : Helix Nebula (SHN) — Finding Lifecycle Service Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createAssetId,
  createUserId,
  createFindingId,
} from '@shn/shared-kernel';
import { FindingLifecycleService } from '../../dist/index.js';
import type { FindingRepository, FindingRecord, FindingStatusTransitionRecord } from '@shn/data-access';

function createMockFindingRepo(): {
  repo: FindingRepository;
  findings: Map<string, FindingRecord>;
  transitions: FindingStatusTransitionRecord[];
} {
  const findings = new Map<string, FindingRecord>();
  const transitions: FindingStatusTransitionRecord[] = [];

  const repo: Partial<FindingRepository> = {
    async createFinding(params: any): Promise<FindingRecord> {
      const record: FindingRecord = {
        id: params.id,
        workspaceId: params.workspaceId,
        organizationId: params.organizationId,
        assetId: params.assetId,
        executionId: params.executionId ?? null,
        title: params.title,
        description: params.description,
        category: params.category,
        severity: params.severity,
        cve_id: params.cve_id ?? null,
        cwe_id: params.cwe_id ?? null,
        cvssScore: params.cvssScore ?? null,
        cvssVector: params.cvssVector ?? null,
        status: params.status ?? 'DRAFT',
        rawEvidenceSha256: params.rawEvidenceSha256,
        evidenceArtifactId: params.evidenceArtifactId ?? null,
        remediationGuidance: params.remediationGuidance ?? null,
        metadata: params.metadata ?? {},
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      findings.set(params.id, record);
      return record;
    },

    async findById(id: string, workspaceId: string): Promise<FindingRecord | null> {
      const rec = findings.get(id);
      if (!rec || rec.workspaceId !== workspaceId) return null;
      return rec;
    },

    async transitionStatus(params: any): Promise<FindingRecord | null> {
      const rec = findings.get(params.findingId);
      if (!rec || rec.workspaceId !== params.workspaceId) return null;
      const fromStatus = rec.status;
      rec.status = params.toStatus;
      rec.updatedAt = new Date();
      transitions.push({
        id: generateUUIDv7(),
        findingId: params.findingId,
        workspaceId: params.workspaceId,
        fromStatus,
        toStatus: params.toStatus,
        changedBy: params.changedBy,
        reason: params.reason ?? null,
        createdAt: new Date(),
      });
      return rec;
    },

    async listStatusTransitions(findingId: string, workspaceId: string): Promise<FindingStatusTransitionRecord[]> {
      return transitions.filter((t) => t.findingId === findingId && t.workspaceId === workspaceId);
    },

    async listFindings(workspaceId: string): Promise<FindingRecord[]> {
      return Array.from(findings.values()).filter((f) => f.workspaceId === workspaceId);
    },
  };

  return { repo: repo as FindingRepository, findings, transitions };
}

describe('FindingLifecycleService (Unit Tests)', () => {
  const orgId = createOrganizationId(generateUUIDv7()).value;
  const workspaceId = createWorkspaceId(generateUUIDv7()).value;
  const assetId = createAssetId(generateUUIDv7()).value;
  const userId = createUserId(generateUUIDv7()).value;
  const validSha = 'a'.repeat(64);

  it('should enforce mandatory raw evidence SHA-256 hash (INV-05)', async () => {
    const { repo } = createMockFindingRepo();
    const service = new FindingLifecycleService({ findingRepository: repo });

    // Missing evidence hash
    const resNoSha = await service.recordFinding({
      workspaceId,
      organizationId: orgId,
      assetId,
      title: 'Vulnerability without evidence',
      description: 'Test',
      category: 'MISCONFIG',
      severity: 'HIGH',
      rawEvidenceSha256: '',
    });
    assert.strictEqual(resNoSha.isErr, true);
    if (resNoSha.isErr) {
      assert.strictEqual(resNoSha.error.error_code, 'ERR_FINDING_EVIDENCE_HASH_INVALID');
      assert.strictEqual(resNoSha.error.status, 400);
    }

    // Invalid non-hex hash
    const resBadSha = await service.recordFinding({
      workspaceId,
      organizationId: orgId,
      assetId,
      title: 'Bad hash',
      description: 'Test',
      category: 'MISCONFIG',
      severity: 'HIGH',
      rawEvidenceSha256: 'not-a-valid-sha256-hash',
    });
    assert.strictEqual(resBadSha.isErr, true);
  });

  it('should validate CVSS score range (0.0 .. 10.0)', async () => {
    const { repo } = createMockFindingRepo();
    const service = new FindingLifecycleService({ findingRepository: repo });

    const resOver = await service.recordFinding({
      workspaceId,
      organizationId: orgId,
      assetId,
      title: 'CVSS Out of range',
      description: 'Test',
      category: 'MISCONFIG',
      severity: 'CRITICAL',
      rawEvidenceSha256: validSha,
      cvssScore: 11.5,
    });
    assert.strictEqual(resOver.isErr, true);
    if (resOver.isErr) {
      assert.strictEqual(resOver.error.error_code, 'ERR_FINDING_CVSS_INVALID');
    }
  });

  it('should enforce formal state machine transitions and audit trail (MOD-INV-04)', async () => {
    const { repo } = createMockFindingRepo();
    const service = new FindingLifecycleService({ findingRepository: repo });

    const recRes = await service.recordFinding({
      workspaceId,
      organizationId: orgId,
      assetId,
      title: 'SQL Injection in /api/v1/search',
      description: 'Parameter id vulnerable to SQLi',
      category: 'INJECTION',
      severity: 'CRITICAL',
      cvssScore: 9.8,
      rawEvidenceSha256: validSha,
    });
    assert.strictEqual(recRes.isOk, true);
    if (!recRes.isOk) return;
    const created = recRes.value;

    assert.strictEqual(created.status, 'DRAFT');

    // 1. Illegal transition: DRAFT -> REMEDIATED (should fail closed)
    const illegalTrans = await service.transitionStatus({
      findingId: created.id,
      workspaceId,
      toStatus: 'REMEDIATED',
      changedBy: userId,
    });
    assert.strictEqual(illegalTrans.isErr, true);
    if (illegalTrans.isErr) {
      assert.strictEqual(illegalTrans.error.error_code, 'ERR_FINDING_INVALID_STATE_TRANSITION');
      assert.strictEqual(illegalTrans.error.status, 409);
    }

    // 2. Legal transition: DRAFT -> UNDER_REVIEW
    const reviewTrans = await service.transitionStatus({
      findingId: created.id,
      workspaceId,
      toStatus: 'UNDER_REVIEW',
      changedBy: userId,
      reason: 'Assigned to security engineer for verification',
    });
    assert.strictEqual(reviewTrans.isOk, true);
    if (reviewTrans.isOk) {
      assert.strictEqual(reviewTrans.value.status, 'UNDER_REVIEW');
    }

    // 3. Legal transition: UNDER_REVIEW -> CONFIRMED
    const confirmTrans = await service.transitionStatus({
      findingId: created.id,
      workspaceId,
      toStatus: 'CONFIRMED',
      changedBy: userId,
      reason: 'Exploit verified in staging replica',
    });
    assert.strictEqual(confirmTrans.isOk, true);

    // 4. Verify audit history
    const historyRes = await service.getStatusHistory(created.id, workspaceId);
    assert.strictEqual(historyRes.isOk, true);
    if (historyRes.isOk) {
      assert.strictEqual(historyRes.value.length, 2);
      assert.strictEqual(historyRes.value[0].fromStatus, 'DRAFT');
      assert.strictEqual(historyRes.value[0].toStatus, 'UNDER_REVIEW');
      assert.strictEqual(historyRes.value[1].fromStatus, 'UNDER_REVIEW');
      assert.strictEqual(historyRes.value[1].toStatus, 'CONFIRMED');
    }
  });
});
