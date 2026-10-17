/**
 * Shadow : Helix Nebula (SHN) — Sovereign Platform Standalone Server
 *
 * Bootstraps Ingress Gateway, wires bounded contexts, detects PostgreSQL or
 * initializes resilient sovereign in-memory substrate, and serves Web Console.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createUserId,
  createScopeId,
  createAssetId,
  createFindingId,
  createCapabilityId,
  type OrganizationId,
  type WorkspaceId,
  type UserId,
  type ScopeId,
  type AssetId,
  type FindingId,
} from '@shn/shared-kernel';
import {
  createDatabasePool,
  runMigrations,
  type DatabasePool,
  type DatabaseConfig,
  OrganizationRepository,
  UserRepository,
  WorkspaceRepository,
  CredentialRepository,
  RoleRepository,
  AssetRepository,
  FindingRepository,
  CapabilityRepository,
  ExecutionRepository,
  ScopeRepository,
  AuditEventRepository,
} from '@shn/data-access';
import { SecurityContextSigner, PasswordHasher } from '@shn/auth-rbac';
import { ScopeGatekeeper, ScopeTokenSigner, TenancyValidator } from '@shn/scope-gatekeeper';
import { ExecutionSupervisor } from '@shn/execution-supervisor';
import {
  CapabilityRegistry,
  CapabilityDispatcher,
  NetworkPortScanAdapter,
  HttpDiscoveryAdapter,
} from '@shn/capability-registry';
import { AssetInventoryService, FindingLifecycleService } from '@shn/asset-inventory';
import { EventStreamHub } from './sse/event-stream-hub.js';
import { createIngressApplication } from './app.js';
import type { IngressServer } from './server.js';

const __filename = fileURLToPath(import.meta.url);

export interface OperatorCredentialsResult {
  readonly password: string;
  readonly isGenerated: boolean;
  readonly credentialsFile?: string | undefined;
  readonly notice: string;
}

export function resolveOperatorCredentials(
  nodeEnv = process.env.NODE_ENV || 'development',
  explicitPassword = process.env.SHN_INITIAL_ADMIN_PASSWORD
): OperatorCredentialsResult {
  if (explicitPassword && explicitPassword.trim().length > 0) {
    if (explicitPassword.length < 8) {
      throw new Error('SHN_INITIAL_ADMIN_PASSWORD must be at least 8 characters in length.');
    }
    return {
      password: explicitPassword.trim(),
      isGenerated: false,
      notice: 'Configured via SHN_INITIAL_ADMIN_PASSWORD environment variable',
    };
  }

  if (nodeEnv === 'production') {
    const credPath = path.resolve(process.cwd(), '.shn-initial-credentials');
    if (fs.existsSync(credPath)) {
      try {
        const content = fs.readFileSync(credPath, 'utf8');
        const match = content.match(/OPERATOR_PASSWORD=(.+)/);
        if (match && match[1]) {
          return {
            password: match[1].trim(),
            isGenerated: false,
            credentialsFile: credPath,
            notice: `Loaded existing master secret from secure file: ${credPath}`,
          };
        }
      } catch {
        // Fall through to regeneration
      }
    }

    const generated = crypto.randomBytes(18).toString('base64url');
    try {
      fs.writeFileSync(
        credPath,
        `# Shadow : Helix Nebula — Sovereign Operator Initial Credentials\n# Provisioned: ${new Date().toISOString()}\nOPERATOR_EMAIL=operator@shn.sovereign\nOPERATOR_PASSWORD=${generated}\n`,
        { mode: 0o600 }
      );
      return {
        password: generated,
        isGenerated: true,
        credentialsFile: credPath,
        notice: `Generated secure initial credentials in restricted file (0600): ${credPath}`,
      };
    } catch {
      throw new Error(
        'In production mode (NODE_ENV=production), either SHN_INITIAL_ADMIN_PASSWORD must be provided or filesystem permissions must permit creating .shn-initial-credentials.'
      );
    }
  }

  // Development and test mode default for automated testing compatibility
  return {
    password: 'Password123!',
    isGenerated: false,
    notice: 'Development fallback active (Baseline credentials provisioned)',
  };
}

interface InMemoryStore {
  orgs: Map<string, any>;
  users: Map<string, any>;
  workspaces: Map<string, any>;
  credentials: Map<string, any>;
  roles: Map<string, any>;
  userRoles: any[];
  assets: Map<string, any>;
  findings: Map<string, any>;
  findingHistory: any[];
  capabilities: Map<string, any>;
  executions: Map<string, any>;
  executionAttempts: any[];
  scopes: Map<string, any>;
  auditEvents: any[];
}

function createInMemoryDatabasePool(): DatabasePool {
  return {
    async query(sql: string): Promise<any> {
      const s = sql.trim().toLowerCase();
      if (s.includes('select 1')) {
        return { rows: [{ '?column?': 1 }], rowCount: 1, command: 'SELECT' };
      }
      return { rows: [], rowCount: 0, command: 'SELECT' };
    },
    async connect(): Promise<any> {
      return {
        query: this.query.bind(this),
        release: () => {},
      };
    },
    async end(): Promise<void> {},
    totalCount: 1,
    idleCount: 1,
    waitingCount: 0,
  };
}

function createInMemoryRepositories(store: InMemoryStore) {
  const orgRepo: any = {
    create: async (data: any) => {
      store.orgs.set(data.id, { ...data, created_at: new Date().toISOString() });
      return store.orgs.get(data.id);
    },
    findById: async (id: string) => store.orgs.get(id) || null,
  };

  const userRepo: any = {
    create: async (data: any) => {
      store.users.set(data.id, { ...data, created_at: new Date().toISOString() });
      return store.users.get(data.id);
    },
    findById: async (id: string) => store.users.get(id) || null,
    findByEmail: async (orgId: string, email: string) => {
      for (const u of store.users.values()) {
        if (u.organization_id === orgId && u.email === email) return u;
      }
      return null;
    },
    findFirstByEmail: async (email: string) => {
      for (const u of store.users.values()) {
        if (u.email === email) return u;
      }
      return null;
    },
  };

  const workspaceRepo: any = {
    create: async (data: any) => {
      store.workspaces.set(data.id, { ...data, created_at: new Date().toISOString() });
      return store.workspaces.get(data.id);
    },
    findById: async (id: string) => store.workspaces.get(id) || null,
    listByOrganization: async (orgId: string) => {
      return Array.from(store.workspaces.values()).filter((w) => w.organization_id === orgId);
    },
  };

  const credentialRepo: any = {
    saveCredential: async (userId: string, hash: string) => {
      store.credentials.set(userId, { user_id: userId, password_hash: hash });
    },
    findByUserId: async (userId: string) => store.credentials.get(userId) || null,
  };

  const roleRepo: any = {
    findRoleByName: async (name: string) => store.roles.get(name) || null,
    assignUserRole: async (userId: string, roleId: string, orgId: string, wksId?: string) => {
      store.userRoles.push({ user_id: userId, role_id: roleId, organization_id: orgId, workspace_id: wksId });
    },
    getUserRoles: async (userId: string, orgId: string, wksId: string) => {
      const assigned = store.userRoles.filter(
        (ur) => ur.user_id === userId && ur.organization_id === orgId && (!ur.workspace_id || ur.workspace_id === wksId)
      );
      return assigned.map((a) => {
        const r = Array.from(store.roles.values()).find((x) => x.id === a.role_id);
        return { role_name: r?.name || 'ORG_ADMIN' };
      });
    },
  };

  const assetRepo: any = {
    createAsset: async (data: any) => {
      const asset = {
        id: data.id || generateUUIDv7(),
        workspaceId: data.workspaceId || data.workspace_id,
        organizationId: data.organizationId || data.organization_id,
        type: data.type,
        canonicalValue: data.canonicalValue || data.canonical_target || data.rawTarget || data.raw_target,
        name: data.name || data.canonicalValue || 'Asset',
        criticality: data.criticality || 'MEDIUM',
        status: data.status || 'ACTIVE',
        tags: data.tags || [],
        metadata: data.metadata || {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        version: 1,
      };
      (asset as any).workspace_id = asset.workspaceId;
      (asset as any).organization_id = asset.organizationId;
      (asset as any).canonical_target = asset.canonicalValue;
      (asset as any).raw_target = asset.canonicalValue;
      (asset as any).created_at = asset.createdAt;
      (asset as any).updated_at = asset.updatedAt;
      store.assets.set(asset.id, asset);
      return asset;
    },
    create: async function (data: any) {
      return (this as any).createAsset(data);
    },
    findById: async (id: string, wksId: string) => {
      const a = store.assets.get(id);
      return a && (a.workspaceId === wksId || a.workspace_id === wksId) ? a : null;
    },
    findByCanonicalValue: async (wksIdOrVal: string, _typeOrWksId?: string, val?: string) => {
      const targetVal = val || wksIdOrVal;
      for (const a of store.assets.values()) {
        if (a.canonicalValue === targetVal || a.canonical_target === targetVal) return a;
      }
      return null;
    },
    listAssets: async (wksId: string, filter: any = {}) => {
      return Array.from(store.assets.values()).filter((a) => {
        if (a.workspaceId !== wksId && a.workspace_id !== wksId) return false;
        if (filter.type && a.type !== filter.type) return false;
        if (filter.status && a.status !== filter.status) return false;
        return true;
      });
    },
    listByWorkspace: async function (wksId: string, filter: any = {}) {
      return (this as any).listAssets(wksId, filter);
    },
    updateAsset: async (id: string, wksId: string, updates: any) => {
      const a = store.assets.get(id);
      if (!a || (a.workspaceId !== wksId && a.workspace_id !== wksId)) return null;
      const updated = {
        ...a,
        name: updates.name !== undefined ? updates.name : a.name,
        criticality: updates.criticality || a.criticality,
        status: updates.status || a.status,
        tags: updates.tags || a.tags,
        metadata: updates.metadata || a.metadata,
        updatedAt: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        version: a.version + 1,
      };
      store.assets.set(id, updated);
      return updated;
    },
    update: async function (id: string, wksId: string, updates: any) {
      return (this as any).updateAsset(id, wksId, updates);
    },
  };

  const findingRepo: any = {
    createFinding: async (data: any) => {
      const f = {
        id: data.id || generateUUIDv7(),
        workspaceId: data.workspaceId || data.workspace_id,
        organizationId: data.organizationId || data.organization_id,
        assetId: data.assetId || data.asset_id,
        executionId: data.executionId ?? data.execution_id ?? null,
        title: data.title,
        description: data.description,
        category: data.category,
        severity: data.severity,
        cveId: data.cveId ?? data.cve_id ?? null,
        cweId: data.cweId ?? data.cwe_id ?? null,
        cvssScore: data.cvssScore !== undefined ? data.cvssScore : data.cvss_score ?? null,
        cvssVector: data.cvssVector ?? data.cvss_vector ?? null,
        status: data.status || 'OPEN',
        rawEvidenceSha256: data.rawEvidenceSha256 || data.raw_evidence_sha256 || '0000000000000000000000000000000000000000000000000000000000000000',
        evidenceArtifactId: data.evidenceArtifactId ?? data.evidence_artifact_id ?? null,
        remediationGuidance: data.remediationGuidance ?? data.remediation_guidance ?? null,
        metadata: data.metadata ?? {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        version: 1,
      };
      (f as any).workspace_id = f.workspaceId;
      (f as any).organization_id = f.organizationId;
      (f as any).asset_id = f.assetId;
      (f as any).execution_id = f.executionId;
      (f as any).cve_id = f.cveId;
      (f as any).cwe_id = f.cweId;
      (f as any).cvss_score = f.cvssScore;
      (f as any).cvss_vector = f.cvssVector;
      (f as any).raw_evidence_sha256 = f.rawEvidenceSha256;
      (f as any).created_at = f.createdAt;
      (f as any).updated_at = f.updatedAt;
      store.findings.set(f.id, f);
      return f;
    },
    create: async function (data: any) {
      return (this as any).createFinding(data);
    },
    findById: async (id: string, wksId: string) => {
      const f = store.findings.get(id);
      return f && (f.workspaceId === wksId || f.workspace_id === wksId) ? f : null;
    },
    findByDeduplicationKey: async (key: string) => {
      for (const f of store.findings.values()) {
        if (f.deduplication_hash === key) return f;
      }
      return null;
    },
    listFindings: async (wksId: string, filter: any = {}) => {
      return Array.from(store.findings.values()).filter((f) => {
        if (f.workspaceId !== wksId && f.workspace_id !== wksId) return false;
        if (filter.assetId && f.assetId !== filter.assetId && f.asset_id !== filter.assetId) return false;
        if (filter.status && f.status !== filter.status) return false;
        if (filter.severity && f.severity !== filter.severity) return false;
        return true;
      });
    },
    listByWorkspace: async function (wksId: string, filter: any = {}) {
      return (this as any).listFindings(wksId, filter);
    },
    recordStatusTransition: async (data: any) => {
      const targetId = data.findingId || data.finding_id;
      const f = store.findings.get(targetId);
      if (f) {
        f.status = data.toStatus || data.to_status;
        f.updatedAt = new Date().toISOString();
        f.updated_at = new Date().toISOString();
        f.version = (f.version || 1) + 1;
      }
      const transition = {
        ...data,
        id: generateUUIDv7(),
        findingId: targetId,
        finding_id: targetId,
        createdAt: new Date().toISOString(),
        created_at: new Date().toISOString(),
      };
      store.findingHistory.push(transition);
      return transition;
    },
    recordTransition: async function (data: any) {
      return (this as any).recordStatusTransition(data);
    },
    getStatusTransitions: async (findingId: string, wksId: string) => {
      return store.findingHistory.filter(
        (h) => (h.findingId === findingId || h.finding_id === findingId) && (h.workspaceId === wksId || h.workspace_id === wksId)
      );
    },
    getHistory: async function (findingId: string, wksId: string) {
      return (this as any).getStatusTransitions(findingId, wksId);
    },
  };


  const capabilityRepo: any = {
    registerCapability: async (data: any) => {
      const rec = {
        ...data,
        internalId: generateUUIDv7(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      store.capabilities.set(data.id, rec);
      return rec;
    },
    create: async function (data: any) {
      return (this as any).registerCapability(data);
    },
    findCapabilityById: async (id: string) => store.capabilities.get(id) || null,
    findById: async function (id: string) {
      return (this as any).findCapabilityById(id);
    },
    findByUri: async (uri: string) => {
      for (const c of store.capabilities.values()) {
        if (c.uri === uri || c.id === uri) return c;
      }
      return null;
    },
    listCapabilities: async (filter: any = {}) => {
      return Array.from(store.capabilities.values()).filter((c) => {
        if (filter.category && c.category !== filter.category) return false;
        if (filter.lifecycleState && c.lifecycleState !== filter.lifecycleState) return false;
        if (filter.state && c.lifecycleState !== filter.state && c.state !== filter.state) return false;
        return true;
      });
    },
    list: async function (filter: any = {}) {
      return (this as any).listCapabilities(filter);
    },
    registerAdapter: async (data: any) => data,
    findAdapterById: async () => null,
    listAdapters: async () => [],
    listAdaptersForCapability: async () => [],
    getWorkspaceBinding: async () => null,
    setWorkspaceBinding: async () => {},
    listWorkspaceBindings: async () => [],
  };

  const executionRepo: any = {
    create: async (data: any) => {
      const e = {
        ...data,
        id: data.id || generateUUIDv7(),
        state: data.state || 'QUEUED',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        started_at: new Date().toISOString(),
        completed_at: null,
        stdout_summary: null,
        stderr_summary: null,
        raw_output_sha256: null,
        version: 1,
      };
      store.executions.set(e.id, e);
      return e;
    },
    createExecution: async function (data: any) {
      return (this as any).create(data);
    },
    findById: async (id: string, wksId: string) => {
      const e = store.executions.get(id);
      return e && (e.workspace_id === wksId || e.workspaceId === wksId) ? e : null;
    },
    listByWorkspace: async (wksId: string) => {
      return Array.from(store.executions.values())
        .filter((e) => e.workspace_id === wksId || e.workspaceId === wksId)
        .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    },
    transitionState: async (id: string, wksId: string, _fromState: any, toState: string, updates: any = {}) => {
      const e = store.executions.get(id);
      if (!e || (e.workspace_id !== wksId && e.workspaceId !== wksId)) return null;
      e.state = toState;
      if (updates.stdout_summary) e.stdout_summary = updates.stdout_summary;
      if (updates.stderr_summary) e.stderr_summary = updates.stderr_summary;
      if (updates.raw_output_sha256) e.raw_output_sha256 = updates.raw_output_sha256;
      if (updates.started_at) e.started_at = updates.started_at;
      if (updates.completed_at) e.completed_at = updates.completed_at;
      e.updated_at = new Date().toISOString();
      e.version = (e.version || 1) + 1;
      return e;
    },
    acquireWorkerLease: async () => ({ leaseAcquired: true }),
    releaseWorkerLease: async () => {},
    heartbeatWorker: async () => {},
    recordAttempt: async (data: any) => {
      const attempt = { ...data, id: data.id || generateUUIDv7() };
      store.executionAttempts.push(attempt);
      return attempt;
    },
    listArtifacts: async () => [],
  };

  const scopeRepo: any = {
    createScope: async (data: any) => {
      const s = {
        ...data,
        id: data.id || generateUUIDv7(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      store.scopes.set(s.id, s);
      return s;
    },
    findById: async (id: string, wksId: string) => {
      const s = store.scopes.get(id);
      return s && s.workspace_id === wksId ? s : null;
    },
    listByWorkspace: async (wksId: string) => {
      return Array.from(store.scopes.values()).filter((s) => s.workspace_id === wksId);
    },
    findActiveByWorkspace: async (wksId: string) => {
      return Array.from(store.scopes.values()).filter((s) => s.workspace_id === wksId && s.status === 'ACTIVE');
    },
  };

  const auditRepo: any = {
    append: async (event: any) => {
      store.auditEvents.push({ ...event, recorded_at: new Date().toISOString() });
    },
    findByEventId: async (id: string) => {
      return store.auditEvents.find((e) => e.event_id === id) || null;
    },
    listByWorkspace: async (wksId: string, limit = 50) => {
      return store.auditEvents
        .filter((e) => e.workspace_id === wksId)
        .slice(-limit)
        .reverse();
    },
  };

  return {
    orgRepo,
    userRepo,
    workspaceRepo,
    credentialRepo,
    roleRepo,
    assetRepo,
    findingRepo,
    capabilityRepo,
    executionRepo,
    scopeRepo,
    auditRepo,
  };
}

async function seedDemonstrationData(
  store: InMemoryStore,
  repos: ReturnType<typeof createInMemoryRepositories>,
  adminPassword = process.env.SHN_INITIAL_ADMIN_PASSWORD || 'Password123!'
) {
  const hasher = new PasswordHasher();
  const passwordHash = await hasher.hashPassword(adminPassword);

  const adminRoleId = generateUUIDv7();
  store.roles.set('ORG_ADMIN', { id: adminRoleId, name: 'ORG_ADMIN', permissions: 0xffffffff });
  store.roles.set('ADMIN', { id: adminRoleId, name: 'ADMIN', permissions: 0xffffffff });

  const rawOrgId = generateUUIDv7();
  const orgRes = createOrganizationId(rawOrgId);
  const orgId: OrganizationId = orgRes.isOk ? orgRes.value : (rawOrgId as any);

  const org = await repos.orgRepo.create({
    id: orgId,
    name: 'Apex Sovereign Cyber Defense',
    slug: 'apex-sovereign',
  });

  const rawUserId = generateUUIDv7();
  const userRes = createUserId(rawUserId);
  const userId: UserId = userRes.isOk ? userRes.value : (rawUserId as any);

  const user = await repos.userRepo.create({
    id: userId,
    organization_id: org.id,
    email: 'operator@shn.sovereign',
    display_name: 'Chief Security Officer',
    status: 'ACTIVE',
  });
  await repos.credentialRepo.saveCredential(user.id, passwordHash);

  const rawWksId = generateUUIDv7();
  const wksRes = createWorkspaceId(rawWksId);
  const workspaceId: WorkspaceId = wksRes.isOk ? wksRes.value : (rawWksId as any);

  const workspace = await repos.workspaceRepo.create({
    id: workspaceId,
    organization_id: org.id,
    name: 'Helix Sector Alpha (Production)',
    slug: 'helix-sector-alpha',
  });
  await repos.roleRepo.assignUserRole(user.id, adminRoleId, org.id, workspace.id);

  const rawDevWksId = generateUUIDv7();
  const devWksRes = createWorkspaceId(rawDevWksId);
  const devWorkspaceId: WorkspaceId = devWksRes.isOk ? devWksRes.value : (rawDevWksId as any);

  await repos.workspaceRepo.create({
    id: devWorkspaceId,
    organization_id: org.id,
    name: 'Quantum Lab Sandbox',
    slug: 'quantum-lab-sandbox',
  });

  const rawScopeId = generateUUIDv7();
  const scopeRes = createScopeId(rawScopeId);
  const scopeId: ScopeId = scopeRes.isOk ? scopeRes.value : (rawScopeId as any);

  await repos.scopeRepo.createScope({
    id: scopeId,
    workspace_id: workspace.id,
    organization_id: org.id,
    name: 'Perimeter Defense Zone Alpha',
    description: 'Authorized operational target inclusions for automated scanning',
    status: 'ACTIVE',
    inclusions: [
      { type: 'CIDR', value: '10.240.0.0/24' },
      { type: 'IPV4', value: '192.168.10.45' },
      { type: 'DOMAIN', value: 'api.sovereign.internal' },
      { type: 'URL', value: 'https://gateway.sovereign.internal/api' },
    ],
    exclusions: [
      { type: 'IPV4', value: '169.254.169.254', reason: 'AWS/GCP Cloud Metadata Protection (SEC-INV-08)' },
      { type: 'CIDR', value: '127.0.0.0/8', reason: 'Loopback Protection' },
    ],
    allowed_actions: [
      'RECON_PASSIVE',
      'PROBING_ACTIVE',
      'PORT_SCAN',
      'HTTP_DISCOVERY',
      'network:scan',
      'http:probe',
    ],
    disallowed_actions: ['EXPLOIT', 'DENIAL_OF_SERVICE'],
    port_ranges: [
      { start: 22, end: 22 },
      { start: 80, end: 443 },
      { start: 8000, end: 9000 },
    ],
    valid_from: new Date(Date.now() - 3600000).toISOString(),
    valid_until: new Date(Date.now() + 86400000 * 90).toISOString(),
    rate_limits: { requests_per_second: 50 },
    scope_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    created_by: user.id,
  });

  const rawAsset1 = generateUUIDv7();
  const asset1Res = createAssetId(rawAsset1);
  const asset1Id: AssetId = asset1Res.isOk ? asset1Res.value : (rawAsset1 as any);

  const asset1 = await repos.assetRepo.create({
    id: asset1Id,
    workspace_id: workspace.id,
    organization_id: org.id,
    type: 'IPV4',
    raw_target: '10.240.0.1',
    canonical_target: '10.240.0.1',
    name: 'Sovereign Core Gateway',
    criticality: 'CRITICAL',
    status: 'ACTIVE',
    tags: ['edge', 'gateway', 'core-infra'],
    metadata: { env: 'production', cluster: 'helix-core-1' },
  });

  const rawAsset2 = generateUUIDv7();
  const asset2Res = createAssetId(rawAsset2);
  const asset2Id: AssetId = asset2Res.isOk ? asset2Res.value : (rawAsset2 as any);

  const asset2 = await repos.assetRepo.create({
    id: asset2Id,
    workspace_id: workspace.id,
    organization_id: org.id,
    type: 'DOMAIN',
    raw_target: 'api.sovereign.internal',
    canonical_target: 'api.sovereign.internal',
    name: 'Zero-Trust Authentication Gateway',
    criticality: 'HIGH',
    status: 'ACTIVE',
    tags: ['identity', 'rest-api'],
    metadata: { protocol: 'https', tls_version: '1.3' },
  });

  const rawAsset3 = generateUUIDv7();
  const asset3Res = createAssetId(rawAsset3);
  const asset3Id: AssetId = asset3Res.isOk ? asset3Res.value : (rawAsset3 as any);

  await repos.assetRepo.create({
    id: asset3Id,
    workspace_id: workspace.id,
    organization_id: org.id,
    type: 'CIDR',
    raw_target: '10.240.0.0/24',
    canonical_target: '10.240.0.0/24',
    name: 'Kubernetes Workload Subnet',
    criticality: 'MEDIUM',
    status: 'ACTIVE',
    tags: ['k8s', 'internal'],
    metadata: { vpc_id: 'vpc-helix-alpha' },
  });

  const rawFinding1 = generateUUIDv7();
  const finding1Res = createFindingId(rawFinding1);
  const finding1Id: FindingId = finding1Res.isOk ? finding1Res.value : (rawFinding1 as any);

  await repos.findingRepo.create({
    id: finding1Id,
    workspace_id: workspace.id,
    organization_id: org.id,
    asset_id: asset1.id,
    title: 'Container Breakout Risk: Insecure Pod Security Standards',
    description: 'HostPath volume mount detected with write access to root filesystem, allowing privilege escalation.',
    category: 'CONTAINER_SECURITY',
    severity: 'CRITICAL',
    cve_id: 'CVE-2024-21626',
    cwe_id: 'CWE-250',
    cvss_score: 8.8,
    cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
    raw_evidence_sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
    remediation_guidance: 'Enforce Restricted Pod Security Standards and eliminate privileged hostPath mounts.',
    status: 'OPEN',
    deduplication_hash: 'dedup-hash-crit-1',
  });

  const rawFinding2 = generateUUIDv7();
  const finding2Res = createFindingId(rawFinding2);
  const finding2Id: FindingId = finding2Res.isOk ? finding2Res.value : (rawFinding2 as any);

  await repos.findingRepo.create({
    id: finding2Id,
    workspace_id: workspace.id,
    organization_id: org.id,
    asset_id: asset2.id,
    title: 'HTTP/2 Rapid Reset Exposure (DDoS Vector)',
    description: 'Server accepts stream resets without bounding resource allocation, causing amplification.',
    category: 'DENIAL_OF_SERVICE',
    severity: 'HIGH',
    cve_id: 'CVE-2023-44487',
    cwe_id: 'CWE-400',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    raw_evidence_sha256: 'f0e1d2c3b4a5968778695a4b3c2d1e0f0123456789abcdef0123456789abcdef',
    remediation_guidance: 'Update reverse proxy to apply RST_STREAM rate limits.',
    status: 'TRIAGED',
    deduplication_hash: 'dedup-hash-high-1',
  });

  await repos.executionRepo.create({
    id: generateUUIDv7(),
    workspace_id: workspace.id,
    organization_id: org.id,
    scope_id: scopeId,
    action: 'PORT_SCAN',
    target: '10.240.0.1',
    capability_uri: 'cap:network:port-scan:v1',
    state: 'COMPLETED',
    requested_by: user.id,
    command: { executable: 'nmap', args: ['-sS', '-p', '22,80,443', '10.240.0.1'] },
    stdout_summary: 'Open ports discovered: 22/tcp (ssh OpenSSH 9.6), 443/tcp (https TLS 1.3). Scan completed in 1.42s.',
    stderr_summary: null,
    raw_output_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  });

  await repos.executionRepo.create({
    id: generateUUIDv7(),
    workspace_id: workspace.id,
    organization_id: org.id,
    scope_id: scopeId,
    action: 'HTTP_DISCOVERY',
    target: 'https://gateway.sovereign.internal',
    capability_uri: 'cap:http:service-discovery:v1',
    state: 'COMPLETED',
    requested_by: user.id,
    command: { executable: 'curl', args: ['-I', 'https://gateway.sovereign.internal'] },
    stdout_summary: 'HTTP/2 200 OK. Server: Sovereign-Ingress. Strict-Transport-Security: max-age=31536000.',
    stderr_summary: null,
    raw_output_sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
  });

  await repos.auditRepo.append({
    event_id: generateUUIDv7(),
    event_type: 'platform.initialized',
    schema_version: '1.0.0',
    occurred_at: new Date().toISOString(),
    producer: { service: 'ingress-gateway', version: '0.1.0', instance_id: 'standalone-primary' },
    workspace_id: workspace.id,
    correlation_id: 'corr-init-genesis',
    causation_id: 'cause-init-genesis',
    trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
    authorization_context: { subject_id: user.id, roles: ['ORG_ADMIN'] },
    scope_reference: { scope_id: scopeId, sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    payload: { message: 'Shadow : Helix Nebula Sovereign Platform Online' },
    integrity: { signature: 'sig_genesis_verified', algorithm: 'ed25519' },
  });
}

async function seedPostgresDemonstrationData(
  repos: any,
  adminPassword = process.env.SHN_INITIAL_ADMIN_PASSWORD || 'Password123!'
) {
  let org = await repos.orgRepo.findBySlug('apex-sovereign');
  if (!org) {
    const rawOrgId = generateUUIDv7();
    const orgRes = createOrganizationId(rawOrgId);
    const orgId: OrganizationId = orgRes.isOk ? orgRes.value : (rawOrgId as any);
    org = await repos.orgRepo.create({
      id: orgId,
      name: 'Apex Sovereign Cyber Defense',
      slug: 'apex-sovereign',
    });
  }

  let user = await repos.userRepo.findFirstByEmail('operator@shn.sovereign');
  if (!user) {
    const hasher = new PasswordHasher();
    const passwordHash = await hasher.hashPassword(adminPassword);

    const rawUserId = generateUUIDv7();
    const userRes = createUserId(rawUserId);
    const userId: UserId = userRes.isOk ? userRes.value : (rawUserId as any);

    user = await repos.userRepo.create({
      id: userId,
      organization_id: org.id,
      email: 'operator@shn.sovereign',
      display_name: 'Chief Security Officer',
      status: 'ACTIVE',
    });
    await repos.credentialRepo.saveCredential(user.id, passwordHash);
  }

  let workspace = await repos.workspaceRepo.findBySlug(org.id, 'helix-sector-alpha');
  if (!workspace) {
    const rawWksId = generateUUIDv7();
    const wksRes = createWorkspaceId(rawWksId);
    const workspaceId: WorkspaceId = wksRes.isOk ? wksRes.value : (rawWksId as any);

    workspace = await repos.workspaceRepo.create({
      id: workspaceId,
      organization_id: org.id,
      name: 'Helix Sector Alpha (Production)',
      slug: 'helix-sector-alpha',
    });
    const adminRole = await repos.roleRepo.findRoleByName('ORG_ADMIN');
    const adminRoleId = adminRole?.id ?? '00000000-0000-7000-8001-000000000001';
    await repos.roleRepo.assignUserRole(user.id, adminRoleId, org.id, workspace.id);
  }

  let devWorkspace = await repos.workspaceRepo.findBySlug(org.id, 'quantum-lab-sandbox');
  if (!devWorkspace) {
    const rawDevWksId = generateUUIDv7();
    const devWksRes = createWorkspaceId(rawDevWksId);
    const devWorkspaceId: WorkspaceId = devWksRes.isOk ? devWksRes.value : (rawDevWksId as any);

    devWorkspace = await repos.workspaceRepo.create({
      id: devWorkspaceId,
      organization_id: org.id,
      name: 'Quantum Lab Sandbox',
      slug: 'quantum-lab-sandbox',
    });
  }

  const existingScopes = await repos.scopeRepo.listByWorkspace(workspace.id);
  let scopeId: string;
  if (existingScopes.length === 0) {
    const rawScopeId = generateUUIDv7();
    const scopeRes = createScopeId(rawScopeId);
    scopeId = scopeRes.isOk ? scopeRes.value : (rawScopeId as any);

    await repos.scopeRepo.createScope({
      id: scopeId,
      workspace_id: workspace.id,
      organization_id: org.id,
      name: 'Perimeter Defense Zone Alpha',
      description: 'Authorized operational target inclusions for automated scanning',
      status: 'ACTIVE',
      inclusions: [
        { type: 'CIDR', value: '10.240.0.0/24' },
        { type: 'IPV4', value: '192.168.10.45' },
        { type: 'DOMAIN', value: 'api.sovereign.internal' },
        { type: 'URL', value: 'https://gateway.sovereign.internal/api' },
      ],
      exclusions: [
        { type: 'IPV4', value: '169.254.169.254', reason: 'AWS/GCP Cloud Metadata Protection (SEC-INV-08)' },
        { type: 'CIDR', value: '127.0.0.0/8', reason: 'Loopback Protection' },
      ],
      allowed_actions: [
        'RECON_PASSIVE',
        'PROBING_ACTIVE',
        'PORT_SCAN',
        'HTTP_DISCOVERY',
        'network:scan',
        'http:probe',
      ],
      disallowed_actions: ['EXPLOIT', 'DENIAL_OF_SERVICE'],
      port_ranges: [
        { start: 22, end: 22 },
        { start: 80, end: 443 },
        { start: 8000, end: 9000 },
      ],
      valid_from: new Date(Date.now() - 3600000).toISOString(),
      valid_until: new Date(Date.now() + 86400000 * 90).toISOString(),
      rate_limits: { requests_per_second: 50 },
      scope_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      created_by: user.id,
    });
  } else {
    scopeId = existingScopes[0].id;
  }

  const existingAssets = await repos.assetRepo.listAssets(workspace.id);
  let asset1Id: string | undefined;
  if (existingAssets.length === 0) {
    const rawAsset1 = generateUUIDv7();
    const asset1Res = createAssetId(rawAsset1);
    asset1Id = asset1Res.isOk ? asset1Res.value : (rawAsset1 as any);

    await repos.assetRepo.createAsset({
      id: asset1Id as any,
      workspaceId: workspace.id,
      organizationId: org.id,
      type: 'IPV4',
      canonicalValue: '10.240.0.1',
      name: 'Sovereign Core Gateway',
      criticality: 'CRITICAL',
      status: 'ACTIVE',
      tags: ['edge', 'gateway', 'core-infra'],
      metadata: { env: 'production', cluster: 'helix-core-1' },
    });

    const rawAsset2 = generateUUIDv7();
    const asset2Res = createAssetId(rawAsset2);
    const asset2Id = asset2Res.isOk ? asset2Res.value : (rawAsset2 as any);

    await repos.assetRepo.createAsset({
      id: asset2Id as any,
      workspaceId: workspace.id,
      organizationId: org.id,
      type: 'FQDN',
      canonicalValue: 'api.sovereign.internal',
      name: 'Zero-Trust Authentication Gateway',
      criticality: 'HIGH',
      status: 'ACTIVE',
      tags: ['identity', 'rest-api'],
      metadata: { protocol: 'https', tls_version: '1.3' },
    });
  } else {
    asset1Id = existingAssets[0].id;
  }

  const existingFindings = await repos.findingRepo.listFindings(workspace.id);
  if (existingFindings.length === 0 && asset1Id) {
    const rawFinding1 = generateUUIDv7();
    const finding1Res = createFindingId(rawFinding1);
    const finding1Id = finding1Res.isOk ? finding1Res.value : (rawFinding1 as any);

    await repos.findingRepo.createFinding({
      id: finding1Id as any,
      workspaceId: workspace.id,
      organizationId: org.id,
      assetId: asset1Id as any,
      title: 'Container Breakout Risk: Insecure Pod Security Standards',
      description: 'HostPath volume mount detected with write access to root filesystem, allowing privilege escalation.',
      category: 'CONTAINER_SECURITY',
      severity: 'CRITICAL',
      cveId: 'CVE-2024-21626',
      cweId: 'CWE-250',
      cvssScore: 8.8,
      cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
      rawEvidenceSha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      remediationGuidance: 'Enforce Restricted Pod Security Standards and eliminate privileged hostPath mounts.',
      status: 'CONFIRMED',
    });
  }

  const existingAudit = await repos.auditRepo.listByWorkspace(workspace.id, 1);
  if (existingAudit.length === 0) {
    await repos.auditRepo.append({
      event_id: generateUUIDv7(),
      event_type: 'platform.initialized',
      schema_version: '1.0.0',
      occurred_at: new Date().toISOString(),
      producer: { service: 'ingress-gateway', version: '0.1.0', instance_id: 'standalone-primary' },
      workspace_id: workspace.id,
      correlation_id: generateUUIDv7(),
      causation_id: generateUUIDv7(),
      trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
      authorization_context: { subject_id: user.id, roles: ['ORG_ADMIN'] },
      scope_reference: { scope_id: scopeId, sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
      payload: { message: 'Shadow : Helix Nebula Sovereign Platform Online' },
      integrity: { signature: 'sig_genesis_verified', algorithm: 'ed25519' },
    });
  }
}

function attachStaticWebConsoleHandler(server: IngressServer) {
  const router = server.getRouter();
  const webDistDir = path.resolve(process.cwd(), 'packages/web-console/dist');

  const MIME_TYPES: Record<string, string> = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
  };

  router.use(async (req, res, next) => {
    if (req.method !== 'GET') {
      await next();
      return;
    }

    if (
      req.path.startsWith('/api') ||
      req.path.startsWith('/health') ||
      req.path === '/metrics' ||
      req.path === '/openapi.json'
    ) {
      await next();
      return;
    }

    if (!fs.existsSync(webDistDir)) {
      await next();
      return;
    }

    let filePath = path.join(webDistDir, req.path === '/' ? 'index.html' : req.path);
    if (!fs.existsSync(filePath)) {
      filePath = path.join(webDistDir, 'index.html');
    }

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      const content = fs.readFileSync(filePath);
      res.setHeader('Content-Type', contentType);
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.status(200);
      res.raw.end(content);
      return;
    }

    await next();
  });
}

export async function startStandaloneServer(customPort?: number): Promise<{
  server: IngressServer;
  port: number;
  url: string;
  isPostgres: boolean;
  eventStreamHub: EventStreamHub;
}> {
  const creds = resolveOperatorCredentials();

  if (process.env.NODE_ENV === 'production') {
    if (!process.env.SHN_SIGNER_SECRET || process.env.SHN_SIGNER_SECRET === 'shn-sovereign-signer-secret-key-32b!') {
      throw new Error('Production Security Invariant Violation: SHN_SIGNER_SECRET must be configured with a secure key.');
    }
    if (!process.env.SHN_SCOPE_SIGNER_SECRET || process.env.SHN_SCOPE_SIGNER_SECRET === 'shn-sovereign-scope-secret-key-32b!!') {
      throw new Error('Production Security Invariant Violation: SHN_SCOPE_SIGNER_SECRET must be configured with a secure key.');
    }
    if (process.env.SHN_INITIAL_ADMIN_PASSWORD === 'Password123!') {
      throw new Error('Production Security Invariant Violation: SHN_INITIAL_ADMIN_PASSWORD cannot be set to default "Password123!" in production.');
    }
  }

  const port = customPort !== undefined ? customPort : Number(process.env.SHN_PORT || 8080);
  const host = process.env.SHN_HOST || '0.0.0.0';
  const signerSecret = process.env.SHN_SIGNER_SECRET || 'shn-sovereign-signer-secret-key-32b!';
  const signer = new SecurityContextSigner(signerSecret);

  let pool: DatabasePool | undefined;
  let isPostgres = false;

  const dbConfig: DatabaseConfig = {
    host: process.env.SHN_DB_HOST || '127.0.0.1',
    port: parseInt(process.env.SHN_DB_PORT || '54329', 10),
    database: process.env.SHN_DB_NAME || 'shn_test',
    user: process.env.SHN_DB_USER || 'postgres',
    password: process.env.SHN_DB_PASSWORD || 'postgres_test_password',
    ssl: false,
    maxConnections: 5,
    minConnections: 1,
    idleTimeoutMs: 2000,
    connectionTimeoutMs: 1500,
  };

  try {
    const testPool = createDatabasePool(dbConfig);
    const probe = await Promise.race([
      testPool.query('SELECT 1 as live;'),
      new Promise<null>((_, reject) => setTimeout(() => reject(new Error('Postgres connection timeout')), 1000)),
    ]);
    if (probe && probe.rows.length > 0) {
      pool = testPool;
      isPostgres = true;
      const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
      if (fs.existsSync(migrationsDir)) {
        await runMigrations(pool, migrationsDir);
      }
    }
  } catch {
    isPostgres = false;
  }

  const inMemoryStore: InMemoryStore = {
    orgs: new Map(),
    users: new Map(),
    workspaces: new Map(),
    credentials: new Map(),
    roles: new Map(),
    userRoles: [],
    assets: new Map(),
    findings: new Map(),
    findingHistory: [],
    capabilities: new Map(),
    executions: new Map(),
    executionAttempts: [],
    scopes: new Map(),
    auditEvents: [],
  };

  let repos: any;
  if (isPostgres && pool) {
    repos = {
      orgRepo: new OrganizationRepository(pool),
      userRepo: new UserRepository(pool),
      workspaceRepo: new WorkspaceRepository(pool),
      credentialRepo: new CredentialRepository(pool),
      roleRepo: new RoleRepository(pool),
      assetRepo: new AssetRepository(pool),
      findingRepo: new FindingRepository(pool),
      capabilityRepo: new CapabilityRepository(pool),
      executionRepo: new ExecutionRepository(pool),
      scopeRepo: new ScopeRepository(pool),
      auditRepo: new AuditEventRepository(pool),
    };
    await seedPostgresDemonstrationData(repos, creds.password);
  } else {
    pool = createInMemoryDatabasePool();
    repos = createInMemoryRepositories(inMemoryStore);
    await seedDemonstrationData(inMemoryStore, repos, creds.password);
  }

  const assetService = new AssetInventoryService({ assetRepository: repos.assetRepo });
  const findingService = new FindingLifecycleService({
    findingRepository: repos.findingRepo,
    assetRepository: repos.assetRepo,
  });

  const capabilityRegistry = new CapabilityRegistry({ repository: repos.capabilityRepo });

  await capabilityRegistry.registerCapability({
    id: createCapabilityId('shn://capabilities/network/port-scan').unwrapOr('shn://capabilities/network/port-scan' as any),
    name: 'network-port-scan',
    version: '1.0.0',
    displayName: 'Network Port Scanner',
    description: 'TCP SYN and connect port scanner with rate-limiting and scope containment enforcement.',
    category: 'RECONNAISSANCE',
    riskLevel: 'LOW',
    supportedTargets: ['IP', 'CIDR', 'DOMAIN', 'HOST'],
    requiredPermissions: 1,
    requiredScopeAction: 'network:scan',
    argumentSchema: {
      type: 'object',
      properties: {
        ports: { type: 'string', description: 'Port range' },
        timing: { type: 'number', default: 3 },
      },
    },
    outputSchema: {
      type: 'object',
      properties: {
        openPorts: { type: 'array', items: { type: 'number' } },
      },
    },
    platformCompatibility: ['linux', 'darwin', 'win32'],
    lifecycleState: 'ACTIVE',
    integrityDigest: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
  });

  await capabilityRegistry.registerCapability({
    id: createCapabilityId('shn://capabilities/web/http-discovery').unwrapOr('shn://capabilities/web/http-discovery' as any),
    name: 'http-discovery',
    version: '1.0.0',
    displayName: 'HTTP Service & Header Fingerprinting',
    description: 'HTTP/HTTPS endpoint discovery, banner identification, and security header audit.',
    category: 'DISCOVERY',
    riskLevel: 'INFORMATIONAL',
    supportedTargets: ['URL', 'DOMAIN', 'HOST'],
    requiredPermissions: 1,
    requiredScopeAction: 'http:probe',
    argumentSchema: {
      type: 'object',
      properties: {
        timeoutMs: { type: 'number', default: 5000 },
        followRedirects: { type: 'boolean', default: false },
      },
    },
    outputSchema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number' },
        headers: { type: 'object' },
      },
    },
    platformCompatibility: ['linux', 'darwin', 'win32'],
    lifecycleState: 'ACTIVE',
    integrityDigest: 'b1c2d3e4f5a60718293a4b5c6d7e8f90b1c2d3e4f5a60718293a4b5c6d7e8f90',
  });

  await capabilityRegistry.registerAdapter(new NetworkPortScanAdapter());
  await capabilityRegistry.registerAdapter(new HttpDiscoveryAdapter());

  const tenancyValidator = new TenancyValidator(repos.workspaceRepo);
  const scopeSecret = process.env.SHN_SCOPE_SIGNER_SECRET || 'shn-sovereign-scope-secret-key-32b!!';
  const scopeTokenSigner = new ScopeTokenSigner(scopeSecret);
  const scopeGatekeeper = new ScopeGatekeeper({
    scopeRepo: repos.scopeRepo,
    workspaceRepo: repos.workspaceRepo,
    tokenSigner: scopeTokenSigner,
    tenancyValidator,
  });

  const executionSupervisor = new ExecutionSupervisor({
    gatekeeper: scopeGatekeeper,
    executionRepo: repos.executionRepo,
    authSigner: signer,
    tenancyValidator,
  });

  const capabilityDispatcher = new CapabilityDispatcher({
    registry: capabilityRegistry,
    supervisor: executionSupervisor,
    scopeGatekeeper,
    tenancyValidator,
  });

  const eventStreamHub = new EventStreamHub();

  let server: IngressServer | undefined;
  try {
    server = createIngressApplication({
      pool,
      orgRepo: repos.orgRepo,
      userRepo: repos.userRepo,
      workspaceRepo: repos.workspaceRepo,
      credentialRepo: repos.credentialRepo,
      roleRepo: repos.roleRepo,
      assetRepo: repos.assetRepo,
      findingRepo: repos.findingRepo,
      executionRepo: repos.executionRepo,
      scopeRepo: repos.scopeRepo,
      auditRepo: repos.auditRepo,
      assetService,
      findingService,
      capabilityRegistry,
      capabilityDispatcher,
      signer,
      tenancyValidator,
      eventStreamHub,
      config: {
        port,
        host,
        corsAllowedOrigins: ['*'],
      },
    });

    attachStaticWebConsoleHandler(server);

    const started = await server.start();
    const url = `http://localhost:${started.port}`;

    console.log(`
========================================================================
SHADOW : HELIX NEBULA (SHN) — SOVEREIGN CYBERSECURITY PLATFORM
========================================================================
[+] Ingress Gateway REST API: ${url}
[+] Web Console UI:          ${url} (or http://localhost:3000 via Vite)
[+] OpenAPI 3.1 Spec:         ${url}/openapi.json
[+] Real-Time Event Stream:  ${url}/api/v1/workspaces/:workspaceId/events/stream
[+] Platform Health Probes:  ${url}/health/live  |  ${url}/health/ready
[+] Prometheus Metrics:      ${url}/metrics
[+] Persistence Engine:      ${isPostgres ? 'PostgreSQL (Active)' : 'Sovereign In-Memory Engine (Active)'}
[+] Sovereign Operator:      operator@shn.sovereign
[+] Credential Provisioning: ${creds.notice}
[+] Security Status:         Active (Zero-Trust Identity & Tenancy Hardened)
========================================================================
`);

    return { server, port: started.port, url, isPostgres, eventStreamHub };
  } catch (err) {
    if (server) {
      await server.stop().catch(() => {});
    }
    throw err;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  startStandaloneServer().catch((err) => {
    console.error('[-] Fatal server startup error:', err);
    process.exit(1);
  });
}
