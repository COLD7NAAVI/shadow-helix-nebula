/**
 * Shadow : Helix Nebula (SHN) — Application Factory & Router Assembly
 *
 * Authoritative Spec: Phase 0.3, Phase 0.14 Perimeter B (REST Gateway).
 * Assembles routers, registers middleware pipelines, and connects domain controllers.
 */

import type { DatabasePool } from '@shn/data-access';
import {
  OrganizationRepository,
  UserRepository,
  WorkspaceRepository,
  CredentialRepository,
  RoleRepository,
  AssetRepository,
  FindingRepository,
  ExecutionRepository,
  ScopeRepository,
  AuditEventRepository,
} from '@shn/data-access';
import { SecurityContextSigner, AuthorizationService } from '@shn/auth-rbac';
import { TenancyValidator } from '@shn/scope-gatekeeper';
import { AssetInventoryService, FindingLifecycleService } from '@shn/asset-inventory';
import { CapabilityRegistry, CapabilityDispatcher } from '@shn/capability-registry';

import type { GatewayConfig } from './contracts.js';
import { Router } from './routing/router.js';
import { IngressServer } from './server.js';
import { createAuthMiddleware } from './middleware/auth.js';
import { createTenancyMiddleware } from './middleware/tenancy.js';

import { HealthController } from './controllers/health.controller.js';
import { AuthController } from './controllers/auth.controller.js';
import { WorkspaceController } from './controllers/workspace.controller.js';
import { AssetController } from './controllers/asset.controller.js';
import { FindingController } from './controllers/finding.controller.js';
import { CapabilityController } from './controllers/capability.controller.js';
import { ExecutionController } from './controllers/execution.controller.js';
import { ScopeController } from './controllers/scope.controller.js';
import { AuditController } from './controllers/audit.controller.js';
import { OpenApiController } from './controllers/openapi.controller.js';
import { EventStreamController } from './controllers/event-stream.controller.js';
import { EventStreamHub } from './sse/event-stream-hub.js';

export interface AppDependencies {
  pool?: DatabasePool | undefined;
  orgRepo?: OrganizationRepository | undefined;
  userRepo?: UserRepository | undefined;
  workspaceRepo?: WorkspaceRepository | undefined;
  credentialRepo?: CredentialRepository | undefined;
  roleRepo?: RoleRepository | undefined;
  assetRepo?: AssetRepository | undefined;
  findingRepo?: FindingRepository | undefined;
  executionRepo?: ExecutionRepository | undefined;
  scopeRepo?: ScopeRepository | undefined;
  auditRepo?: AuditEventRepository | undefined;
  assetService?: AssetInventoryService | undefined;
  findingService?: FindingLifecycleService | undefined;
  capabilityRegistry?: CapabilityRegistry | undefined;
  capabilityDispatcher?: CapabilityDispatcher | undefined;
  signer: SecurityContextSigner;
  tenancyValidator?: TenancyValidator | undefined;
  authService?: AuthorizationService | undefined;
  eventStreamHub?: EventStreamHub | undefined;
  config?: Partial<GatewayConfig> | undefined;
}


export function createIngressApplication(deps: AppDependencies): IngressServer {
  const router = new Router();

  const authMiddleware = createAuthMiddleware({
    signer: deps.signer,
    authService: deps.authService,
    workspaceRepo: deps.workspaceRepo,
  });

  const tenancyMiddleware = createTenancyMiddleware({
    tenancyValidator: deps.tenancyValidator,
  });

  // 1. Health & Telemetry & OpenAPI Specification
  const healthCtrl = new HealthController({ pool: deps.pool });
  const openApiCtrl = new OpenApiController();
  router.get('/health/live', (req, res) => healthCtrl.getLiveness(req, res));
  router.get('/health/ready', (req, res) => healthCtrl.getReadiness(req, res));
  router.get('/metrics', (req, res) => healthCtrl.getMetrics(req, res));
  router.get('/openapi.json', (req, res) => openApiCtrl.getSpec(req, res));
  router.get('/api/v1/openapi.json', (req, res) => openApiCtrl.getSpec(req, res));

  // 2. Auth & Identity
  if (deps.orgRepo && deps.userRepo && deps.workspaceRepo) {
    const authCtrl = new AuthController({
      orgRepo: deps.orgRepo,
      userRepo: deps.userRepo,
      workspaceRepo: deps.workspaceRepo,
      signer: deps.signer,
      credentialRepo: deps.credentialRepo,
      roleRepo: deps.roleRepo,
    });
    router.post('/api/v1/auth/register', (req, res) => authCtrl.register(req, res));
    router.post('/api/v1/auth/login', (req, res) => authCtrl.login(req, res));
    router.get('/api/v1/auth/me', authMiddleware, (req, res) => authCtrl.me(req, res));
  }

  // 3. Workspace Management
  if (deps.workspaceRepo) {
    const wksCtrl = new WorkspaceController({
      workspaceRepo: deps.workspaceRepo,
      roleRepo: deps.roleRepo,
    });
    router.post('/api/v1/workspaces', authMiddleware, (req, res) => wksCtrl.create(req, res));
    router.get('/api/v1/workspaces', authMiddleware, (req, res) => wksCtrl.list(req, res));
    router.get('/api/v1/workspaces/:workspaceId', authMiddleware, tenancyMiddleware, (req, res) => wksCtrl.get(req, res));
  }

  // 4. Asset Inventory
  if (deps.assetService) {
    const assetCtrl = new AssetController({ assetService: deps.assetService });
    router.post('/api/v1/workspaces/:workspaceId/assets', authMiddleware, tenancyMiddleware, (req, res) => assetCtrl.register(req, res));
    router.get('/api/v1/workspaces/:workspaceId/assets', authMiddleware, tenancyMiddleware, (req, res) => assetCtrl.list(req, res));
    router.get('/api/v1/workspaces/:workspaceId/assets/:assetId', authMiddleware, tenancyMiddleware, (req, res) => assetCtrl.get(req, res));
    router.patch('/api/v1/workspaces/:workspaceId/assets/:assetId', authMiddleware, tenancyMiddleware, (req, res) => assetCtrl.update(req, res));
  }

  // 5. Finding Lifecycle
  if (deps.findingService) {
    const findingCtrl = new FindingController({ findingService: deps.findingService });
    router.post('/api/v1/workspaces/:workspaceId/findings', authMiddleware, tenancyMiddleware, (req, res) => findingCtrl.record(req, res));
    router.get('/api/v1/workspaces/:workspaceId/findings', authMiddleware, tenancyMiddleware, (req, res) => findingCtrl.list(req, res));
    router.get('/api/v1/workspaces/:workspaceId/findings/:findingId', authMiddleware, tenancyMiddleware, (req, res) => findingCtrl.get(req, res));
    router.post('/api/v1/workspaces/:workspaceId/findings/:findingId/transitions', authMiddleware, tenancyMiddleware, (req, res) => findingCtrl.transition(req, res));
    router.get('/api/v1/workspaces/:workspaceId/findings/:findingId/history', authMiddleware, tenancyMiddleware, (req, res) => findingCtrl.getHistory(req, res));
  }

  // 6. Capability Registry
  if (deps.capabilityRegistry) {
    const capCtrl = new CapabilityController({ registry: deps.capabilityRegistry });
    router.get('/api/v1/capabilities', (req, res) => capCtrl.list(req, res));
    router.get('/api/v1/capabilities/:capabilityId', (req, res) => capCtrl.get(req, res));
    router.get('/api/v1/workspaces/:workspaceId/capabilities', authMiddleware, tenancyMiddleware, (req, res) => capCtrl.listForWorkspace(req, res));
  }

  // 7. Execution Lifecycle
  if (deps.capabilityDispatcher) {
    const execCtrl = new ExecutionController({
      dispatcher: deps.capabilityDispatcher,
      executionRepo: deps.executionRepo,
    });
    router.post('/api/v1/workspaces/:workspaceId/executions', authMiddleware, tenancyMiddleware, (req, res) => execCtrl.execute(req, res));
    router.get('/api/v1/workspaces/:workspaceId/executions', authMiddleware, tenancyMiddleware, (req, res) => execCtrl.list(req, res));
    router.get('/api/v1/workspaces/:workspaceId/executions/:executionId', authMiddleware, tenancyMiddleware, (req, res) => execCtrl.get(req, res));
  }

  // 8. Scope Boundaries
  if (deps.scopeRepo) {
    const scopeCtrl = new ScopeController({ scopeRepo: deps.scopeRepo });
    router.get('/api/v1/workspaces/:workspaceId/scopes', authMiddleware, tenancyMiddleware, (req, res) => scopeCtrl.list(req, res));
    router.post('/api/v1/workspaces/:workspaceId/scopes', authMiddleware, tenancyMiddleware, (req, res) => scopeCtrl.create(req, res));
    router.get('/api/v1/workspaces/:workspaceId/scopes/:scopeId', authMiddleware, tenancyMiddleware, (req, res) => scopeCtrl.get(req, res));
  }

  // 9. Audit Activity
  if (deps.auditRepo) {
    const auditCtrl = new AuditController({ auditRepo: deps.auditRepo });
    router.get('/api/v1/workspaces/:workspaceId/audit', authMiddleware, tenancyMiddleware, (req, res) => auditCtrl.list(req, res));
    router.get('/api/v1/workspaces/:workspaceId/audit/:eventId', authMiddleware, tenancyMiddleware, (req, res) => auditCtrl.get(req, res));
  }

  // 10. Real-Time Telemetry & Domain Event Stream (SSE)
  const eventStreamHub = deps.eventStreamHub ?? new EventStreamHub();
  const eventStreamCtrl = new EventStreamController({ hub: eventStreamHub });
  router.get('/api/v1/workspaces/:workspaceId/events/stream', authMiddleware, tenancyMiddleware, (req, res) =>
    eventStreamCtrl.streamEvents(req, res)
  );

  return new IngressServer({
    config: deps.config,
    router,
    pool: deps.pool,
  });
}
