/**
 * Shadow : Helix Nebula (SHN) — Workspace Controller
 *
 * Authoritative Spec: Phase 0.3 Context 1 (BC-WKS), Phase 0.14 Section 8.
 * Handles workspace creation, retrieval, and multi-tenant scoping.
 */

import {
  generateUUIDv7,
  createWorkspaceId,
  type WorkspaceId,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import { WorkspaceRepository, RoleRepository } from '@shn/data-access';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface WorkspaceControllerOptions {
  workspaceRepo: WorkspaceRepository;
  roleRepo?: RoleRepository | undefined;
}

export class WorkspaceController {
  private readonly workspaceRepo: WorkspaceRepository;
  private readonly roleRepo?: RoleRepository | undefined;

  constructor(options: WorkspaceControllerOptions) {
    this.workspaceRepo = options.workspaceRepo;
    this.roleRepo = options.roleRepo;
  }

  async create(req: IngressRequest, res: IngressResponse): Promise<void> {
    if (!req.actor) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        detail: 'Authentication required to create a workspace.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const body = req.body ?? {};
    const { name, slug } = body;

    if (!name || typeof name !== 'string' || !name.trim()) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Field "name" is required and cannot be empty.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const cleanName = name.trim();
    const cleanSlug = (typeof slug === 'string' && slug.trim()) ||
      cleanName.toLowerCase().replace(/[^a-z0-9]/g, '-') + `-${Date.now()}`;

    const wksIdRes = createWorkspaceId(generateUUIDv7());
    const wksId = wksIdRes.isOk ? wksIdRes.value : (generateUUIDv7() as WorkspaceId);

    const created = await this.workspaceRepo.create({
      id: wksId,
      organization_id: req.actor.organizationId,
      name: cleanName,
      slug: cleanSlug,
    });

    // Assign creator WORKSPACE_ADMIN role if role repository is configured
    if (this.roleRepo) {
      const adminRole = await this.roleRepo.findRoleByName('WORKSPACE_ADMIN');
      if (adminRole) {
        await this.roleRepo.assignUserRole(
          req.actor.id,
          adminRole.id,
          req.actor.organizationId,
          created.id
        );
      }
    }

    res.status(201).json(created);
  }

  async list(req: IngressRequest, res: IngressResponse): Promise<void> {
    if (!req.actor) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        detail: 'Authentication required to list workspaces.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const workspaces = await this.workspaceRepo.listByOrganization(req.actor.organizationId);
    res.status(200).json(workspaces);
  }

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.params['workspaceId'];
    if (!workspaceId) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: 'Workspace ID path parameter is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const workspace = await this.workspaceRepo.findById(workspaceId as WorkspaceId);
    if (!workspace) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
        detail: 'Workspace not found or access denied.',
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 404,
      });
      sendProblemDetails(res, problem);
      return;
    }

    res.status(200).json(workspace);
  }
}
