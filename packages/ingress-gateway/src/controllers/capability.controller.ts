/**
 * Shadow : Helix Nebula (SHN) — Capability Registry Controller
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Phase 0.8, Phase 0.14 Section 8.
 * Exposes abstract capability manifests, tool adapter providers, and workspace bindings.
 */

import type { WorkspaceId } from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { CapabilityRegistry, CapabilityCategory } from '@shn/capability-registry';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

const VALID_CATEGORIES: readonly string[] = [
  'RECONNAISSANCE',
  'DISCOVERY',
  'VULNERABILITY_SCAN',
  'EXPLOITATION',
  'ANALYSIS',
  'REPORTING',
  'UTILITY',
];

export interface CapabilityControllerOptions {
  registry: CapabilityRegistry;
}

export class CapabilityController {
  private readonly registry: CapabilityRegistry;

  constructor(options: CapabilityControllerOptions) {
    this.registry = options.registry;
  }

  async list(req: IngressRequest, res: IngressResponse): Promise<void> {
    const query = req.query;
    const rawCategory = query['category'];
    const category = (typeof rawCategory === 'string' && VALID_CATEGORIES.includes(rawCategory.toUpperCase()))
      ? (rawCategory.toUpperCase() as CapabilityCategory)
      : undefined;

    const capabilities = await this.registry.listCapabilities({
      category,
      state: 'ACTIVE',
    });

    res.status(200).json(capabilities);
  }

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const rawId = req.params['capabilityId'];
    if (!rawId) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: 'Capability ID is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const cap = await this.registry.findCapability(rawId);
    if (!cap) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.CAP_NOT_FOUND,
        detail: `Capability "${rawId}" not found.`,
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 404,
      });
      sendProblemDetails(res, problem);
      return;
    }

    res.status(200).json(cap);
  }

  async listForWorkspace(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const query = req.query;
    const rawCategory = query['category'];
    const category = (typeof rawCategory === 'string' && VALID_CATEGORIES.includes(rawCategory.toUpperCase()))
      ? (rawCategory.toUpperCase() as CapabilityCategory)
      : undefined;

    const capabilities = await this.registry.listCapabilities({
      workspaceId,
      category,
      state: 'ACTIVE',
    });

    res.status(200).json(capabilities);
  }
}
