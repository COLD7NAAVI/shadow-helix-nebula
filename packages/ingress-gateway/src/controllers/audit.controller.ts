/**
 * Shadow : Helix Nebula (SHN) — Audit Ledger Controller
 *
 * Authoritative Spec: Phase 0.3 Context 7 (BC-AUD), Phase 0.14 Section 8.
 * Provides query access to immutable CanonicalEventEnvelope audit trails.
 */

import type { WorkspaceId, EventId } from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import { AuditEventRepository } from '@shn/data-access';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface AuditControllerOptions {
  auditRepo: AuditEventRepository;
}

export class AuditController {
  private readonly auditRepo: AuditEventRepository;

  constructor(options: AuditControllerOptions) {
    this.auditRepo = options.auditRepo;
  }

  async list(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId as WorkspaceId;
    const limit = req.query['limit'] ? parseInt(req.query['limit'], 10) : 50;

    try {
      const events = await this.auditRepo.listByWorkspace(workspaceId, limit);
      res.status(200).json(events);
    } catch {
      res.status(200).json([]);
    }
  }

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const eventId = req.params['eventId'] as EventId;
    if (!eventId) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Event ID is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    try {
      const event = await this.auditRepo.findByEventId(eventId);
      if (!event) {
        const problem = createProblemDetails({
          errorCode: ErrorCode.STORAGE_NOT_FOUND,
          detail: `Audit event "${eventId}" not found.`,
          instance: req.path,
          correlationId: req.correlationId,
          customStatus: 404,
        });
        sendProblemDetails(res, problem);
        return;
      }
      res.status(200).json(event);
    } catch {
      const problem = createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: `Audit event "${eventId}" not found.`,
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 404,
      });
      sendProblemDetails(res, problem);
    }
  }
}
