/**
 * Shadow : Helix Nebula (SHN) — Real-Time Event Stream Controller
 *
 * Exposes the Server-Sent Events (SSE) subscription endpoint for active workspaces.
 */

import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import type { EventStreamHub } from '../sse/event-stream-hub.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface EventStreamControllerOptions {
  hub: EventStreamHub;
}

export class EventStreamController {
  private readonly hub: EventStreamHub;

  constructor(options: EventStreamControllerOptions) {
    this.hub = options.hub;
  }

  async streamEvents(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.params.workspaceId;
    if (!workspaceId) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'workspaceId route parameter is required.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    // Tenancy is already validated by tenancyMiddleware, so the actor is authorized.
    const actorId = req.actor?.id;

    // Register SSE connection with hub
    this.hub.register(req, res, workspaceId, actorId);
  }
}
