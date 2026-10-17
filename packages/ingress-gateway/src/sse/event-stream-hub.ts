/**
 * Shadow : Helix Nebula (SHN) — Real-Time Server-Sent Events (SSE) Hub
 *
 * Authoritative Spec: Phase 0.5 (API-EVT-001, NFR-PRF-002), Phase 0.14 Perimeter B Section 18.
 * Provides durable multi-tenant event dispatching to connected operator Web Consoles and SSE clients.
 * Enforces strict workspace hermeticity: an operator connection strictly receives events matching
 * their authorized workspace boundary.
 */

import type { IngressRequest, IngressResponse } from '../contracts.js';
import { generateUUIDv7 } from '@shn/shared-kernel';

export interface StreamEvent {
  readonly id?: string | undefined;
  readonly type: string;
  readonly workspaceId: string;
  readonly payload: unknown;
  readonly timestamp: string;
}

export interface StreamClient {
  readonly id: string;
  readonly workspaceId: string;
  readonly userId?: string | undefined;
  readonly req: IngressRequest;
  readonly res: IngressResponse;
  heartbeatTimer?: NodeJS.Timeout | undefined;
  isAlive: boolean;
}

export interface EventStreamHubOptions {
  readonly heartbeatIntervalMs?: number;
  readonly maxConnectionsPerWorkspace?: number;
  readonly maxTotalConnections?: number;
}

export class EventStreamHub {
  private readonly clientsByWorkspace = new Map<string, Set<StreamClient>>();
  private totalEventsPublished = 0;
  private readonly heartbeatIntervalMs: number;
  private readonly maxConnectionsPerWorkspace: number;
  private readonly maxTotalConnections: number;
  private isDestroyed = false;

  constructor(optionsOrInterval: number | EventStreamHubOptions = 15000) {
    if (typeof optionsOrInterval === 'number') {
      this.heartbeatIntervalMs = optionsOrInterval;
      this.maxConnectionsPerWorkspace = 50;
      this.maxTotalConnections = 500;
    } else {
      this.heartbeatIntervalMs = optionsOrInterval.heartbeatIntervalMs ?? 15000;
      this.maxConnectionsPerWorkspace = optionsOrInterval.maxConnectionsPerWorkspace ?? 50;
      this.maxTotalConnections = optionsOrInterval.maxTotalConnections ?? 500;
    }
  }

  /**
   * Evaluates whether the hub is at connection capacity.
   */
  isAtCapacity(workspaceId?: string): boolean {
    if (this.isDestroyed) return true;
    if (this.subscriberCount() >= this.maxTotalConnections) return true;
    if (workspaceId && this.subscriberCount(workspaceId) >= this.maxConnectionsPerWorkspace) return true;
    return false;
  }

  /**
   * Registers a newly connected client for a specific workspace.
   */
  register(req: IngressRequest, res: IngressResponse, workspaceId: string, userId?: string): StreamClient {
    if (this.isAtCapacity(workspaceId)) {
      res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.status(429);
      res.raw.write(`event: error\ndata: ${JSON.stringify({ error: 'LIMIT_EXCEEDED', detail: 'Maximum concurrent SSE stream limit reached.' })}\n\n`);
      res.raw.end();
      throw new Error(`Maximum concurrent SSE stream limit reached for workspace ${workspaceId}`);
    }

    const clientId = generateUUIDv7();

    // Prepare HTTP response headers for SSE
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.status(200);

    // Send initial connection handshake event
    const handshakeData = JSON.stringify({
      status: 'CONNECTED',
      clientId,
      workspaceId,
      timestamp: new Date().toISOString(),
    });
    res.raw.write(`event: connected\ndata: ${handshakeData}\n\n`);

    const client: StreamClient = {
      id: clientId,
      workspaceId,
      userId,
      req,
      res,
      isAlive: true,
    };

    let set = this.clientsByWorkspace.get(workspaceId);
    if (!set) {
      set = new Set();
      this.clientsByWorkspace.set(workspaceId, set);
    }
    set.add(client);

    // Set up recurring heartbeat keep-alive
    client.heartbeatTimer = setInterval(() => {
      if (!client.isAlive || res.raw.destroyed || res.raw.writableEnded) {
        this.unregister(client);
        return;
      }
      try {
        res.raw.write(`: ping\n\n`);
      } catch {
        this.unregister(client);
      }
    }, this.heartbeatIntervalMs);
    client.heartbeatTimer.unref();

    // Listen for client disconnect
    req.raw.on('close', () => {
      this.unregister(client);
    });

    req.raw.on('error', () => {
      this.unregister(client);
    });

    return client;
  }

  /**
   * Unregisters a client, clearing timers and connections.
   */
  unregister(client: StreamClient): void {
    client.isAlive = false;
    if (client.heartbeatTimer) {
      clearInterval(client.heartbeatTimer);
      client.heartbeatTimer = undefined;
    }

    const set = this.clientsByWorkspace.get(client.workspaceId);
    if (set) {
      set.delete(client);
      if (set.size === 0) {
        this.clientsByWorkspace.delete(client.workspaceId);
      }
    }

    try {
      if (!client.res.raw.writableEnded && !client.res.raw.destroyed) {
        client.res.raw.end();
      }
    } catch {
      // Stream already closed
    }
  }

  /**
   * Publishes an event to all connected clients authorized for the given workspaceId.
   * Strictly enforces workspace isolation (DATA-INV-08, WKS-ISO-001).
   */
  publish(workspaceId: string, eventType: string, payload: unknown): number {
    this.totalEventsPublished++;
    const set = this.clientsByWorkspace.get(workspaceId);
    if (!set || set.size === 0) {
      return 0;
    }

    const eventId = generateUUIDv7();
    const timestamp = new Date().toISOString();
    const eventPayload: StreamEvent = {
      id: eventId,
      type: eventType,
      workspaceId,
      payload,
      timestamp,
    };

    const sseMessage = `id: ${eventId}\nevent: ${eventType}\ndata: ${JSON.stringify(eventPayload)}\n\n`;

    let deliveryCount = 0;
    for (const client of set) {
      if (!client.isAlive || client.res.raw.destroyed || client.res.raw.writableEnded) {
        this.unregister(client);
        continue;
      }

      try {
        client.res.raw.write(sseMessage);
        deliveryCount++;
      } catch {
        this.unregister(client);
      }
    }

    return deliveryCount;
  }

  /**
   * Returns active subscriber count, optionally filtered by workspace.
   */
  subscriberCount(workspaceId?: string): number {
    if (workspaceId) {
      return this.clientsByWorkspace.get(workspaceId)?.size || 0;
    }
    let total = 0;
    for (const set of this.clientsByWorkspace.values()) {
      total += set.size;
    }
    return total;
  }

  /**
   * Returns total events published.
   */
  getTotalEventsPublished(): number {
    return this.totalEventsPublished;
  }

  /**
   * Shuts down all active streams.
   */
  destroy(): void {
    this.isDestroyed = true;
    for (const set of this.clientsByWorkspace.values()) {
      for (const client of set) {
        this.unregister(client);
      }
    }
    this.clientsByWorkspace.clear();
  }
}
