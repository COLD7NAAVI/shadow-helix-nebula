/**
 * Shadow : Helix Nebula (SHN) — Ingress API Gateway Server
 *
 * Authoritative Spec: Phase 0.3 (Perimeter A/B), Phase 0.14 (Level 2/3 REST, RFC 7807).
 * Hardened HTTP server with streaming payload size limits, request timeouts, and CORS.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type {
  GatewayConfig,
  IngressRequest,
  IngressResponse,
} from './contracts.js';
import { Router } from './routing/router.js';
import { createCorrelationMiddleware } from './middleware/correlation.js';
import { createRateLimiterMiddleware } from './middleware/rate-limiter.js';
import { sendProblemDetails, handleUnhandledError } from './errors/problem-details-filter.js';

import type { EventStreamHub } from './sse/event-stream-hub.js';

export interface IngressServerDependencies {
  config?: Partial<GatewayConfig> | undefined;
  router?: Router | undefined;
  pool?: any | undefined;
  eventStreamHub?: EventStreamHub | undefined;
}

export class IngressServer {
  private readonly config: GatewayConfig;
  private readonly router: Router;
  private readonly pool: any | null = null;
  private readonly eventStreamHub: EventStreamHub | null = null;
  private server: Server | null = null;

  constructor(deps?: IngressServerDependencies) {
    this.config = {
      port: deps?.config?.port ?? Number(process.env.SHN_PORT || 8080),
      host: deps?.config?.host ?? (process.env.SHN_HOST || '0.0.0.0'),
      timeoutMs: deps?.config?.timeoutMs ?? 30000,
      maxBodySizeBytes: deps?.config?.maxBodySizeBytes ?? 1048576, // 1MB
      corsAllowedOrigins: deps?.config?.corsAllowedOrigins ?? ['*'],
      rateLimitMaxRequests: deps?.config?.rateLimitMaxRequests ?? 200,
      rateLimitWindowMs: deps?.config?.rateLimitWindowMs ?? 60000,
    };

    this.router = deps?.router ?? new Router();
    this.pool = deps?.pool ?? null;
    this.eventStreamHub = deps?.eventStreamHub ?? null;

    // Attach standard edge middlewares
    this.router.use(createCorrelationMiddleware());
    this.router.use(createRateLimiterMiddleware(this.config.rateLimitMaxRequests, this.config.rateLimitWindowMs));
  }

  getRouter(): Router {
    return this.router;
  }

  async start(): Promise<{ port: number; host: string }> {
    return new Promise((resolve, reject) => {
      this.server = createServer(async (req, res) => {
        await this.handleHttpRequest(req, res);
      });

      this.server.setTimeout(this.config.timeoutMs);

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(this.config.port, this.config.host, () => {
        const address = this.server?.address();
        const actualPort = typeof address === 'object' && address ? address.port : this.config.port;
        resolve({ port: actualPort, host: this.config.host });
      });
    });
  }

  async stop(): Promise<void> {
    if (this.eventStreamHub) {
      try {
        this.eventStreamHub.destroy();
      } catch {
        // SSE cleanup error ignored on shutdown
      }
    }
    if (this.pool && typeof this.pool.end === 'function') {
      try {
        await this.pool.end();
      } catch {
        // Pool end error ignored on shutdown
      }
    }
    return new Promise((resolve) => {
      if (this.server) {
        if (typeof (this.server as any).closeAllConnections === 'function') {
          (this.server as any).closeAllConnections();
        }
        this.server.close(() => {
          this.server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private async handleHttpRequest(rawReq: IncomingMessage, rawRes: ServerResponse): Promise<void> {
    const rawUrl = rawReq.url || '/';
    const parsedUrl = new URL(rawUrl, `http://${rawReq.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;

    // Handle CORS preflight requests immediately fail-safe
    if (rawReq.method === 'OPTIONS') {
      rawRes.setHeader('Access-Control-Allow-Origin', this.config.corsAllowedOrigins.join(', '));
      rawRes.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      rawRes.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Correlation-ID, X-Request-ID, X-Trace-ID');
      rawRes.setHeader('Access-Control-Max-Age', '86400');
      rawRes.statusCode = 204;
      rawRes.end();
      return;
    }

    const query: Record<string, string> = {};
    for (const [k, v] of parsedUrl.searchParams.entries()) {
      query[k] = v;
    }

    const clientIp =
      (typeof rawReq.headers['x-forwarded-for'] === 'string' && rawReq.headers['x-forwarded-for'].split(',')[0]?.trim()) ||
      rawReq.socket.remoteAddress ||
      '127.0.0.1';

    let statusCode = 200;

    const responseWrapper: IngressResponse = {
      raw: rawRes,
      status(code: number) {
        statusCode = code;
        rawRes.statusCode = code;
        return this;
      },
      setHeader(name: string, value: string | number | readonly string[]) {
        rawRes.setHeader(name, value as any);
        return this;
      },
      json(payload: unknown) {
        if (!rawRes.headersSent) {
          rawRes.statusCode = statusCode;
          rawRes.setHeader('Content-Type', 'application/json; charset=utf-8');
          rawRes.end(JSON.stringify(payload));
        }
      },
      text(payload: string, contentType = 'text/plain; charset=utf-8') {
        if (!rawRes.headersSent) {
          rawRes.statusCode = statusCode;
          rawRes.setHeader('Content-Type', contentType);
          rawRes.end(payload);
        }
      },
      problem(pd) {
        sendProblemDetails(this, pd);
      },
      empty(code?: number) {
        if (!rawRes.headersSent) {
          rawRes.statusCode = code ?? statusCode;
          rawRes.end();
        }
      },
    };

    // Apply hardened production security & CORS headers
    rawRes.setHeader('Access-Control-Allow-Origin', this.config.corsAllowedOrigins.join(', '));
    rawRes.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    rawRes.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Correlation-ID, X-Request-ID, X-Trace-ID');
    rawRes.setHeader('X-Content-Type-Options', 'nosniff');
    rawRes.setHeader('X-Frame-Options', 'DENY');
    rawRes.setHeader('X-XSS-Protection', '1; mode=block');
    rawRes.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    rawRes.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    rawRes.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    rawRes.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss:; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';");

    // Read and buffer body with size limits
    let rawBody = '';
    let bytesRead = 0;
    let payloadTooLarge = false;

    try {
      if (['POST', 'PUT', 'PATCH'].includes(rawReq.method || '')) {
        for await (const chunk of rawReq) {
          bytesRead += chunk.length;
          if (bytesRead > this.config.maxBodySizeBytes) {
            payloadTooLarge = true;
            break;
          }
          rawBody += chunk.toString('utf8');
        }
      }

      const requestWrapper: IngressRequest = {
        raw: rawReq,
        method: (rawReq.method || 'GET').toUpperCase(),
        url: rawUrl,
        path: pathname,
        query,
        params: {},
        headers: rawReq.headers,
        body: undefined,
        correlationId: '',
        requestId: '',
        traceId: '',
        clientIp,
      };

      if (payloadTooLarge) {
        const problem = createProblemDetails({
          errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
          detail: `Payload size exceeded maximum allowed limit of ${this.config.maxBodySizeBytes} bytes.`,
          instance: pathname,
          correlationId: requestWrapper.correlationId || 'pre-correlation',
          customStatus: 413,
        });
        sendProblemDetails(responseWrapper, problem);
        return;
      }

      if (rawBody.trim().length > 0) {
        try {
          requestWrapper.body = JSON.parse(rawBody);
        } catch {
          const problem = createProblemDetails({
            errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
            detail: 'Malformed JSON payload.',
            instance: pathname,
            correlationId: requestWrapper.correlationId || 'pre-correlation',
            customStatus: 400,
          });
          sendProblemDetails(responseWrapper, problem);
          return;
        }
      }

      await this.router.handle(requestWrapper, responseWrapper);
    } catch (err: unknown) {
      const fallbackReq: IngressRequest = {
        raw: rawReq,
        method: (rawReq.method || 'GET').toUpperCase(),
        url: rawUrl,
        path: pathname,
        query,
        params: {},
        headers: rawReq.headers,
        body: undefined,
        correlationId: 'err-correlation',
        requestId: 'err-request',
        traceId: 'err-trace',
        clientIp,
      };
      handleUnhandledError(err, fallbackReq, responseWrapper);
    }
  }
}
