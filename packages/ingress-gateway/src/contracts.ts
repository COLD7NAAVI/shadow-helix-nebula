/**
 * Shadow : Helix Nebula (SHN) — Ingress Gateway Contracts
 *
 * Authoritative Spec: Phase 0.3 (Perimeter A/B), Phase 0.4 (INV-01, INV-02),
 * Phase 0.11 (Trust Zones 0/1), Phase 0.14 (Level 2/3 REST, RFC 7807, Perimeter B).
 */

import type { IncomingMessage, ServerResponse, IncomingHttpHeaders } from 'node:http';
import type {
  UserId,
  WorkspaceId,
  OrganizationId,
  SecurityContextToken,
} from '@shn/shared-kernel';
import type { ProblemDetails } from '@shn/error-catalog';

export interface GatewayConfig {
  readonly port: number;
  readonly host: string;
  readonly timeoutMs: number;
  readonly maxBodySizeBytes: number;
  readonly corsAllowedOrigins: readonly string[];
  readonly rateLimitMaxRequests: number;
  readonly rateLimitWindowMs: number;
}

export interface IngressRequest {
  readonly raw: IncomingMessage;
  readonly method: string;
  readonly url: string;
  readonly path: string;
  readonly query: Record<string, string>;
  params: Record<string, string>;
  readonly headers: IncomingHttpHeaders;
  body: any;
  readonly correlationId: string;
  readonly requestId: string;
  readonly traceId: string;
  readonly clientIp: string;
  securityContext?: SecurityContextToken | undefined;
  actor?: {
    readonly id: UserId;
    readonly organizationId: OrganizationId;
    readonly email: string;
    readonly roles: readonly string[];
    readonly permissionMask: number;
  } | undefined;
  workspaceId?: WorkspaceId | undefined;
}

export interface IngressResponse {
  readonly raw: ServerResponse;
  status(code: number): IngressResponse;
  setHeader(name: string, value: string | number | readonly string[]): IngressResponse;
  json(payload: unknown): void;
  text(payload: string, contentType?: string): void;
  problem(pd: ProblemDetails): void;
  empty(code?: number): void;
}

export type RouteHandler = (req: IngressRequest, res: IngressResponse) => Promise<void>;
export type Middleware = (
  req: IngressRequest,
  res: IngressResponse,
  next: () => Promise<void>
) => Promise<void>;

export interface CliOptions {
  readonly url?: string | undefined;
  readonly token?: string | undefined;
  readonly format?: 'text' | 'json' | undefined;
  readonly [key: string]: any;
}

export interface CliCommandResult {
  readonly exitCode: number;
  readonly output: string;
  readonly error?: string | undefined;
}
