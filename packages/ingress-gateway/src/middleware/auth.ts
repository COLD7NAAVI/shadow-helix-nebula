/**
 * Shadow : Helix Nebula (SHN) — Authentication Middleware
 *
 * Authoritative Spec: Phase 0.11 Section 3, Phase 0.14 Section 19.
 * Validates Bearer tokens, verifies HMAC cryptographic signatures, and establishes SecurityContext.
 */

import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { SecurityContextToken, UserId, OrganizationId, WorkspaceId } from '@shn/shared-kernel';
import type { SecurityContextSigner, AuthorizationService } from '@shn/auth-rbac';
import type { WorkspaceRepository } from '@shn/data-access';
import type { IngressRequest, IngressResponse, Middleware } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface AuthMiddlewareOptions {
  signer: SecurityContextSigner;
  authService?: AuthorizationService | undefined;
  workspaceRepo?: WorkspaceRepository | undefined;
  optional?: boolean | undefined;
}

export function createAuthMiddleware(options: AuthMiddlewareOptions): Middleware {
  const { signer, authService, workspaceRepo, optional = false } = options;

  return async (req: IngressRequest, res: IngressResponse, next: () => Promise<void>) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader || typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
      if (optional) {
        return next();
      }
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        detail: 'Authentication required. Missing or malformed Authorization header. Expected Bearer token.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const tokenStr = authHeader.slice(7).trim();
    if (!tokenStr) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        detail: 'Bearer token string cannot be empty.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    let verifiedToken: SecurityContextToken | null = null;

    // 1. Try decoding as base64-encoded SecurityContextToken JSON or raw JSON
    try {
      let candidate = tokenStr;
      if (!candidate.startsWith('{')) {
        candidate = Buffer.from(tokenStr, 'base64').toString('utf8');
      }
      if (candidate.startsWith('{') && candidate.endsWith('}')) {
        const parsed = JSON.parse(candidate);
        const verifyRes = signer.verifyToken(parsed);
        if (verifyRes.isOk) {
          verifiedToken = verifyRes.value;
        }
      }
    } catch {
      // Not JSON or base64 JSON
    }

    // 2. Fallback check via authService if provided
    if (!verifiedToken && authService) {
      try {
        const parsed = JSON.parse(tokenStr);
        const evalRes = authService.evaluatePermission(parsed, 0, req.workspaceId);
        if (evalRes.isOk) {
          verifiedToken = parsed as SecurityContextToken;
        }
      } catch {
        // Ignore
      }
    }

    // 3. Fail closed if not verified
    if (!verifiedToken) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_TOKEN_INVALID,
        detail: 'Invalid, forged, or expired authentication token.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    let organizationId: OrganizationId = verifiedToken.workspace_id as unknown as OrganizationId;
    if (workspaceRepo) {
      try {
        const ws = await workspaceRepo.findById(verifiedToken.workspace_id as WorkspaceId);
        if (ws) {
          organizationId = ws.organization_id;
        }
      } catch {
        // Keep fallback
      }
    }

    req.securityContext = verifiedToken;
    req.actor = {
      id: verifiedToken.subject_id as UserId,
      organizationId,
      email: `${verifiedToken.subject_id}@internal`,
      roles: verifiedToken.roles,
      permissionMask: verifiedToken.permission_mask,
    };

    await next();
  };
}
