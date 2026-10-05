/**
 * Shadow : Helix Nebula (SHN) — Tenancy Boundary Validator
 *
 * Enforces SEC-INV-05, INV-01, and INV-19:
 * - Deterministic Organization -> Workspace tenancy hierarchy
 * - Cross-tenant and cross-workspace access prohibition
 * - Strict UUID validation
 * - Fail-closed enforcement on missing or mismatched context
 */

import {
  type OrganizationId,
  type WorkspaceId,
  type SecurityContextToken,
  isValidUUID,
  ok,
  err,
  type Result,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import type { WorkspaceRepository, OrganizationRepository } from '@shn/data-access';
import { makeScopeProblem } from '../errors.js';

export interface TenancyValidationContext {
  readonly organizationId: OrganizationId;
  readonly workspaceId: WorkspaceId;
}

export class TenancyValidator {
  constructor(
    private readonly workspaceRepo?: WorkspaceRepository,
    private readonly orgRepo?: OrganizationRepository
  ) {}

  /**
   * Validates that organizationId and workspaceId are structurally valid UUIDs.
   */
  validateIdentifiers(
    orgId: string | undefined,
    wsId: string | undefined
  ): Result<TenancyValidationContext, ProblemDetails> {
    if (!orgId || typeof orgId !== 'string' || !isValidUUID(orgId)) {
      return err(
        makeScopeProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          `Invalid or missing organizationId: '${orgId}'`
        )
      );
    }

    if (!wsId || typeof wsId !== 'string' || !isValidUUID(wsId)) {
      return err(
        makeScopeProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          `Invalid or missing workspaceId: '${wsId}'`
        )
      );
    }

    return ok({
      organizationId: orgId as OrganizationId,
      workspaceId: wsId as WorkspaceId,
    });
  }

  /**
   * Asserts that a security context's workspace matches the target resource workspace.
   */
  assertWorkspaceMatch(
    context: SecurityContextToken,
    resourceWorkspaceId: WorkspaceId
  ): Result<void, ProblemDetails> {
    if (context.workspace_id !== resourceWorkspaceId) {
      return err(
        makeScopeProblem(
          ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          `Security context workspace '${context.workspace_id}' does not match target resource workspace '${resourceWorkspaceId}'`
        )
      );
    }
    return ok(undefined);
  }

  /**
   * If repositories are present, verifies from persistence that the workspace
   * actually belongs to the given organization.
   */
  async verifyWorkspaceBelongsToOrg(
    workspaceId: WorkspaceId,
    organizationId: OrganizationId
  ): Promise<Result<void, ProblemDetails>> {
    if (!this.workspaceRepo) {
      // If no repository wired (e.g. pure unit test), rely on explicit context validation
      return ok(undefined);
    }

    try {
      if (this.orgRepo) {
        const org = await this.orgRepo.findById(organizationId);
        if (!org) {
          return err(
            makeScopeProblem(
              ErrorCode.STORAGE_NOT_FOUND,
              `Organization '${organizationId}' does not exist`
            )
          );
        }
      }

      const ws = await this.workspaceRepo.findById(workspaceId);
      if (!ws) {
        return err(
          makeScopeProblem(
            ErrorCode.STORAGE_NOT_FOUND,
            `Workspace '${workspaceId}' does not exist`
          )
        );
      }

      if (ws.organization_id !== organizationId) {
        return err(
          makeScopeProblem(
            ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
            `Workspace '${workspaceId}' belongs to organization '${ws.organization_id}', not '${organizationId}'`
          )
        );
      }

      return ok(undefined);
    } catch (e) {
      return err(
        makeScopeProblem(
          ErrorCode.INTERNAL_FAULT,
          `Failed to verify workspace tenancy: ${(e as Error).message}`
        )
      );
    }
  }
}
