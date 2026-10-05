/**
 * Shadow : Helix Nebula (SHN) — Sovereign Authorization & Identity Service
 *
 * Implements Phase 0.7 Section 4.1.2: IAuthorizationService
 * Enforces SEC-AUT-001, API-INV-01, SEC-INV-01, SEC-INV-05, and SEC-INV-12.
 */

import {
  type UserId,
  type OrganizationId,
  type WorkspaceId,
  type SessionId,
  type SecurityContextToken,
  isValidUUID,
  createSessionId,
  ok,
  err,
  type Result,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  type ProblemDetails,
} from '@shn/error-catalog';
import type {
  UserRepository,
  CredentialRepository,
  SessionRepository,
  RoleRepository,
  PermissionRepository,
  WorkspaceRepository,
} from '@shn/data-access';
import type { IEventPublisher } from '@shn/event-bus';
import type { ILogger, ITracer } from '@shn/telemetry';

import {
  type IAuthorizationService,
  type AuthSessionResult,
  type ClientInfo,
} from '../contracts.js';
import { PasswordHasher, defaultPasswordHasher } from '../password-hasher.js';
import { SecurityContextSigner } from '../crypto/security-context-signer.js';
import { SessionManager } from './session-manager.js';
import { makeAuthProblem } from '../errors.js';

export interface AuthorizationServiceOptions {
  readonly userRepo: UserRepository;
  readonly credentialRepo: CredentialRepository;
  readonly sessionRepo: SessionRepository;
  readonly roleRepo: RoleRepository;
  readonly permissionRepo: PermissionRepository;
  readonly signer: SecurityContextSigner;
  readonly workspaceRepo?: WorkspaceRepository | undefined;
  readonly passwordHasher?: PasswordHasher | undefined;
  readonly sessionManager?: SessionManager | undefined;
  readonly eventPublisher?: IEventPublisher | undefined;
  readonly logger?: ILogger | undefined;
  readonly tracer?: ITracer | undefined;
}

export class AuthorizationService implements IAuthorizationService {
  private readonly userRepo: UserRepository;
  private readonly credentialRepo: CredentialRepository;
  private readonly sessionRepo: SessionRepository;
  private readonly roleRepo: RoleRepository;
  private readonly permissionRepo: PermissionRepository;
  private readonly signer: SecurityContextSigner;
  private readonly workspaceRepo: WorkspaceRepository | undefined;
  private readonly passwordHasher: PasswordHasher;
  private readonly sessionManager: SessionManager;
  private readonly eventPublisher: IEventPublisher | undefined;
  private readonly logger: ILogger | undefined;
  private readonly tracer: ITracer | undefined;

  constructor(options: AuthorizationServiceOptions) {
    this.userRepo = options.userRepo;
    this.credentialRepo = options.credentialRepo;
    this.sessionRepo = options.sessionRepo;
    this.roleRepo = options.roleRepo;
    this.permissionRepo = options.permissionRepo;
    this.signer = options.signer;
    this.workspaceRepo = options.workspaceRepo;
    this.passwordHasher = options.passwordHasher ?? defaultPasswordHasher;
    this.sessionManager = options.sessionManager ?? new SessionManager(this.sessionRepo);
    this.eventPublisher = options.eventPublisher;
    this.logger = options.logger;
    this.tracer = options.tracer;
  }

  async authenticateSession(
    organizationId: OrganizationId | string,
    email: string,
    password: string,
    workspaceId?: WorkspaceId | string,
    clientInfo?: ClientInfo
  ): Promise<Result<AuthSessionResult, ProblemDetails>> {
    // 1. Fail-closed on malformed or empty inputs
    if (typeof organizationId !== 'string' || !isValidUUID(organizationId)) {
      return err(
        makeAuthProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Invalid OrganizationId: must be a valid UUID string',
          '/auth/login'
        )
      );
    }
    if (typeof email !== 'string' || !email.includes('@')) {
      // Execute dummy verify for timing protection
      await this.passwordHasher.verifyDummy(password || '');
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_CREDENTIALS_INVALID,
          'Invalid authentication credentials: valid email and password required',
          '/auth/login'
        )
      );
    }
    if (typeof password !== 'string' || password.length === 0) {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_CREDENTIALS_INVALID,
          'Password cannot be empty',
          '/auth/login'
        )
      );
    }
    if (workspaceId && (typeof workspaceId !== 'string' || !isValidUUID(workspaceId))) {
      return err(
        makeAuthProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Invalid WorkspaceId: must be a valid UUID string',
          '/auth/login'
        )
      );
    }

    const cleanEmail = email.trim().toLowerCase();

    // 2. Lookup user in IAM repository
    let user;
    try {
      user = await this.userRepo.findByEmail(organizationId as OrganizationId, cleanEmail);
    } catch {
      user = null;
    }

    if (!user) {
      // Execute dummy scrypt verification to prevent timing-based user enumeration
      await this.passwordHasher.verifyDummy(password);
      this.logger?.warn('Authentication failed: user not found', {
        organization_id: organizationId,
        email: cleanEmail,
      });
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_CREDENTIALS_INVALID,
          'Invalid authentication credentials: user not found or password incorrect',
          '/auth/login'
        )
      );
    }

    // 3. Check User Account Status
    if (user.status === 'DISABLED') {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_ACCOUNT_DISABLED,
          'User account has been disabled by an administrator',
          '/auth/login'
        )
      );
    }
    if (user.status === 'SUSPENDED' || user.status === 'REVOKED') {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_ACCOUNT_REVOKED,
          'User account has been revoked or suspended',
          '/auth/login'
        )
      );
    }

    // 4. Retrieve Credentials & Evaluate Account Lockout
    const credentials = await this.credentialRepo.findByUserId(user.id);
    if (!credentials) {
      await this.passwordHasher.verifyDummy(password);
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_CREDENTIALS_INVALID,
          'User credentials not initialized',
          '/auth/login'
        )
      );
    }

    if (credentials.locked_until && new Date(credentials.locked_until).getTime() > Date.now()) {
      this.logger?.warn('Authentication rejected: account locked', {
        user_id: user.id,
        locked_until: credentials.locked_until,
      });
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_ACCOUNT_LOCKED,
          `Account is temporarily locked until ${credentials.locked_until} due to consecutive failed attempts`,
          '/auth/login'
        )
      );
    }

    // 5. Constant-time cryptographic password verification
    const isPasswordValid = await this.passwordHasher.verifyPassword(
      password,
      credentials.password_hash
    );

    if (!isPasswordValid) {
      const lockoutStatus = await this.credentialRepo.recordFailedAttempt(user.id, 5, 15);
      this.logger?.warn('Authentication failed: invalid password', {
        user_id: user.id,
        failed_attempts: lockoutStatus.failedAttempts,
        is_locked: lockoutStatus.isLocked,
      });

      if (lockoutStatus.isLocked) {
        return err(
          makeAuthProblem(
            ErrorCode.AUTH_ACCOUNT_LOCKED,
            `Account locked due to ${lockoutStatus.failedAttempts} consecutive failed attempts`,
            '/auth/login'
          )
        );
      }

      return err(
        makeAuthProblem(
          ErrorCode.AUTH_CREDENTIALS_INVALID,
          'Invalid authentication credentials: user not found or password incorrect',
          '/auth/login'
        )
      );
    }

    // 6. Reset failed attempts upon successful password verification
    await this.credentialRepo.recordSuccessfulAuth(user.id);

    // 7. Verify Workspace Scope (if specified)
    let boundWorkspaceId: WorkspaceId | null = null;
    if (workspaceId) {
      if (this.workspaceRepo) {
        const ws = await this.workspaceRepo.findByIdAndOrganization(
          workspaceId as WorkspaceId,
          organizationId as OrganizationId
        );
        if (!ws) {
          return err(
            makeAuthProblem(
              ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
              `Workspace ${workspaceId} does not belong to organization ${organizationId}`,
              '/auth/login'
            )
          );
        }
      }
      boundWorkspaceId = workspaceId as WorkspaceId;
    } else if (this.workspaceRepo) {
      // Find the first active workspace in this organization as default anchor
      const orgWorkspaces = await this.workspaceRepo.listByOrganization(organizationId as OrganizationId);
      if (orgWorkspaces.length > 0) {
        boundWorkspaceId = orgWorkspaces[0]!.id;
      }
    }

    // Fallback to a zero-UUID workspace anchor if no workspace is yet created in organization
    const effectiveWorkspaceId: WorkspaceId = boundWorkspaceId ?? ('00000000-0000-7000-8000-000000000000' as WorkspaceId);

    // 8. Query User Roles & Aggregate Effective Permissions
    const userRoles = await this.roleRepo.getUserRoles(
      user.id,
      organizationId,
      boundWorkspaceId
    );
    const roleNames = userRoles.map((r) => r.role_name);
    const roleIds = userRoles.map((r) => r.role_id);

    const { bitmask } = await this.permissionRepo.getEffectivePermissions(roleIds);

    // 9. Generate Session Record, Bearer Token & Refresh Token
    const sessionIdRes = createSessionId();
    const sessionId = sessionIdRes.isOk ? sessionIdRes.value : ('00000000-0000-7000-8000-000000000001' as SessionId);

    const sessionResult = await this.sessionManager.createSession({
      sessionId,
      userId: user.id,
      organizationId,
      workspaceId: boundWorkspaceId,
      ipAddress: clientInfo?.ip_address ?? null,
      userAgent: clientInfo?.user_agent ?? null,
    });

    // 10. Issue HMAC-signed stateless SecurityContextToken
    const securityContextToken = this.signer.createToken({
      subjectId: user.id,
      subjectType: 'OPERATOR',
      workspaceId: effectiveWorkspaceId,
      roles: roleNames,
      permissionMask: bitmask,
    });

    this.logger?.info('Session authenticated successfully', {
      user_id: user.id,
      session_id: sessionResult.session.id,
      roles: roleNames,
    });

    return ok({
      user_id: user.id as UserId,
      organization_id: organizationId as OrganizationId,
      workspace_id: boundWorkspaceId,
      session: sessionResult.session,
      bearer_token: sessionResult.bearerToken,
      refresh_token: sessionResult.refreshToken,
      security_context_token: securityContextToken,
      roles: Object.freeze(roleNames),
      permission_mask: bitmask,
    });
  }

  async refreshSession(
    refreshToken: string,
    _clientInfo?: ClientInfo
  ): Promise<Result<AuthSessionResult, ProblemDetails>> {
    if (typeof refreshToken !== 'string' || refreshToken.trim().length === 0) {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_TOKEN_INVALID,
          'Refresh token must be a non-empty string',
          '/auth/refresh'
        )
      );
    }

    const session = await this.sessionManager.findByRefreshToken(refreshToken);
    if (!session || session.status !== 'ACTIVE') {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_SESSION_REVOKED,
          'Session is inactive or has been revoked',
          '/auth/refresh'
        )
      );
    }

    if (new Date(session.expires_at).getTime() <= Date.now()) {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_TOKEN_EXPIRED,
          'Session refresh window has expired',
          '/auth/refresh'
        )
      );
    }

    // Verify user is still active
    const user = await this.userRepo.findById(session.user_id);
    if (!user || user.status !== 'ACTIVE') {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_ACCOUNT_REVOKED,
          'User account is no longer active',
          '/auth/refresh'
        )
      );
    }

    // Rotate tokens
    const rotated = await this.sessionManager.rotateSession(session.id);

    // Recompute effective permissions
    const userRoles = await this.roleRepo.getUserRoles(
      user.id,
      session.organization_id,
      session.workspace_id
    );
    const roleNames = userRoles.map((r) => r.role_name);
    const roleIds = userRoles.map((r) => r.role_id);
    const { bitmask } = await this.permissionRepo.getEffectivePermissions(roleIds);

    const effectiveWorkspaceId: WorkspaceId =
      session.workspace_id ?? ('00000000-0000-7000-8000-000000000000' as WorkspaceId);

    const securityContextToken = this.signer.createToken({
      subjectId: user.id,
      subjectType: 'OPERATOR',
      workspaceId: effectiveWorkspaceId,
      roles: roleNames,
      permissionMask: bitmask,
    });

    return ok({
      user_id: user.id as UserId,
      organization_id: session.organization_id,
      workspace_id: session.workspace_id,
      session: rotated.session,
      bearer_token: rotated.newBearerToken,
      refresh_token: rotated.newRefreshToken,
      security_context_token: securityContextToken,
      roles: Object.freeze(roleNames),
      permission_mask: bitmask,
    });
  }

  async revokeToken(
    sessionId: SessionId | string,
    reason: string,
    _operatorContext?: SecurityContextToken
  ): Promise<Result<void, ProblemDetails>> {
    if (typeof sessionId !== 'string' || !isValidUUID(sessionId)) {
      return err(
        makeAuthProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Invalid SessionId: must be a valid UUID',
          '/auth/revoke'
        )
      );
    }

    await this.sessionManager.revokeSession(sessionId, reason || 'Revoked by operator');
    this.logger?.info('Session revoked', { session_id: sessionId, reason });

    return ok(undefined);
  }

  evaluatePermission(
    token: SecurityContextToken,
    requiredPermissionBit: number,
    targetWorkspaceId?: WorkspaceId | string
  ): Result<boolean, ProblemDetails> {
    // 1. Verify token signature and expiration
    const verifyRes = this.signer.verifyToken(token);
    if (!verifyRes.isOk) {
      return err(verifyRes.error);
    }

    const verifiedToken = verifyRes.value;

    // 2. Enforce workspace isolation if targetWorkspaceId is supplied
    if (targetWorkspaceId) {
      if (typeof targetWorkspaceId !== 'string' || !isValidUUID(targetWorkspaceId)) {
        return err(
          makeAuthProblem(
            ErrorCode.INVALID_PAYLOAD_SCHEMA,
            'Invalid target WorkspaceId: must be a valid UUID',
            '/auth/evaluate'
          )
        );
      }

      if (verifiedToken.workspace_id !== targetWorkspaceId) {
        return err(
          makeAuthProblem(
            ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
            `Cross-workspace access denied: token workspace (${verifiedToken.workspace_id}) does not match target (${targetWorkspaceId})`,
            '/auth/evaluate'
          )
        );
      }
    }

    // 3. Fast microsecond bitwise permission check
    const hasPermission = (verifiedToken.permission_mask & requiredPermissionBit) === requiredPermissionBit;
    if (!hasPermission) {
      return err(
        makeAuthProblem(
          ErrorCode.AUTH_FORBIDDEN,
          `Access forbidden: required permission bit (0x${requiredPermissionBit.toString(16)}) not granted`,
          '/auth/evaluate'
        )
      );
    }

    return ok(true);
  }

  enforceTenantIsolation(
    token: SecurityContextToken,
    targetOrganizationId: OrganizationId | string,
    targetWorkspaceId?: WorkspaceId | string
  ): Result<void, ProblemDetails> {
    if (typeof targetOrganizationId !== 'string' || !isValidUUID(targetOrganizationId)) {
      return err(
        makeAuthProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Invalid target OrganizationId: must be a valid UUID',
          '/auth/isolation'
        )
      );
    }

    const verifyRes = this.signer.verifyToken(token);
    if (!verifyRes.isOk) {
      return err(verifyRes.error);
    }

    const verifiedToken = verifyRes.value;

    if (targetWorkspaceId) {
      if (typeof targetWorkspaceId !== 'string' || !isValidUUID(targetWorkspaceId)) {
        return err(
          makeAuthProblem(
            ErrorCode.INVALID_PAYLOAD_SCHEMA,
            'Invalid target WorkspaceId: must be a valid UUID',
            '/auth/isolation'
          )
        );
      }

      if (verifiedToken.workspace_id !== targetWorkspaceId) {
        return err(
          makeAuthProblem(
            ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
            `Cross-workspace boundary violation: token workspace ${verifiedToken.workspace_id} != target ${targetWorkspaceId}`,
            '/auth/isolation'
          )
        );
      }
    }

    return ok(undefined);
  }

  // Getter for underlying components
  getEventPublisher(): IEventPublisher | undefined {
    return this.eventPublisher;
  }

  getTracer(): ITracer | undefined {
    return this.tracer;
  }
}
