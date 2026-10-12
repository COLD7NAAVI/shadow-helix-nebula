/**
 * Shadow : Helix Nebula (SHN) — Capability Registry & Base Tool Adapter Contracts
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Phase 0.4 (INV-01, INV-03, INV-04),
 *                    Phase 0.7 Section 4.2.3 (mod_capability_registry),
 *                    Phase 0.8 (Plugin & Adapter Architecture),
 *                    Phase 0.9 (Tool Integration Architecture),
 *                    Phase 0.10, Phase 0.14
 */

import type {
  CapabilityId,
  AdapterId,
  WorkspaceId,
  OrganizationId,
  UserId,
  ScopeId,
  ExecutionId,
  SecurityContextToken,
  Result,
} from '@shn/shared-kernel';
import type { ProblemDetails } from '@shn/error-catalog';
import type { ScopeDefinition, ScopeToken } from '@shn/scope-gatekeeper';
import type {
  ExecutionState,
  ExecutionTerminationReason,
  ResourceLimits,
} from '@shn/execution-supervisor';

// ----------------------------------------------------------------------------
// 1. Classification & Domain Types
// ----------------------------------------------------------------------------

export type CapabilityLifecycleState =
  | 'DRAFT'
  | 'ACTIVE'
  | 'DEPRECATED'
  | 'DISABLED'
  | 'REVOKED';

export type AdapterLifecycleState =
  | 'DISCOVERED'
  | 'REGISTERED'
  | 'VALIDATED'
  | 'ENABLED'
  | 'AVAILABLE'
  | 'DISABLED'
  | 'REVOKED';

export type CapabilityCategory =
  | 'RECONNAISSANCE'
  | 'DISCOVERY'
  | 'VULNERABILITY_SCAN'
  | 'EXPLOITATION'
  | 'ANALYSIS'
  | 'REPORTING'
  | 'UTILITY';

export type RiskClassification =
  | 'INFORMATIONAL'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'
  | 'INVASIVE';

export type TargetType =
  | 'IP'
  | 'CIDR'
  | 'DOMAIN'
  | 'URL'
  | 'HOST';

export type PlatformType = 'linux' | 'darwin' | 'win32';

// ----------------------------------------------------------------------------
// 2. Capability Contracts
// ----------------------------------------------------------------------------

export interface CapabilityDefinition {
  readonly id: CapabilityId;
  readonly name: string;
  readonly version: string;
  readonly displayName: string;
  readonly description: string;
  readonly category: CapabilityCategory;
  readonly riskLevel: RiskClassification;
  readonly supportedTargets: readonly TargetType[];
  readonly requiredPermissions: number;
  readonly requiredScopeAction: string;
  readonly argumentSchema: Record<string, unknown>;
  readonly outputSchema: Record<string, unknown>;
  readonly environmentRequirements?: Record<string, unknown> | undefined;
  readonly resourceRequirements?: Partial<ResourceLimits> | undefined;
  readonly platformCompatibility: readonly PlatformType[];
  readonly lifecycleState: CapabilityLifecycleState;
  readonly integrityDigest: string;
  readonly workspaceId?: WorkspaceId | null | undefined;
  readonly metadata?: Record<string, unknown> | undefined;
}

export interface AdapterCapabilityBinding {
  readonly capabilityId: CapabilityId;
  readonly versionConstraint: string;
  readonly supportedTargetTypes?: readonly TargetType[] | undefined;
  readonly priority?: number | undefined;
}

export interface ToolAdapterDefinition {
  readonly id: AdapterId;
  readonly name: string;
  readonly version: string;
  readonly lifecycleState: AdapterLifecycleState;
  readonly supportedCapabilities: readonly AdapterCapabilityBinding[];
  readonly platformCompatibility: readonly PlatformType[];
  readonly binaryPath: string;
  readonly manifestDigest: string;
  readonly workspaceId?: WorkspaceId | null | undefined;
  readonly metadata?: Record<string, unknown> | undefined;
}

// ----------------------------------------------------------------------------
// 3. Evidence & Adapter Outputs
// ----------------------------------------------------------------------------

export interface EvidenceArtifact {
  readonly name: string;
  readonly mimeType: string;
  readonly contentSha256: string;
  readonly content: Buffer | string;
  readonly byteSize: number;
  readonly storageUri?: string | undefined;
}

export interface AdapterExecutionOutput {
  readonly exitCode: number;
  readonly rawOutput: string;
  readonly rawStderr: string;
  readonly rawOutputSha256: string;
  readonly parsedPayload?: unknown | undefined;
  readonly findings?: readonly unknown[] | undefined;
  readonly artifacts: readonly EvidenceArtifact[];
}

export interface CommandVector {
  readonly executable: string;
  readonly args: readonly string[];
  readonly env?: Record<string, string> | undefined;
  readonly inputPayload?: unknown | undefined;
  readonly resourceLimits?: Partial<ResourceLimits> | undefined;
}

// ----------------------------------------------------------------------------
// 4. Base Tool Adapter Interface
// ----------------------------------------------------------------------------

export interface IToolAdapter {
  readonly adapterId: AdapterId;
  readonly name: string;
  readonly version: string;
  readonly platformSupport: readonly PlatformType[];
  readonly supportedCapabilities: readonly AdapterCapabilityBinding[];

  getLifecycleState(): AdapterLifecycleState;
  setLifecycleState(state: AdapterLifecycleState): void;

  validateParameters(
    capability: CapabilityDefinition,
    params: Record<string, unknown>
  ): Result<Record<string, unknown>, ProblemDetails>;

  validateTarget(
    capability: CapabilityDefinition,
    target: string,
    port?: number
  ): Result<void, ProblemDetails>;

  buildCommand(
    capability: CapabilityDefinition,
    target: string,
    params: Record<string, unknown>,
    port?: number
  ): Result<CommandVector, ProblemDetails>;

  parseOutput(
    rawOutput: string,
    rawStderr: string,
    exitCode: number,
    sha256: string
  ): Result<AdapterExecutionOutput, ProblemDetails>;

  classifyError(
    exitCode: number,
    rawStderr: string
  ): ExecutionTerminationReason;

  extractEvidence(
    rawOutput: string,
    rawStderr: string,
    sha256: string
  ): readonly EvidenceArtifact[];

  checkReadiness(): Promise<Result<{ ready: boolean; details?: string }, ProblemDetails>>;
}

// ----------------------------------------------------------------------------
// 5. Capability Registry Interface
// ----------------------------------------------------------------------------

export interface ResolveProviderOptions {
  readonly workspaceId?: WorkspaceId | undefined;
  readonly target?: string | undefined;
  readonly preferredAdapterId?: AdapterId | string | undefined;
}

export interface ListCapabilitiesFilter {
  readonly workspaceId?: WorkspaceId | undefined;
  readonly category?: CapabilityCategory | undefined;
  readonly state?: CapabilityLifecycleState | undefined;
  readonly targetType?: TargetType | undefined;
}

export interface ListAdaptersFilter {
  readonly workspaceId?: WorkspaceId | undefined;
  readonly capabilityId?: CapabilityId | string | undefined;
  readonly state?: AdapterLifecycleState | undefined;
}

export interface WorkspaceBindingConfig {
  readonly preferredAdapterId?: string | undefined;
  readonly isEnabled: boolean;
  readonly overrides?: Record<string, unknown> | undefined;
}

export interface ICapabilityRegistry {
  registerCapability(
    capability: CapabilityDefinition,
    workspaceId?: WorkspaceId
  ): Promise<Result<CapabilityDefinition, ProblemDetails>>;

  findCapability(
    id: CapabilityId | string,
    workspaceId?: WorkspaceId
  ): Promise<CapabilityDefinition | null>;

  listCapabilities(
    filter?: ListCapabilitiesFilter
  ): Promise<readonly CapabilityDefinition[]>;

  updateCapabilityState(
    id: CapabilityId | string,
    state: CapabilityLifecycleState,
    workspaceId?: WorkspaceId
  ): Promise<Result<void, ProblemDetails>>;

  registerAdapter(
    adapter: IToolAdapter,
    workspaceId?: WorkspaceId
  ): Promise<Result<void, ProblemDetails>>;

  findAdapter(
    id: AdapterId | string,
    workspaceId?: WorkspaceId
  ): Promise<IToolAdapter | null>;

  listAdapters(
    filter?: ListAdaptersFilter
  ): Promise<readonly IToolAdapter[]>;

  updateAdapterState(
    id: AdapterId | string,
    state: AdapterLifecycleState,
    workspaceId?: WorkspaceId
  ): Promise<Result<void, ProblemDetails>>;

  setWorkspaceBinding(
    workspaceId: WorkspaceId,
    capabilityId: CapabilityId | string,
    preferredAdapterId: AdapterId | string,
    isEnabled?: boolean,
    overrides?: Record<string, unknown> | undefined
  ): Promise<Result<void, ProblemDetails>>;

  getWorkspaceBinding(
    workspaceId: WorkspaceId,
    capabilityId: CapabilityId | string
  ): Promise<WorkspaceBindingConfig | null>;

  resolveProvider(
    capabilityId: CapabilityId | string,
    options?: ResolveProviderOptions
  ): Promise<Result<IToolAdapter, ProblemDetails>>;
}

// ----------------------------------------------------------------------------
// 6. Capability Execution Gateway / Dispatcher Contracts
// ----------------------------------------------------------------------------

export interface CapabilityExecutionRequest {
  readonly capabilityId: CapabilityId | string;
  readonly target: string;
  readonly port?: number | undefined;
  readonly parameters?: Record<string, unknown> | undefined;
  readonly securityContext: SecurityContextToken;
  readonly workspaceId: WorkspaceId;
  readonly organizationId: OrganizationId;
  readonly actorId: UserId;
  readonly scopeId?: ScopeId | undefined;
  readonly scopeToken?: ScopeToken | undefined;
  readonly scopeOverride?: ScopeDefinition | undefined;
  readonly preferredAdapterId?: AdapterId | string | undefined;
  readonly resourceLimits?: Partial<ResourceLimits> | undefined;
}

export interface CapabilityExecutionResult {
  readonly executionId: ExecutionId;
  readonly capabilityId: CapabilityId;
  readonly adapterId: AdapterId;
  readonly state: ExecutionState;
  readonly exitCode: number;
  readonly rawOutput: string;
  readonly rawStderr: string;
  readonly rawOutputSha256: string;
  readonly durationMs: number;
  readonly output?: AdapterExecutionOutput | undefined;
  readonly failureDetails?: ProblemDetails | undefined;
}
