/**
 * Shadow : Helix Nebula (SHN) — Authoritative Capability Registry
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Phase 0.4 (INV-01, INV-03, INV-04),
 *                    Phase 0.7 Section 4.2.3 (mod_capability_registry),
 *                    Phase 0.8 (Plugin & Adapter Architecture),
 *                    Phase 0.9 (Multi-Provider Capability Resolution & Tool Selection)
 */

import {
  ok,
  err,
  type Result,
  type WorkspaceId,
  type CapabilityId,
  type AdapterId,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { makeCapabilityProblem } from '../errors.js';
import { validateCapabilityManifest } from '../manifests/validator.js';
import { satisfiesVersion, compareSemVer, parseSemVer } from '../versioning/semver.js';
import type {
  ICapabilityRegistry,
  CapabilityDefinition,
  IToolAdapter,
  CapabilityLifecycleState,
  AdapterLifecycleState,
  ResolveProviderOptions,
  ListCapabilitiesFilter,
  ListAdaptersFilter,
  PlatformType,
  WorkspaceBindingConfig,
} from '../contracts.js';
import type { CapabilityRepository } from '@shn/data-access';

export interface CapabilityRegistryOptions {
  readonly repository?: CapabilityRepository | undefined;
  readonly platform?: PlatformType | undefined;
}

export class CapabilityRegistry implements ICapabilityRegistry {
  private readonly systemCapabilities = new Map<string, CapabilityDefinition>();
  private readonly workspaceCapabilities = new Map<string, Map<string, CapabilityDefinition>>();

  private readonly systemAdapters = new Map<string, IToolAdapter>();
  private readonly workspaceAdapters = new Map<string, Map<string, IToolAdapter>>();

  private readonly workspaceBindings = new Map<string, Map<string, WorkspaceBindingConfig>>();

  private readonly repository?: CapabilityRepository | undefined;
  private readonly hostPlatform: PlatformType;

  constructor(options?: CapabilityRegistryOptions) {
    this.repository = options?.repository;
    this.hostPlatform = options?.platform ?? (process.platform === 'win32'
      ? 'win32'
      : process.platform === 'darwin'
      ? 'darwin'
      : 'linux');
  }

  // --------------------------------------------------------------------------
  // 1. Capability Registration & Lifecycle
  // --------------------------------------------------------------------------

  async registerCapability(
    capability: CapabilityDefinition,
    workspaceId?: WorkspaceId
  ): Promise<Result<CapabilityDefinition, ProblemDetails>> {
    const valRes = validateCapabilityManifest(capability);
    if (valRes.isErr) return valRes;

    const validated = valRes.value;
    const capId = validated.id;

    // Duplicate detection
    if (workspaceId) {
      const wsMap = this.workspaceCapabilities.get(workspaceId);
      if (wsMap?.has(capId)) {
        return err(
          makeCapabilityProblem(
            ErrorCode.CAP_ALREADY_EXISTS,
            `Capability '${capId}' already registered in workspace '${workspaceId}'`
          )
        );
      }
    } else if (this.systemCapabilities.has(capId)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_ALREADY_EXISTS,
          `System capability '${capId}' is already registered`
        )
      );
    }

    // Platform compatibility check
    if (!validated.platformCompatibility.includes(this.hostPlatform)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_MALFORMED_MANIFEST,
          `Capability '${capId}' does not support host platform '${this.hostPlatform}'`
        )
      );
    }

    // In-memory indexing
    if (workspaceId) {
      let wsMap = this.workspaceCapabilities.get(workspaceId);
      if (!wsMap) {
        wsMap = new Map();
        this.workspaceCapabilities.set(workspaceId, wsMap);
      }
      wsMap.set(capId, validated);
    } else {
      this.systemCapabilities.set(capId, validated);
    }

    // Optional DB persistence
    if (this.repository) {
      try {
        await this.repository.registerCapability({
          id: validated.id,
          workspaceId: workspaceId ?? null,
          name: validated.name,
          version: validated.version,
          displayName: validated.displayName,
          description: validated.description,
          category: validated.category,
          riskLevel: validated.riskLevel,
          supportedTargets: validated.supportedTargets,
          requiredPermissions: validated.requiredPermissions,
          requiredScopeAction: validated.requiredScopeAction,
          argumentSchema: validated.argumentSchema,
          outputSchema: validated.outputSchema,
          environmentRequirements: validated.environmentRequirements,
          resourceRequirements: validated.resourceRequirements as any,
          platformCompatibility: validated.platformCompatibility,
          lifecycleState: validated.lifecycleState,
          integrityDigest: validated.integrityDigest,
          metadata: validated.metadata,
        });
      } catch (e: any) {
        // Rollback memory if DB fails
        if (workspaceId) {
          this.workspaceCapabilities.get(workspaceId)?.delete(capId);
        } else {
          this.systemCapabilities.delete(capId);
        }
        return err(
          makeCapabilityProblem(
            ErrorCode.INTERNAL_FAULT,
            `Failed to persist capability: ${e.message}`
          )
        );
      }
    }

    return ok(validated);
  }

  async findCapability(
    id: CapabilityId | string,
    workspaceId?: WorkspaceId
  ): Promise<CapabilityDefinition | null> {
    const capIdStr = String(id);

    // 1. Check workspace override
    if (workspaceId) {
      const wsMap = this.workspaceCapabilities.get(workspaceId);
      if (wsMap?.has(capIdStr)) {
        return wsMap.get(capIdStr)!;
      }
    }

    // 2. Check system capability
    if (this.systemCapabilities.has(capIdStr)) {
      return this.systemCapabilities.get(capIdStr)!;
    }

    // 3. Fallback to repository if configured
    if (this.repository) {
      const dbRecord = await this.repository.findCapabilityById(capIdStr, workspaceId);
      if (dbRecord) {
        const def: CapabilityDefinition = {
          id: dbRecord.id as CapabilityId,
          name: dbRecord.name,
          version: dbRecord.version,
          displayName: dbRecord.displayName,
          description: dbRecord.description,
          category: dbRecord.category as any,
          riskLevel: dbRecord.riskLevel as any,
          supportedTargets: dbRecord.supportedTargets as any,
          requiredPermissions: Number(dbRecord.requiredPermissions),
          requiredScopeAction: dbRecord.requiredScopeAction,
          argumentSchema: dbRecord.argumentSchema,
          outputSchema: dbRecord.outputSchema,
          environmentRequirements: dbRecord.environmentRequirements,
          resourceRequirements: dbRecord.resourceRequirements as any,
          platformCompatibility: dbRecord.platformCompatibility as any,
          lifecycleState: dbRecord.lifecycleState as any,
          integrityDigest: dbRecord.integrityDigest,
          workspaceId: dbRecord.workspaceId,
          metadata: dbRecord.metadata,
        };

        // Cache in memory
        if (dbRecord.workspaceId) {
          let wsMap = this.workspaceCapabilities.get(dbRecord.workspaceId);
          if (!wsMap) {
            wsMap = new Map();
            this.workspaceCapabilities.set(dbRecord.workspaceId, wsMap);
          }
          wsMap.set(capIdStr, def);
        } else {
          this.systemCapabilities.set(capIdStr, def);
        }

        return def;
      }
    }

    return null;
  }

  async listCapabilities(
    filter?: ListCapabilitiesFilter
  ): Promise<readonly CapabilityDefinition[]> {
    const result: CapabilityDefinition[] = [];
    const seenIds = new Set<string>();

    // If workspace provided, include workspace overrides first
    if (filter?.workspaceId) {
      const wsMap = this.workspaceCapabilities.get(filter.workspaceId);
      if (wsMap) {
        for (const cap of wsMap.values()) {
          if (this.matchesCapFilter(cap, filter)) {
            result.push(cap);
            seenIds.add(cap.id);
          }
        }
      }
    }

    // Include system capabilities if not overridden
    for (const cap of this.systemCapabilities.values()) {
      if (!seenIds.has(cap.id) && this.matchesCapFilter(cap, filter)) {
        result.push(cap);
      }
    }

    return result.sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  }

  private matchesCapFilter(cap: CapabilityDefinition, filter?: ListCapabilitiesFilter): boolean {
    if (!filter) return true;
    if (filter.category && cap.category !== filter.category) return false;
    if (filter.state && cap.lifecycleState !== filter.state) return false;
    if (filter.targetType && !cap.supportedTargets.includes(filter.targetType)) return false;
    return true;
  }

  async updateCapabilityState(
    id: CapabilityId | string,
    state: CapabilityLifecycleState,
    workspaceId?: WorkspaceId
  ): Promise<Result<void, ProblemDetails>> {
    const capIdStr = String(id);
    const existing = await this.findCapability(capIdStr, workspaceId);
    if (!existing) {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_NOT_FOUND,
          `Capability '${capIdStr}' not found`
        )
      );
    }

    // Update in-memory
    if (workspaceId && this.workspaceCapabilities.get(workspaceId)?.has(capIdStr)) {
      const current = this.workspaceCapabilities.get(workspaceId)!.get(capIdStr)!;
      this.workspaceCapabilities.get(workspaceId)!.set(capIdStr, { ...current, lifecycleState: state });
    } else if (this.systemCapabilities.has(capIdStr)) {
      const current = this.systemCapabilities.get(capIdStr)!;
      this.systemCapabilities.set(capIdStr, { ...current, lifecycleState: state });
    }

    if (this.repository) {
      await this.repository.updateCapabilityLifecycle(capIdStr, state, workspaceId);
    }

    return ok(undefined);
  }

  // --------------------------------------------------------------------------
  // 2. Adapter Registration & Lifecycle
  // --------------------------------------------------------------------------

  async registerAdapter(
    adapter: IToolAdapter,
    workspaceId?: WorkspaceId
  ): Promise<Result<void, ProblemDetails>> {
    const adapterIdStr = String(adapter.adapterId);

    // Validate platform support
    if (!adapter.platformSupport.includes(this.hostPlatform)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.ADAPTER_INCOMPATIBLE,
          `Tool adapter '${adapterIdStr}' does not support host platform '${this.hostPlatform}'`
        )
      );
    }

    // Duplicate check
    if (workspaceId) {
      let wsMap = this.workspaceAdapters.get(workspaceId);
      if (wsMap?.has(adapterIdStr)) {
        return err(
          makeCapabilityProblem(
            ErrorCode.CAP_ALREADY_EXISTS,
            `Adapter '${adapterIdStr}' already registered in workspace '${workspaceId}'`
          )
        );
      }
      if (!wsMap) {
        wsMap = new Map();
        this.workspaceAdapters.set(workspaceId, wsMap);
      }
      wsMap.set(adapterIdStr, adapter);
    } else {
      if (this.systemAdapters.has(adapterIdStr)) {
        return err(
          makeCapabilityProblem(
            ErrorCode.CAP_ALREADY_EXISTS,
            `System adapter '${adapterIdStr}' is already registered`
          )
        );
      }
      this.systemAdapters.set(adapterIdStr, adapter);
    }

    if (this.repository) {
      try {
        await this.repository.registerAdapter({
          id: adapterIdStr,
          workspaceId: workspaceId ?? null,
          name: adapter.name,
          version: adapter.version,
          lifecycleState: adapter.getLifecycleState(),
          supportedCapabilities: adapter.supportedCapabilities.map(b => ({
            capabilityId: String(b.capabilityId),
            versionConstraint: b.versionConstraint,
          })),
          platformCompatibility: adapter.platformSupport,
          binaryPath: (adapter as any).executablePath ?? adapter.name,
          manifestDigest: '0'.repeat(64),
        });
      } catch (e: any) {
        // Rollback memory if DB fails
        if (workspaceId) {
          this.workspaceAdapters.get(workspaceId)?.delete(adapterIdStr);
        } else {
          this.systemAdapters.delete(adapterIdStr);
        }
        return err(
          makeCapabilityProblem(
            e.message?.startsWith('Conflict') ? ErrorCode.CAP_ALREADY_EXISTS : ErrorCode.INTERNAL_FAULT,
            `Failed to persist adapter: ${e.message}`
          )
        );
      }
    }

    return ok(undefined);
  }

  async findAdapter(
    id: AdapterId | string,
    workspaceId?: WorkspaceId
  ): Promise<IToolAdapter | null> {
    const adapterIdStr = String(id);
    if (workspaceId) {
      const wsMap = this.workspaceAdapters.get(workspaceId);
      if (wsMap?.has(adapterIdStr)) {
        return wsMap.get(adapterIdStr)!;
      }
    }
    return this.systemAdapters.get(adapterIdStr) ?? null;
  }

  async listAdapters(
    filter?: ListAdaptersFilter
  ): Promise<readonly IToolAdapter[]> {
    const result: IToolAdapter[] = [];
    const seenIds = new Set<string>();

    if (filter?.workspaceId) {
      const wsMap = this.workspaceAdapters.get(filter.workspaceId);
      if (wsMap) {
        for (const a of wsMap.values()) {
          if (this.matchesAdapterFilter(a, filter)) {
            result.push(a);
            seenIds.add(String(a.adapterId));
          }
        }
      }
    }

    for (const a of this.systemAdapters.values()) {
      if (!seenIds.has(String(a.adapterId)) && this.matchesAdapterFilter(a, filter)) {
        result.push(a);
      }
    }

    return result.sort((a, b) => a.name.localeCompare(b.name));
  }

  private matchesAdapterFilter(adapter: IToolAdapter, filter?: ListAdaptersFilter): boolean {
    if (!filter) return true;
    if (filter.state && adapter.getLifecycleState() !== filter.state) return false;
    if (filter.capabilityId) {
      const capIdStr = String(filter.capabilityId);
      const supports = adapter.supportedCapabilities.some(b => String(b.capabilityId) === capIdStr);
      if (!supports) return false;
    }
    return true;
  }

  async updateAdapterState(
    id: AdapterId | string,
    state: AdapterLifecycleState,
    workspaceId?: WorkspaceId
  ): Promise<Result<void, ProblemDetails>> {
    const adapter = await this.findAdapter(id, workspaceId);
    if (!adapter) {
      return err(
        makeCapabilityProblem(
          ErrorCode.ADAPTER_NOT_FOUND,
          `Tool adapter '${id}' not found`
        )
      );
    }

    adapter.setLifecycleState(state);

    if (this.repository) {
      await this.repository.updateAdapterLifecycle(String(id), state, workspaceId);
    }

    return ok(undefined);
  }

  // --------------------------------------------------------------------------
  // 3. Workspace Capability Bindings (Tenant Configuration & Adapter Overrides)
  // --------------------------------------------------------------------------

  async setWorkspaceBinding(
    workspaceId: WorkspaceId,
    capabilityId: CapabilityId | string,
    preferredAdapterId: AdapterId | string,
    isEnabled = true,
    overrides?: Record<string, unknown> | undefined
  ): Promise<Result<void, ProblemDetails>> {
    const capIdStr = String(capabilityId);
    const prefAdapterStr = String(preferredAdapterId);
    let wsMap = this.workspaceBindings.get(workspaceId);
    if (!wsMap) {
      wsMap = new Map();
      this.workspaceBindings.set(workspaceId, wsMap);
    }

    const config: WorkspaceBindingConfig = {
      preferredAdapterId: prefAdapterStr,
      isEnabled,
      overrides,
    };
    wsMap.set(capIdStr, config);

    if (this.repository) {
      await this.repository.setWorkspaceBinding(
        workspaceId,
        capIdStr,
        prefAdapterStr,
        isEnabled,
        overrides ?? {}
      );
    }

    return ok(undefined);
  }

  async getWorkspaceBinding(
    workspaceId: WorkspaceId,
    capabilityId: CapabilityId | string
  ): Promise<WorkspaceBindingConfig | null> {
    const capIdStr = String(capabilityId);
    const inMem = this.workspaceBindings.get(workspaceId)?.get(capIdStr);
    if (inMem) return inMem;

    if (this.repository) {
      const dbRec = await this.repository.getWorkspaceBinding(workspaceId, capIdStr);
      if (dbRec) {
        const config: WorkspaceBindingConfig = {
          preferredAdapterId: dbRec.preferredAdapterId ?? undefined,
          isEnabled: dbRec.isEnabled,
          overrides: dbRec.overrides,
        };
        let wsMap = this.workspaceBindings.get(workspaceId);
        if (!wsMap) {
          wsMap = new Map();
          this.workspaceBindings.set(workspaceId, wsMap);
        }
        wsMap.set(capIdStr, config);
        return config;
      }
    }

    return null;
  }

  // --------------------------------------------------------------------------
  // 4. Dynamic Multi-Provider Capability Resolution (Phase 0.9 §9)
  // --------------------------------------------------------------------------

  async resolveProvider(
    capabilityId: CapabilityId | string,
    options?: ResolveProviderOptions
  ): Promise<Result<IToolAdapter, ProblemDetails>> {
    const capIdStr = String(capabilityId);

    // 1. Resolve capability contract
    const capability = await this.findCapability(capIdStr, options?.workspaceId);
    if (!capability) {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_NOT_FOUND,
          `Capability '${capIdStr}' is not registered`
        )
      );
    }

    // 2. Check capability lifecycle state
    if (capability.lifecycleState === 'DISABLED') {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_DISABLED,
          `Capability '${capIdStr}' is disabled in this environment`
        )
      );
    }
    if (capability.lifecycleState === 'REVOKED') {
      return err(
        makeCapabilityProblem(
          ErrorCode.CAP_REVOKED,
          `Capability '${capIdStr}' has been revoked for security reasons`
        )
      );
    }

    // 2b. Check workspace binding overrides if workspaceId is provided
    let preferredAdapterId = options?.preferredAdapterId;
    if (options?.workspaceId) {
      const binding = await this.getWorkspaceBinding(options.workspaceId, capIdStr);
      if (binding) {
        if (!binding.isEnabled) {
          return err(
            makeCapabilityProblem(
              ErrorCode.CAP_DISABLED,
              `Capability '${capIdStr}' is disabled in workspace '${options.workspaceId}'`
            )
          );
        }
        if (!preferredAdapterId && binding.preferredAdapterId) {
          preferredAdapterId = binding.preferredAdapterId as any;
        }
      }
    }

    // 3. Collect compatible adapters
    const allAdapters = await this.listAdapters({
      workspaceId: options?.workspaceId,
      capabilityId: capIdStr,
    });

    const candidateAdapters: Array<{ adapter: IToolAdapter; priority: number }> = [];

    for (const adapter of allAdapters) {
      const state = adapter.getLifecycleState();
      if (state !== 'ENABLED' && state !== 'AVAILABLE') {
        continue;
      }

      // Check host platform support
      if (!adapter.platformSupport.includes(this.hostPlatform)) {
        continue;
      }

      // Find binding for this capability
      const binding = adapter.supportedCapabilities.find(b => String(b.capabilityId) === capIdStr);
      if (!binding) continue;

      // Validate SemVer compatibility
      if (!satisfiesVersion(capability.version, binding.versionConstraint)) {
        continue;
      }

      let priority = binding.priority ?? 0;

      // Preference bonus if explicitly requested or configured in workspace binding
      if (preferredAdapterId && String(adapter.adapterId) === String(preferredAdapterId)) {
        priority += 10_000;
      }

      candidateAdapters.push({ adapter, priority });
    }

    if (candidateAdapters.length === 0) {
      return err(
        makeCapabilityProblem(
          ErrorCode.ADAPTER_NOT_FOUND,
          `No compatible, enabled tool adapter found for capability '${capIdStr}' on platform '${this.hostPlatform}'`
        )
      );
    }

    // Sort candidates:
    // 1. Priority descending
    // 2. Adapter SemVer descending
    // 3. Name ascending
    candidateAdapters.sort((a, b) => {
      if (a.priority !== b.priority) {
        return b.priority - a.priority;
      }

      const verA = parseSemVer(a.adapter.version);
      const verB = parseSemVer(b.adapter.version);
      if (verA.isOk && verB.isOk) {
        const cmp = compareSemVer(verB.value, verA.value);
        if (cmp !== 0) return cmp;
      }

      return a.adapter.name.localeCompare(b.adapter.name);
    });

    const winner = candidateAdapters[0]!.adapter;
    return ok(winner);
  }
}
