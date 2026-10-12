/**
 * @shn/capability-registry — Public Facade
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Phase 0.4 (INV-01, INV-03, INV-04, INV-06),
 *                    Phase 0.7 Section 4.2.3 (mod_capability_registry),
 *                    Phase 0.8 (Plugin & Adapter Contracts),
 *                    Phase 0.9 (Tool Integration Architecture),
 *                    Phase 0.14
 *
 * Enforces MOD-INV-01: Explicit exported contracts only.
 */

// Domain Contracts & Types
export {
  type CapabilityLifecycleState,
  type AdapterLifecycleState,
  type CapabilityCategory,
  type RiskClassification,
  type TargetType,
  type PlatformType,
  type CapabilityDefinition,
  type AdapterCapabilityBinding,
  type ToolAdapterDefinition,
  type EvidenceArtifact,
  type AdapterExecutionOutput,
  type CommandVector,
  type IToolAdapter,
  type ResolveProviderOptions,
  type ListCapabilitiesFilter,
  type ListAdaptersFilter,
  type WorkspaceBindingConfig,
  type ICapabilityRegistry,
  type CapabilityExecutionRequest,
  type CapabilityExecutionResult,
} from './contracts.js';

// Problem Details & Error Factory
export { makeCapabilityProblem } from './errors.js';

// Strict SemVer Engine
export {
  type SemVer,
  type VersionCompatibility,
  parseSemVer,
  formatSemVer,
  compareSemVer,
  satisfiesVersion,
  isValidVersionConstraint,
  evaluateCompatibility,
} from './versioning/semver.js';

// Manifest Validators
export {
  validateCapabilityManifest,
  validateToolAdapterManifest,
} from './manifests/validator.js';

// Capability Registry
export {
  type CapabilityRegistryOptions,
  CapabilityRegistry,
} from './registry/capability-registry.js';

// Base Tool Adapter & Reference Adapters
export { BaseToolAdapter } from './adapters/base-tool-adapter.js';
export { NetworkPortScanAdapter } from './adapters/reference/network-port-scan-adapter.js';
export { HttpDiscoveryAdapter } from './adapters/reference/http-discovery-adapter.js';

// Capability Execution Dispatcher & Gateway
export {
  type CapabilityDispatcherOptions,
  CapabilityDispatcher,
} from './execution/capability-dispatcher.js';
