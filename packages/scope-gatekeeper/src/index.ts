/**
 * @shn/scope-gatekeeper — Public Facade
 *
 * Tenancy & Zero-Trust Scope Gatekeeper bounded context adhering to MOD-INV-01.
 * Authoritative Spec: Phase 0.1 Section 18, Phase 0.3 Context 3, Phase 0.7 Section 4.1.1,
 *                    Phase 0.10 Section 4.2, Phase 0.14 Section 20.
 */

// Contracts & Types
export {
  type IScopeGatekeeper,
  type ScopeTargetType,
  type PortRange,
  type ScopeInclusions,
  type ScopeExclusions,
  type ScopeStatus,
  type ScopeDefinition,
  type ScopeToken,
  type ScopeTokenClaims,
  type NormalizedTarget,
  type TargetVerdict,
  type EvaluateTargetParams,
  type MintScopeTokenParams,
} from './contracts.js';

// Central Gatekeeper
export {
  ScopeGatekeeper,
  type ScopeGatekeeperOptions,
} from './gatekeeper/scope-gatekeeper.js';

// Tenancy
export {
  TenancyValidator,
  type TenancyValidationContext,
} from './tenancy/tenancy-validator.js';

// Cryptographic Token Signer
export {
  ScopeTokenSigner,
  type ScopeTokenHeader,
  DEFAULT_SCOPE_TOKEN_TTL_SECONDS,
} from './tokens/scope-token-signer.js';

// CIDR & IP Evaluators
export {
  type ParsedCidr,
  type IPv4Cidr,
  type IPv6Cidr,
  getIPv4Mask,
  getIPv6Mask,
  parseIPv4Address,
  formatIPv4Address,
  parseIPv6Address,
  formatIPv6Address,
  parseCidrBlock,
  isProhibitedIPv4,
  isProhibitedIPv6,
  isBlacklistedIpOrCidr,
  isTargetContainedInCidr,
} from './evaluators/cidr-evaluator.js';

// Hostname Evaluator
export {
  canonicalizeHostname,
  isHostnameContainedInScope,
  isBlacklistedHostname,
} from './evaluators/hostname-evaluator.js';

// URL Evaluator
export {
  type ParsedScopeUrl,
  parseAndNormalizeUrl,
  isUrlContainedInScope,
} from './evaluators/url-evaluator.js';

// Scope Composition & Sealing
export {
  calculateCanonicalScopeSha256,
  intersectPortRanges,
  intersectScopes,
} from './evaluators/scope-composition.js';

// Errors
export { makeScopeProblem } from './errors.js';
