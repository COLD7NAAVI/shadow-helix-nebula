/**
 * Shadow : Helix Nebula (SHN) — Web Console Contracts & Domain Models
 */

export type ThemeMode = 'night' | 'day' | 'ambient';
export type AccentColor = 'cyan' | 'violet' | 'magenta' | 'emerald' | 'amber';
export type FontPreference = 'sans' | 'mono';
export type DensityPreference = 'comfortable' | 'compact';
export type BackgroundStyle = 'nebula' | 'starfield' | 'void';

export interface PersonalizationSettings {
  theme: ThemeMode;
  accent: AccentColor;
  font: FontPreference;
  density: DensityPreference;
  reducedMotion: boolean;
  backgroundOpacity: number;
  backgroundStyle: BackgroundStyle;
  refreshIntervalSeconds: number;
}

export interface User {
  id: string;
  email: string;
  displayName: string;
  organizationId: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
}

export interface Workspace {
  id: string;
  organization_id?: string;
  organizationId?: string;
  name: string;
  slug: string;
  created_at?: string;
  createdAt?: string;
}

export interface LoginResponse {
  token: string;
  user: User;
  workspaceId: string;
  roles: string[];
  permissionMask: number;
  expiresAt: number;
}

export interface RegisterResponse {
  organization: Organization;
  user: { id: string; email: string; displayName: string };
  workspace: Workspace;
}

export interface Asset {
  id: string;
  workspaceId?: string;
  workspace_id?: string;
  organizationId?: string;
  type: 'IPV4' | 'IPV6' | 'CIDR' | 'FQDN' | 'URL' | 'HOST' | 'DOMAIN';
  rawTarget?: string;
  raw_target?: string;
  canonicalValue?: string;
  canonical_target?: string;
  name: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'ACTIVE' | 'INACTIVE' | 'DISCOVERED' | 'ARCHIVED';
  tags?: string[];
  metadata?: Record<string, unknown>;
  createdAt?: string;
  created_at?: string;
  updatedAt?: string;
}

export interface RegisterAssetInput {
  rawTarget: string;
  type?: string;
  name?: string;
  criticality?: string;
  status?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  workspaceId?: string;
  workspace_id?: string;
  organizationId?: string;
  assetId?: string;
  asset_id?: string;
  executionId?: string | null;
  execution_id?: string | null;
  title: string;
  description: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  cveId?: string | null;
  cve_id?: string | null;
  cweId?: string | null;
  cwe_id?: string | null;
  cvssScore?: number | null;
  cvss_score?: number | null;
  cvssVector?: string | null;
  cvss_vector?: string | null;
  status: 'DRAFT' | 'OPEN' | 'TRIAGED' | 'CONFIRMED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'ACCEPTED_RISK';
  rawEvidenceSha256?: string;
  raw_evidence_sha256?: string;
  remediationGuidance?: string | null;
  remediation_guidance?: string | null;
  metadata?: Record<string, unknown>;
  createdAt?: string;
  created_at?: string;
  updatedAt?: string;
}

export interface FindingTransition {
  id: string;
  findingId?: string;
  finding_id?: string;
  fromStatus?: string;
  toStatus?: string;
  changedBy?: string;
  reason?: string | null;
  createdAt?: string;
  created_at?: string;
}

export interface Capability {
  id: string;
  uri: string;
  name: string;
  version: string;
  category: string;
  description: string;
  state: 'ACTIVE' | 'DEPRECATED' | 'DISABLED';
  parametersSchema?: Record<string, unknown>;
  adapters?: Array<{
    id: string;
    name: string;
    isAvailable: boolean;
    sandboxLevel: string;
  }>;
}

export interface Execution {
  id: string;
  workspaceId?: string;
  workspace_id?: string;
  organizationId?: string;
  scopeId?: string | null;
  scope_id?: string | null;
  action: string;
  target: string;
  capabilityUri?: string;
  capability_uri?: string;
  state: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  requestedBy?: string;
  requested_by?: string;
  stdoutSummary?: string | null;
  stdout_summary?: string | null;
  stderrSummary?: string | null;
  stderr_summary?: string | null;
  rawOutputSha256?: string | null;
  raw_output_sha256?: string | null;
  createdAt?: string;
  created_at?: string;
  startedAt?: string | null;
  started_at?: string | null;
  completedAt?: string | null;
  completed_at?: string | null;
  command?: { executable: string; args: string[] };
}

export interface Scope {
  id: string;
  workspaceId?: string;
  workspace_id?: string;
  name: string;
  description?: string | null;
  status: 'ACTIVE' | 'SUSPENDED' | 'ARCHIVED' | 'EXPIRED';
  inclusions: Array<{ type: string; value: string }>;
  exclusions: Array<{ type: string; value: string; reason?: string }>;
  allowed_actions?: string[];
  disallowed_actions?: string[];
  port_ranges?: Array<{ start: number; end: number }>;
  valid_from?: string;
  valid_until?: string;
  scope_sha256?: string;
}

export interface AuditEvent {
  event_id: string;
  event_type: string;
  schema_version?: string;
  occurred_at: string;
  producer: Record<string, unknown>;
  workspace_id: string;
  correlation_id: string;
  causation_id?: string;
  trace_id?: string;
  authorization_context?: Record<string, unknown>;
  scope_reference?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  integrity?: Record<string, unknown>;
  recorded_at?: string;
}

export interface HealthStatus {
  status: 'UP' | 'DOWN' | 'DEGRADED';
  component: string;
  timestamp: string;
}
