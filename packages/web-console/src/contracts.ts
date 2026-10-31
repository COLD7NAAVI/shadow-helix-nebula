/**
 * Shadow : Helix Nebula (SHN) — Web Console Contracts & Domain Models
 */

export type ThemeMode = 'night' | 'day' | 'ambient';
export type AccentColor = 'cyan' | 'violet' | 'magenta' | 'emerald' | 'amber';
export type FontPreference = 'sans' | 'mono';
export type DensityPreference = 'comfortable' | 'compact';
export type BackgroundStyle = 'nebula' | 'starfield' | 'void';
export type BundledWallpaper =
  | 'nebula-core'
  | 'cyber-matrix'
  | 'quantum-aurora'
  | 'solar-corona'
  | 'tactical-carbon'
  | 'obsidian-void'
  | 'custom';

export interface AmbientSettings {
  wallpaperPreset: BundledWallpaper;
  customWallpaperDataUrl?: string | undefined;
  wallpaperOpacity: number;
  wallpaperBlur: number;
  overlayIntensity: number;
}

export interface PersonalizationSettings {
  theme: ThemeMode;
  accent: AccentColor;
  font: FontPreference;
  density: DensityPreference;
  reducedMotion: boolean;
  backgroundOpacity: number;
  backgroundStyle: BackgroundStyle;
  refreshIntervalSeconds: number;
  wallpaperPreset: BundledWallpaper;
  customWallpaperDataUrl?: string | undefined;
  wallpaperOpacity: number;
  wallpaperBlur: number;
  overlayIntensity: number;
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

export interface AiProvider {
  id: string;
  organizationId: string;
  workspaceId?: string | null;
  providerType: 'OPENAI_COMPATIBLE' | 'OLLAMA' | 'ANTHROPIC' | 'LOCAL_HEURISTIC';
  displayName: string;
  baseUrl?: string | null;
  modelName: string;
  secretId?: string | null;
  isDefault: boolean;
  isActive: boolean;
  maxTokens: number;
  temperature: number;
  timeoutMs: number;
  healthStatus: 'UNKNOWN' | 'HEALTHY' | 'DEGRADED' | 'UNREACHABLE';
  lastHealthCheckAt?: string | null;
  healthDetails?: Record<string, unknown>;
  createdAt?: string;
}

export interface AiRecommendation {
  id: string;
  workspaceId: string;
  organizationId: string;
  recommendationId: string;
  objective: string;
  rationale: string;
  proposedCapability: string;
  parameters: Record<string, unknown>;
  target: string;
  requiredScopeAction: string;
  riskLevel: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  requiresApproval: boolean;
  confidence: number;
  supportingEvidenceIds: string[];
  assumptions: string[];
  expectedImpact?: string | null;
  rollbackConditions?: string | null;
  status: 'PENDING' | 'APPROVED' | 'DISMISSED' | 'EXECUTING' | 'COMPLETED' | 'FAILED';
  executionId?: string | null;
  approvedBy?: string | null;
  approvedAt?: string | null;
  createdAt?: string;
}

export interface Report {
  id: string;
  workspaceId: string;
  organizationId: string;
  title: string;
  reportType: 'EXECUTIVE_SUMMARY' | 'TECHNICAL_ASSESSMENT' | 'COMPLIANCE_AUDIT' | 'EVIDENCE_CATALOG';
  scopeId?: string | null;
  status: 'DRAFT' | 'GENERATING' | 'COMPLETED' | 'FAILED';
  version: number;
  summaryContent: {
    targetCount?: number;
    findingsCount?: number;
    criticalFindings?: number;
    highFindings?: number;
    mediumFindings?: number;
    lowFindings?: number;
    executionsCount?: number;
    overview?: string;
  };
  findingsSnapshot: Finding[];
  assetsSnapshot: Asset[];
  executionsSnapshot: Execution[];
  htmlContent?: string | null;
  contentSha256: string;
  generatedBy: string;
  createdAt: string;
}

export interface GraphNode {
  id: string;
  type: 'WORKSPACE' | 'SCOPE' | 'ASSET' | 'SERVICE' | 'FINDING' | 'EXECUTION' | 'HYPOTHESIS';
  label: string;
  criticality?: string;
  severity?: string;
  status?: string;
  confidence?: number;
  details?: Record<string, unknown>;
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  isHypothesis?: boolean;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  savedLayout?: {
    positions: Record<string, { x: number; y: number }>;
    annotations: Array<{ id: string; text: string; x: number; y: number }>;
  };
}

export interface GeoMarker {
  id: string;
  target: string;
  label: string;
  lat: number;
  lng: number;
  type: string;
  criticality: string;
  workspaceId: string;
}

export interface ThreatPoint {
  id: string;
  cveId: string;
  title: string;
  lat: number;
  lng: number;
  severity: string;
  provider: string;
  observedAt: string;
}

export interface GeoIntelData {
  assessmentMarkers: GeoMarker[];
  externalThreatPoints: ThreatPoint[];
  metadata: {
    legend: {
      assessment: string;
      external: string;
    };
    generatedAt: string;
  };
}

export interface UserPreferences {
  theme: 'cyber-operations' | 'light' | 'ambient';
  accentColor: 'cyan' | 'emerald' | 'violet' | 'amber' | 'rose';
  density: 'compact' | 'comfortable';
  reducedMotion: boolean;
  dashboardLayout?: {
    panels?: Array<{ id: string; visible: boolean; order: number; colSpan: number }>;
    refreshIntervalSec?: number;
    ambientSettings?: AmbientSettings;
    [key: string]: unknown;
  };
}
