/**
 * Shadow : Helix Nebula (SHN) — Sovereign HTTP API Client
 *
 * Implements Level 2/3 REST RFC 7807 Problem Details client with
 * automatic SecurityContextToken Bearer injection and correlation tracking.
 */

import type {
  LoginResponse,
  RegisterResponse,
  Workspace,
  Asset,
  RegisterAssetInput,
  Finding,
  FindingTransition,
  Capability,
  Execution,
  Scope,
  AuditEvent,
  HealthStatus,
  AiProvider,
  AiRecommendation,
  Report,
  GraphData,
  GeoIntelData,
  UserPreferences,
} from '../contracts.js';

export interface ApiClientConfig {
  baseUrl?: string | undefined;
  getToken?: (() => string | null) | undefined;
  onUnauthorized?: (() => void) | undefined;
}

export interface ProblemDetailsError {
  type?: string | undefined;
  title: string;
  status: number;
  detail: string;
  instance?: string | undefined;
  code?: string | undefined;
  correlationId?: string | undefined;
  invalidParams?: Array<{ name: string; reason: string }> | undefined;
}

export class ApiError extends Error {
  constructor(public readonly problem: ProblemDetailsError) {
    super(problem.detail || problem.title || `API error (${problem.status})`);
    this.name = 'ApiError';
    Object.setPrototypeOf(this, ApiError.prototype);
  }
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly getToken: () => string | null;
  private readonly onUnauthorized?: (() => void) | undefined;

  constructor(config?: ApiClientConfig) {
    this.baseUrl = config?.baseUrl ?? '';
    this.getToken = config?.getToken ?? (() => (typeof localStorage !== 'undefined' ? localStorage.getItem('shn_auth_token') : null));
    this.onUnauthorized = config?.onUnauthorized;
  }

  private generateCorrelationId(): string {
    return 'req-' + Math.random().toString(36).substring(2, 10) + '-' + Date.now();
  }

  private activeRefreshPromise: Promise<string | null> | null = null;

  async refreshAuthToken(): Promise<string | null> {
    if (this.activeRefreshPromise) {
      return this.activeRefreshPromise;
    }

    this.activeRefreshPromise = (async () => {
      try {
        const token = this.getToken();
        if (!token) return null;

        const res = await fetch(`${this.baseUrl}/api/v1/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            'X-Correlation-ID': this.generateCorrelationId(),
          },
        });

        if (!res.ok) {
          if (res.status === 401 && this.onUnauthorized) {
            this.onUnauthorized();
          }
          return null;
        }

        const data: LoginResponse = await res.json();
        if (data && data.token && typeof localStorage !== 'undefined') {
          localStorage.setItem('shn_auth_token', data.token);
          localStorage.setItem('shn_active_workspace_id', data.workspaceId);
          localStorage.setItem('shn_auth_roles', JSON.stringify(data.roles));
          return data.token;
        }
        return null;
      } catch {
        return null;
      } finally {
        this.activeRefreshPromise = null;
      }
    })();

    return this.activeRefreshPromise;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = new Headers(options.headers);

    if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
      headers.set('Content-Type', 'application/json');
    }

    const token = this.getToken();
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    if (!headers.has('X-Correlation-ID')) {
      headers.set('X-Correlation-ID', this.generateCorrelationId());
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (response.status === 401) {
        if (!endpoint.includes('/api/v1/auth/')) {
          const refreshedToken = await this.refreshAuthToken();
          if (refreshedToken) {
            headers.set('Authorization', `Bearer ${refreshedToken}`);
            const retryRes = await fetch(url, { ...options, headers });
            if (retryRes.ok) {
              if (retryRes.status === 204) return null as unknown as T;
              const ct = retryRes.headers.get('content-type') || '';
              if (ct.includes('application/json')) return (await retryRes.json()) as T;
              return (await retryRes.text()) as unknown as T;
            }
          }
        }
        if (this.onUnauthorized) this.onUnauthorized();
      }

      if (!response.ok) {
        let problem: ProblemDetailsError;
        try {
          problem = await response.json();
        } catch {
          problem = {
            title: response.statusText || 'HTTP Error',
            status: response.status,
            detail: `Server responded with status code ${response.status}`,
          };
        }
        throw new ApiError(problem);
      }

      if (response.status === 204) {
        return null as unknown as T;
      }

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        return (await response.json()) as T;
      }
      return (await response.text()) as unknown as T;
    } catch (err) {
      if (err instanceof ApiError || (err instanceof Error && err.name === 'ApiError')) {
        throw err;
      }
      throw new ApiError({
        title: 'Network or Connection Failure',
        status: 0,
        detail: err instanceof Error ? err.message : 'Failed to connect to SHN Gateway.',
      });
    }
  }

  // Health & Metrics
  async getLiveness(): Promise<HealthStatus> {
    return this.request<HealthStatus>('/health/live');
  }

  async getReadiness(): Promise<HealthStatus> {
    return this.request<HealthStatus>('/health/ready');
  }

  async getMetrics(): Promise<string> {
    return this.request<string>('/metrics');
  }

  // Auth & Identity
  async login(credentials: { email: string; password: string; workspaceId?: string | undefined }): Promise<LoginResponse> {
    return this.request<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  }

  async register(input: {
    organizationName: string;
    adminEmail: string;
    adminPassword: string;
    adminName: string;
  }): Promise<RegisterResponse> {
    return this.request<RegisterResponse>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async getMe(): Promise<{ actor: any; workspaceId: string; securityContext: any }> {
    return this.request('/api/v1/auth/me');
  }

  async switchWorkspace(workspaceId: string): Promise<LoginResponse> {
    return this.request<LoginResponse>('/api/v1/auth/switch-workspace', {
      method: 'POST',
      body: JSON.stringify({ workspaceId }),
    });
  }

  async refreshSession(): Promise<LoginResponse> {
    return this.request<LoginResponse>('/api/v1/auth/refresh', {
      method: 'POST',
    });
  }

  // Workspaces
  async listWorkspaces(): Promise<Workspace[]> {
    return this.request<Workspace[]>('/api/v1/workspaces');
  }

  async createWorkspace(input: { name: string; slug?: string }): Promise<Workspace> {
    return this.request<Workspace>('/api/v1/workspaces', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async getWorkspace(workspaceId: string): Promise<Workspace> {
    return this.request<Workspace>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}`);
  }

  // Asset Inventory
  async listAssets(workspaceId: string, filter?: { type?: string; status?: string }): Promise<Asset[]> {
    const params = new URLSearchParams();
    if (filter?.type) params.set('type', filter.type);
    if (filter?.status) params.set('status', filter.status);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.request<Asset[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/assets${qs}`);
  }

  async getAsset(workspaceId: string, assetId: string): Promise<Asset> {
    return this.request<Asset>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/assets/${encodeURIComponent(assetId)}`
    );
  }

  async registerAsset(workspaceId: string, input: RegisterAssetInput): Promise<Asset> {
    return this.request<Asset>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/assets`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async updateAsset(workspaceId: string, assetId: string, updates: Partial<Asset>): Promise<Asset> {
    return this.request<Asset>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/assets/${encodeURIComponent(assetId)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(updates),
      }
    );
  }

  // Findings
  async listFindings(
    workspaceId: string,
    filter?: { severity?: string; status?: string; assetId?: string }
  ): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filter?.severity) params.set('severity', filter.severity);
    if (filter?.status) params.set('status', filter.status);
    if (filter?.assetId) params.set('assetId', filter.assetId);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.request<Finding[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/findings${qs}`);
  }

  async getFinding(workspaceId: string, findingId: string): Promise<Finding> {
    return this.request<Finding>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/findings/${encodeURIComponent(findingId)}`
    );
  }

  async recordFinding(workspaceId: string, input: Record<string, unknown>): Promise<Finding> {
    return this.request<Finding>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/findings`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async transitionFinding(
    workspaceId: string,
    findingId: string,
    toStatus: string,
    reason?: string
  ): Promise<FindingTransition> {
    return this.request<FindingTransition>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/findings/${encodeURIComponent(findingId)}/transitions`,
      {
        method: 'POST',
        body: JSON.stringify({ toStatus, reason }),
      }
    );
  }

  async getFindingHistory(workspaceId: string, findingId: string): Promise<FindingTransition[]> {
    return this.request<FindingTransition[]>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/findings/${encodeURIComponent(findingId)}/history`
    );
  }

  // Capabilities
  async listCapabilities(): Promise<Capability[]> {
    const caps = await this.request<any[]>('/api/v1/capabilities');
    return (caps || []).map((c) => ({
      ...c,
      id: c.id,
      uri: c.uri || c.id,
      name: c.name || c.id,
      displayName: c.displayName || c.name || c.id,
      version: c.version || '1.0.0',
      category: c.category || 'UTILITY',
      description: c.description || '',
      state: c.state || c.lifecycleState || 'ACTIVE',
    }));
  }

  async getCapability(capabilityId: string): Promise<Capability> {
    const c = await this.request<any>(`/api/v1/capabilities/${encodeURIComponent(capabilityId)}`);
    return {
      ...c,
      id: c.id,
      uri: c.uri || c.id,
      name: c.name || c.id,
      displayName: c.displayName || c.name || c.id,
      version: c.version || '1.0.0',
      category: c.category || 'UTILITY',
      description: c.description || '',
      state: c.state || c.lifecycleState || 'ACTIVE',
    };
  }

  async listWorkspaceCapabilities(workspaceId: string): Promise<Capability[]> {
    const caps = await this.request<any[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/capabilities`);
    return (caps || []).map((c) => ({
      ...c,
      id: c.id,
      uri: c.uri || c.id,
      name: c.name || c.id,
      displayName: c.displayName || c.name || c.id,
      version: c.version || '1.0.0',
      category: c.category || 'UTILITY',
      description: c.description || '',
      state: c.state || c.lifecycleState || 'ACTIVE',
    }));
  }

  // Executions
  private normalizeExecution(e: any): Execution {
    return {
      ...e,
      id: e.id || e.executionId || '',
      executionId: e.executionId || e.id || '',
      workspaceId: e.workspaceId || e.workspace_id,
      organizationId: e.organizationId || e.organization_id,
      scopeId: e.scopeId || e.scope_id,
      action: e.action || e.capabilityUri || e.capability_uri || 'Capability',
      target: e.target || '',
      port: e.port !== undefined ? Number(e.port) : undefined,
      capabilityUri: e.capabilityUri || e.capability_uri || e.capabilityId,
      state: e.state || 'QUEUED',
      requestedBy: e.requestedBy || e.requested_by,
      stdoutSummary: e.stdoutSummary ?? e.stdout_summary ?? e.rawOutput ?? null,
      stderrSummary: e.stderrSummary ?? e.stderr_summary ?? e.rawStderr ?? null,
      rawOutputSha256: e.rawOutputSha256 ?? e.raw_output_sha256 ?? null,
      createdAt: e.createdAt || e.created_at || new Date().toISOString(),
      startedAt: e.startedAt || e.started_at || null,
      completedAt: e.completedAt || e.completed_at || null,
      durationMs: e.durationMs,
      output: e.output,
      command: e.command,
    };
  }

  async listExecutions(workspaceId: string): Promise<Execution[]> {
    const list = await this.request<any[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/executions`);
    return (list || []).map((e) => this.normalizeExecution(e));
  }

  async getExecution(workspaceId: string, executionId: string): Promise<Execution> {
    const raw = await this.request<any>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/executions/${encodeURIComponent(executionId)}`
    );
    return this.normalizeExecution(raw);
  }

  async executeCapability(
    workspaceId: string,
    input: {
      capabilityId: string;
      target: string;
      port?: number | undefined;
      parameters?: Record<string, unknown> | undefined;
      scopeId?: string | undefined;
    }
  ): Promise<Execution> {
    if (!input.capabilityId || input.capabilityId === 'undefined' || input.capabilityId.trim() === '') {
      throw new Error('Valid capability identifier is required for execution dispatch.');
    }
    if (!input.target || input.target === 'undefined' || input.target.trim() === '') {
      throw new Error('Valid target is required for execution dispatch.');
    }

    const raw = await this.request<any>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/executions`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
    return this.normalizeExecution(raw);
  }

  async dispatchExecution(
    workspaceId: string,
    input: {
      capabilityUri: string;
      target: string;
      port?: number | undefined;
      parameters?: Record<string, unknown> | undefined;
      scopeId?: string | undefined;
    }
  ): Promise<Execution> {
    if (!input.capabilityUri || input.capabilityUri === 'undefined' || input.capabilityUri.trim() === '') {
      throw new Error('Valid capability identifier is required for execution dispatch.');
    }
    if (!input.target || input.target === 'undefined' || input.target.trim() === '') {
      throw new Error('Valid target is required for execution dispatch.');
    }

    return this.executeCapability(workspaceId, {
      capabilityId: input.capabilityUri,
      target: input.target,
      port: input.port,
      parameters: input.parameters,
      scopeId: input.scopeId,
    });
  }

  // Scopes
  async listScopes(workspaceId: string): Promise<Scope[]> {
    return this.request<Scope[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/scopes`);
  }

  async createScope(workspaceId: string, input: Record<string, unknown>): Promise<Scope> {
    return this.request<Scope>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/scopes`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async getScope(workspaceId: string, scopeId: string): Promise<Scope> {
    return this.request<Scope>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/scopes/${encodeURIComponent(scopeId)}`
    );
  }

  // Audit Events
  async listAuditEvents(workspaceId: string, limit = 50): Promise<AuditEvent[]> {
    return this.request<AuditEvent[]>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/audit?limit=${encodeURIComponent(limit)}`
    );
  }

  // OpenAPI Specification
  async getOpenApiSpec(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/openapi.json');
  }

  // Real-Time SSE Telemetry & Domain Event Stream
  subscribeToWorkspaceEvents(
    workspaceId: string,
    onEvent: (evt: { type: string; payload: any; timestamp: string }) => void,
    onError?: (err: unknown) => void
  ): () => void {
    if (typeof EventSource === 'undefined') {
      return () => {};
    }

    const token = this.getToken();
    const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : '';
    const streamUrl = `${this.baseUrl}/api/v1/workspaces/${encodeURIComponent(workspaceId)}/events/stream${tokenQuery}`;

    const es = new EventSource(streamUrl);

    es.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        onEvent(parsed);
      } catch {
        // Raw comment
      }
    };

    const eventTypes = [
      'connected',
      'execution.dispatched',
      'execution.completed',
      'execution.failed',
      'finding.created',
      'finding.transitioned',
      'asset.registered',
      'scope.created',
      'audit.recorded',
    ];

    for (const evtType of eventTypes) {
      es.addEventListener(evtType, (event: any) => {
        try {
          const parsed = JSON.parse(event.data);
          onEvent({
            type: evtType,
            payload: parsed.payload ?? parsed,
            timestamp: parsed.timestamp ?? new Date().toISOString(),
          });
        } catch {
          // Ignored
        }
      });
    }

    es.onerror = (err) => {
      if (onError) onError(err);
    };

    return () => {
      es.close();
    };
  }

  // AI Providers & Connection Probing
  async listAiProviders(): Promise<AiProvider[]> {
    return this.request<AiProvider[]>('/api/v1/ai/providers');
  }

  async createAiProvider(input: Record<string, unknown>): Promise<AiProvider> {
    return this.request<AiProvider>('/api/v1/ai/providers', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async testAiConnection(input: Record<string, unknown>): Promise<{ success: boolean; latencyMs?: number; message?: string; modelsAvailable?: string[] }> {
    return this.request<{ success: boolean; latencyMs?: number; message?: string; modelsAvailable?: string[] }>('/api/v1/ai/test-connection', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  // Evidence-Driven AI Security Assistant & Recommendations
  async listAiRecommendations(workspaceId: string, status?: string): Promise<AiRecommendation[]> {
    const qs = status ? `?status=${encodeURIComponent(status)}` : '';
    return this.request<AiRecommendation[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/ai/recommendations${qs}`);
  }

  async generateAiRecommendations(workspaceId: string): Promise<AiRecommendation[]> {
    return this.request<AiRecommendation[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/ai/recommendations/generate`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async approveAiRecommendation(workspaceId: string, id: string): Promise<{ success: boolean; recommendation: AiRecommendation; executionId?: string }> {
    return this.request<{ success: boolean; recommendation: AiRecommendation; executionId?: string }>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/ai/recommendations/${encodeURIComponent(id)}/approve`,
      {
        method: 'POST',
        body: JSON.stringify({}),
      }
    );
  }

  async dismissAiRecommendation(workspaceId: string, id: string): Promise<{ success: boolean; recommendation: AiRecommendation }> {
    return this.request<{ success: boolean; recommendation: AiRecommendation }>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/ai/recommendations/${encodeURIComponent(id)}/dismiss`,
      {
        method: 'POST',
        body: JSON.stringify({}),
      }
    );
  }

  async chatAi(workspaceId: string, prompt: string, providerId?: string): Promise<{ reply: string; proposedActions?: any[] }> {
    return this.request<{ reply: string; proposedActions?: any[] }>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/ai/chat`, {
      method: 'POST',
      body: JSON.stringify({ prompt, providerId }),
    });
  }

  // Professional Reports
  async listReports(workspaceId: string): Promise<Report[]> {
    return this.request<Report[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/reports`);
  }

  async getReport(workspaceId: string, reportId: string): Promise<Report> {
    return this.request<Report>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/reports/${encodeURIComponent(reportId)}`);
  }

  async generateReport(workspaceId: string, input: { title: string; reportType?: string; scopeId?: string }): Promise<Report> {
    return this.request<Report>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/reports`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async getReportHtml(workspaceId: string, reportId: string): Promise<string> {
    const url = `${this.baseUrl}/api/v1/workspaces/${encodeURIComponent(workspaceId)}/reports/${encodeURIComponent(reportId)}/html`;
    const token = this.getToken();
    const headers = new Headers();
    if (token) headers.set('Authorization', `Bearer ${token}`);
    headers.set('X-Correlation-ID', this.generateCorrelationId());
    const resp = await fetch(url, { headers });
    if (!resp.ok) {
      throw new Error(`Failed to load report HTML: ${resp.status}`);
    }
    return resp.text();
  }

  // User Preferences & Saved Layouts
  async getUserPreferences(): Promise<UserPreferences> {
    return this.request<UserPreferences>('/api/v1/users/me/preferences');
  }

  async saveUserPreferences(prefs: Partial<UserPreferences>): Promise<UserPreferences> {
    return this.request<UserPreferences>('/api/v1/users/me/preferences', {
      method: 'PUT',
      body: JSON.stringify(prefs),
    });
  }

  // Interactive Graph
  async getGraph(workspaceId: string): Promise<GraphData> {
    return this.request<GraphData>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/graph`);
  }

  async saveGraph(
    workspaceId: string,
    layout: { name?: string; positions: Record<string, { x: number; y: number }>; annotations?: any[]; filters?: any }
  ): Promise<{ success: boolean }> {
    return this.request<{ success: boolean }>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/graph`, {
      method: 'PUT',
      body: JSON.stringify(layout),
    });
  }

  // Threat Intelligence & Geographic Intelligence
  async getGeoIntel(workspaceId?: string): Promise<GeoIntelData> {
    const endpoint = workspaceId
      ? `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/threat-intel/geo`
      : '/api/v1/threat-intel/geo';
    return this.request<GeoIntelData>(endpoint);
  }

  async getThreatFeed(): Promise<{ feed: any[]; provider: string }> {
    return this.request<{ feed: any[]; provider: string }>('/api/v1/threat-intel/feed');
  }

  async getCve(cveId: string): Promise<any> {
    return this.request<any>(`/api/v1/threat-intel/cve/${encodeURIComponent(cveId)}`);
  }
}
