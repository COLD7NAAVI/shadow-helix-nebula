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
  async login(credentials: { email: string; password: string; workspaceId?: string }): Promise<LoginResponse> {
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
    return this.request<Capability[]>('/api/v1/capabilities');
  }

  async getCapability(capabilityId: string): Promise<Capability> {
    return this.request<Capability>(`/api/v1/capabilities/${encodeURIComponent(capabilityId)}`);
  }

  async listWorkspaceCapabilities(workspaceId: string): Promise<Capability[]> {
    return this.request<Capability[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/capabilities`);
  }

  // Executions
  async listExecutions(workspaceId: string): Promise<Execution[]> {
    return this.request<Execution[]>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/executions`);
  }

  async getExecution(workspaceId: string, executionId: string): Promise<Execution> {
    return this.request<Execution>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/executions/${encodeURIComponent(executionId)}`
    );
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
    return this.request<Execution>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/executions`, {
      method: 'POST',
      body: JSON.stringify(input),
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
}
