/**
 * Shadow : Helix Nebula (SHN) — OpenAPI 3.1 Contract Specification
 *
 * Authoritative Spec: Phase 0.5 (API-FST-001, API-FST-002), Phase 0.14 (Perimeter B, OpenAPI 3.1).
 * Defines the complete, machine-readable REST API contracts, RFC 7807 problem details,
 * nominal identifier formats, and RBAC requirements.
 */

export const OPENAPI_3_1_SPEC = {
  openapi: '3.1.0',
  info: {
    title: 'Shadow : Helix Nebula (SHN) — Sovereign Cybersecurity Platform API',
    version: '1.0.0',
    description:
      'Authoritative Level 2/3 REST API and Real-Time Event Gateway for Shadow : Helix Nebula (SHN). Built strictly upon Phase 0 architectural invariants (INV-01, INV-02, INV-06, INV-09, INV-14, INV-19) with RFC 7807 Problem Details and multi-tenant hermeticity.',
    license: {
      name: 'Proprietary / Sovereign',
    },
  },
  servers: [
    {
      url: '/',
      description: 'Current Sovereign Gateway Instance',
    },
  ],
  tags: [
    { name: 'Health & Telemetry', description: 'Operational health probes and Prometheus metrics' },
    { name: 'Authentication & Identity', description: 'Zero-trust authentication, token rotation, and operator profile' },
    { name: 'Workspaces', description: 'Logical multi-tenant workspace isolation boundaries (WKS-ISO-001)' },
    { name: 'Scopes', description: 'Pre-dispatch 5-dimensional target scope perimeters (SCP-DEF-001, SCP-ENF-001)' },
    { name: 'Asset Inventory', description: 'Deterministic canonical target asset discovery and tracking (FR-AST-001)' },
    { name: 'Finding Lifecycle', description: 'Cryptographically hashed vulnerability findings and state machine (FR-FND-001)' },
    { name: 'Capabilities', description: 'Tool-agnostic capability registry and adapter provider catalog (BC-CAP)' },
    { name: 'Executions', description: 'Supervised sandboxed execution dispatch and state tracking (BC-EXE)' },
    { name: 'Audit Activity', description: 'Append-only immutable audit ledger queries (SEC-AUD-001, DATA-INV-07)' },
    { name: 'Real-Time Streaming', description: 'Server-Sent Events (SSE) telemetry and domain event distribution (API-EVT-001)' },
  ],
  paths: {
    '/health/live': {
      get: {
        tags: ['Health & Telemetry'],
        summary: 'Liveness Probe',
        description: 'Returns HTTP 200 UP if the HTTP process is alive.',
        responses: {
          '200': {
            description: 'Process is alive',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HealthStatus' },
              },
            },
          },
        },
      },
    },
    '/health/ready': {
      get: {
        tags: ['Health & Telemetry'],
        summary: 'Readiness Probe',
        description: 'Returns HTTP 200 UP if database and downstream substrates are ready for traffic.',
        responses: {
          '200': {
            description: 'System is ready',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HealthStatus' },
              },
            },
          },
          '503': {
            description: 'System is not ready',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
              },
            },
          },
        },
      },
    },
    '/metrics': {
      get: {
        tags: ['Health & Telemetry'],
        summary: 'Prometheus Metrics Scraping Endpoint',
        description: 'Serializes platform operational metrics into Prometheus text exposition format.',
        responses: {
          '200': {
            description: 'Prometheus metrics',
            content: {
              'text/plain': {
                schema: { type: 'string' },
              },
            },
          },
        },
      },
    },
    '/api/v1/auth/register': {
      post: {
        tags: ['Authentication & Identity'],
        summary: 'Register Initial Organization & Operator',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/RegisterRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Organization and operator successfully registered',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthResponse' },
              },
            },
          },
          '400': { $ref: '#/components/responses/BadRequestProblem' },
          '409': { $ref: '#/components/responses/ConflictProblem' },
        },
      },
    },
    '/api/v1/auth/login': {
      post: {
        tags: ['Authentication & Identity'],
        summary: 'Authenticate Operator',
        description: 'Validates operator credentials, issues signed SecurityContextToken.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/LoginRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Operator authenticated successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthResponse' },
              },
            },
          },
          '401': { $ref: '#/components/responses/UnauthorizedProblem' },
          '423': { $ref: '#/components/responses/AccountLockedProblem' },
        },
      },
    },
    '/api/v1/auth/me': {
      get: {
        tags: ['Authentication & Identity'],
        summary: 'Get Authenticated Identity Profile',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Current authenticated actor profile',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/OperatorProfile' },
              },
            },
          },
          '401': { $ref: '#/components/responses/UnauthorizedProblem' },
        },
      },
    },
    '/api/v1/workspaces': {
      get: {
        tags: ['Workspaces'],
        summary: 'List Operator Workspaces',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'List of accessible workspaces',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/Workspace' },
                },
              },
            },
          },
          '401': { $ref: '#/components/responses/UnauthorizedProblem' },
        },
      },
      post: {
        tags: ['Workspaces'],
        summary: 'Create Workspace',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateWorkspaceRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Workspace created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Workspace' },
              },
            },
          },
          '400': { $ref: '#/components/responses/BadRequestProblem' },
          '401': { $ref: '#/components/responses/UnauthorizedProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}': {
      get: {
        tags: ['Workspaces'],
        summary: 'Get Workspace Details',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        responses: {
          '200': {
            description: 'Workspace details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Workspace' },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/scopes': {
      get: {
        tags: ['Scopes'],
        summary: 'List Scope Boundaries',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        responses: {
          '200': {
            description: 'List of defined target scope perimeters',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/Scope' },
                },
              },
            },
          },
        },
      },
      post: {
        tags: ['Scopes'],
        summary: 'Create Scope Boundary',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateScopeRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Scope boundary created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Scope' },
              },
            },
          },
          '400': { $ref: '#/components/responses/BadRequestProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/scopes/{scopeId}': {
      get: {
        tags: ['Scopes'],
        summary: 'Get Scope Boundary Details',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'scopeId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: {
          '200': {
            description: 'Scope boundary details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Scope' },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/assets': {
      get: {
        tags: ['Asset Inventory'],
        summary: 'List Inventory Assets',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'type', in: 'query', schema: { type: 'string' } },
          { name: 'criticality', in: 'query', schema: { type: 'string' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
        ],
        responses: {
          '200': {
            description: 'List of registered assets',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/Asset' },
                },
              },
            },
          },
        },
      },
      post: {
        tags: ['Asset Inventory'],
        summary: 'Register Asset',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/RegisterAssetRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Asset registered',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Asset' },
              },
            },
          },
          '400': { $ref: '#/components/responses/BadRequestProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/assets/{assetId}': {
      get: {
        tags: ['Asset Inventory'],
        summary: 'Get Asset Details',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'assetId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: {
          '200': {
            description: 'Asset details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Asset' },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundProblem' },
        },
      },
      patch: {
        tags: ['Asset Inventory'],
        summary: 'Update Asset Details',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'assetId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UpdateAssetRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Asset updated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Asset' },
              },
            },
          },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/findings': {
      get: {
        tags: ['Finding Lifecycle'],
        summary: 'List Findings',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'severity', in: 'query', schema: { type: 'string' } },
          { name: 'status', in: 'query', schema: { type: 'string' } },
        ],
        responses: {
          '200': {
            description: 'List of findings',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/Finding' },
                },
              },
            },
          },
        },
      },
      post: {
        tags: ['Finding Lifecycle'],
        summary: 'Record Finding',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/RecordFindingRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Finding recorded',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Finding' },
              },
            },
          },
          '400': { $ref: '#/components/responses/BadRequestProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/findings/{findingId}': {
      get: {
        tags: ['Finding Lifecycle'],
        summary: 'Get Finding Details',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'findingId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: {
          '200': {
            description: 'Finding details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Finding' },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/findings/{findingId}/transitions': {
      post: {
        tags: ['Finding Lifecycle'],
        summary: 'Execute Finding State Transition',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'findingId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/TransitionFindingRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Finding status transitioned',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Finding' },
              },
            },
          },
          '400': { $ref: '#/components/responses/BadRequestProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/findings/{findingId}/history': {
      get: {
        tags: ['Finding Lifecycle'],
        summary: 'Get Finding Transition History',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'findingId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: {
          '200': {
            description: 'Transition audit trail',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/FindingHistoryRecord' },
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/capabilities': {
      get: {
        tags: ['Capabilities'],
        summary: 'List Registered Platform Capabilities',
        responses: {
          '200': {
            description: 'List of abstract capability manifests',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/CapabilityManifest' },
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/capabilities/{capabilityId}': {
      get: {
        tags: ['Capabilities'],
        summary: 'Get Capability Manifest',
        parameters: [
          { name: 'capabilityId', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: {
          '200': {
            description: 'Capability manifest details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CapabilityManifest' },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/capabilities': {
      get: {
        tags: ['Capabilities'],
        summary: 'List Capabilities with Workspace Overrides',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        responses: {
          '200': {
            description: 'Capabilities enabled and configured for the active workspace',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/CapabilityManifest' },
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/executions': {
      get: {
        tags: ['Executions'],
        summary: 'List Workspace Executions',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        responses: {
          '200': {
            description: 'List of executions',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/Execution' },
                },
              },
            },
          },
        },
      },
      post: {
        tags: ['Executions'],
        summary: 'Dispatch Capability Execution',
        description: 'Validates target scope pre-dispatch, issues ScopeToken, and dispatches to Execution Supervisor.',
        security: [{ bearerAuth: [] }],
        parameters: [{ $ref: '#/components/parameters/WorkspaceIdParam' }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/DispatchExecutionRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Execution dispatched and completed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Execution' },
              },
            },
          },
          '201': {
            description: 'Execution created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Execution' },
              },
            },
          },
          '400': { $ref: '#/components/responses/BadRequestProblem' },
          '403': { $ref: '#/components/responses/ForbiddenProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/executions/{executionId}': {
      get: {
        tags: ['Executions'],
        summary: 'Get Execution Details',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'executionId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: {
          '200': {
            description: 'Execution details, logs, attempts, and artifacts',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Execution' },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundProblem' },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/audit': {
      get: {
        tags: ['Audit Activity'],
        summary: 'Query Append-Only Audit Ledger',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 100 } },
        ],
        responses: {
          '200': {
            description: 'Tamper-evident audit events',
            content: {
              'application/json': {
                schema: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/AuditEvent' },
                },
              },
            },
          },
        },
      },
    },
    '/api/v1/workspaces/{workspaceId}/events/stream': {
      get: {
        tags: ['Real-Time Streaming'],
        summary: 'Subscribe to Real-Time Telemetry & Domain Event Stream',
        description: 'Server-Sent Events (SSE) streaming live execution updates, finding state changes, asset discoveries, and audit events.',
        security: [{ bearerAuth: [] }],
        parameters: [
          { $ref: '#/components/parameters/WorkspaceIdParam' },
          { name: 'token', in: 'query', description: 'Alternative token query parameter for browser EventSource API', schema: { type: 'string' } },
        ],
        responses: {
          '200': {
            description: 'Server-Sent Events stream',
            content: {
              'text/event-stream': {
                schema: {
                  type: 'string',
                  example: 'event: connected\ndata: {"status":"CONNECTED"}\n\n',
                },
              },
            },
          },
          '401': { $ref: '#/components/responses/UnauthorizedProblem' },
          '404': { $ref: '#/components/responses/NotFoundProblem' },
        },
      },
    },
    '/openapi.json': {
      get: {
        tags: ['Health & Telemetry'],
        summary: 'Get OpenAPI 3.1 Specification',
        responses: {
          '200': {
            description: 'Complete OpenAPI 3.1 contract document',
            content: {
              'application/json': {
                schema: { type: 'object' },
              },
            },
          },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'HMAC-SHA256 signed SecurityContextToken issued by Ingress Gateway.',
      },
    },
    parameters: {
      WorkspaceIdParam: {
        name: 'workspaceId',
        in: 'path',
        required: true,
        schema: { type: 'string', format: 'uuid' },
        description: 'Target logical workspace UUIDv7',
      },
    },
    responses: {
      BadRequestProblem: {
        description: 'Invalid input or request validation failure',
        content: {
          'application/problem+json': {
            schema: { $ref: '#/components/schemas/ProblemDetails' },
          },
        },
      },
      UnauthorizedProblem: {
        description: 'Missing, malformed, or invalid bearer authentication token',
        content: {
          'application/problem+json': {
            schema: { $ref: '#/components/schemas/ProblemDetails' },
          },
        },
      },
      ForbiddenProblem: {
        description: 'Insufficient RBAC permissions or target out of scope bounds',
        content: {
          'application/problem+json': {
            schema: { $ref: '#/components/schemas/ProblemDetails' },
          },
        },
      },
      NotFoundProblem: {
        description: 'Requested resource not found or not in operator workspace',
        content: {
          'application/problem+json': {
            schema: { $ref: '#/components/schemas/ProblemDetails' },
          },
        },
      },
      ConflictProblem: {
        description: 'Resource conflict or duplicate entity',
        content: {
          'application/problem+json': {
            schema: { $ref: '#/components/schemas/ProblemDetails' },
          },
        },
      },
      AccountLockedProblem: {
        description: 'Account temporarily locked due to consecutive authentication failures',
        content: {
          'application/problem+json': {
            schema: { $ref: '#/components/schemas/ProblemDetails' },
          },
        },
      },
    },
    schemas: {
      ProblemDetails: {
        type: 'object',
        required: ['type', 'title', 'status', 'detail', 'instance'],
        properties: {
          type: { type: 'string', format: 'uri' },
          title: { type: 'string' },
          status: { type: 'integer' },
          detail: { type: 'string' },
          instance: { type: 'string' },
          code: { type: 'string' },
          correlationId: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
          invalidParams: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                reason: { type: 'string' },
              },
            },
          },
        },
      },
      HealthStatus: {
        type: 'object',
        required: ['status', 'timestamp'],
        properties: {
          status: { type: 'string', enum: ['UP', 'DOWN'] },
          timestamp: { type: 'string', format: 'date-time' },
          components: { type: 'object' },
        },
      },
      LoginRequest: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8 },
        },
      },
      RegisterRequest: {
        type: 'object',
        required: ['orgName', 'orgSlug', 'email', 'displayName', 'password'],
        properties: {
          orgName: { type: 'string' },
          orgSlug: { type: 'string' },
          email: { type: 'string', format: 'email' },
          displayName: { type: 'string' },
          password: { type: 'string', minLength: 8 },
        },
      },
      AuthResponse: {
        type: 'object',
        required: ['token', 'user', 'organization', 'workspaces'],
        properties: {
          token: { type: 'string' },
          user: {
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uuid' },
              email: { type: 'string' },
              displayName: { type: 'string' },
            },
          },
          organization: {
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uuid' },
              name: { type: 'string' },
              slug: { type: 'string' },
            },
          },
          workspaces: {
            type: 'array',
            items: { $ref: '#/components/schemas/Workspace' },
          },
        },
      },
      OperatorProfile: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          organizationId: { type: 'string', format: 'uuid' },
          email: { type: 'string' },
          roles: { type: 'array', items: { type: 'string' } },
          permissionMask: { type: 'integer' },
        },
      },
      Workspace: {
        type: 'object',
        required: ['id', 'organizationId', 'name', 'slug', 'environment'],
        properties: {
          id: { type: 'string', format: 'uuid' },
          organizationId: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          slug: { type: 'string' },
          environment: { type: 'string', enum: ['LOCAL', 'DEVELOPMENT', 'STAGING', 'PRODUCTION'] },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      CreateWorkspaceRequest: {
        type: 'object',
        required: ['name', 'slug', 'environment'],
        properties: {
          name: { type: 'string' },
          slug: { type: 'string' },
          environment: { type: 'string', enum: ['LOCAL', 'DEVELOPMENT', 'STAGING', 'PRODUCTION'] },
        },
      },
      Scope: {
        type: 'object',
        required: ['id', 'workspaceId', 'name', 'inclusions'],
        properties: {
          id: { type: 'string', format: 'uuid' },
          workspaceId: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          description: { type: 'string' },
          inclusions: { type: 'array', items: { type: 'object' } },
          exclusions: { type: 'array', items: { type: 'object' } },
          allowedPorts: { type: 'array', items: { type: 'integer' } },
          allowedActions: { type: 'array', items: { type: 'string' } },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
      CreateScopeRequest: {
        type: 'object',
        required: ['name', 'inclusions'],
        properties: {
          name: { type: 'string' },
          description: { type: 'string' },
          inclusions: { type: 'array', items: { type: 'object' } },
          exclusions: { type: 'array', items: { type: 'object' } },
          allowedPorts: { type: 'array', items: { type: 'integer' } },
          allowedActions: { type: 'array', items: { type: 'string' } },
        },
      },
      Asset: {
        type: 'object',
        required: ['id', 'workspaceId', 'type', 'canonicalValue'],
        properties: {
          id: { type: 'string', format: 'uuid' },
          workspaceId: { type: 'string', format: 'uuid' },
          organizationId: { type: 'string', format: 'uuid' },
          type: { type: 'string', enum: ['IPV4', 'IPV6', 'CIDR', 'FQDN', 'URL'] },
          canonicalValue: { type: 'string' },
          name: { type: 'string' },
          criticality: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
          status: { type: 'string', enum: ['ACTIVE', 'INACTIVE', 'ARCHIVED'] },
          tags: { type: 'array', items: { type: 'string' } },
          metadata: { type: 'object' },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      RegisterAssetRequest: {
        type: 'object',
        required: ['type', 'rawTarget'],
        properties: {
          type: { type: 'string', enum: ['IPV4', 'IPV6', 'CIDR', 'FQDN', 'URL'] },
          rawTarget: { type: 'string' },
          name: { type: 'string' },
          criticality: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default: 'MEDIUM' },
          tags: { type: 'array', items: { type: 'string' } },
          metadata: { type: 'object' },
        },
      },
      UpdateAssetRequest: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          criticality: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
          status: { type: 'string', enum: ['ACTIVE', 'INACTIVE', 'ARCHIVED'] },
          tags: { type: 'array', items: { type: 'string' } },
          metadata: { type: 'object' },
        },
      },
      Finding: {
        type: 'object',
        required: ['id', 'workspaceId', 'title', 'severity', 'status', 'evidenceHash'],
        properties: {
          id: { type: 'string', format: 'uuid' },
          workspaceId: { type: 'string', format: 'uuid' },
          organizationId: { type: 'string', format: 'uuid' },
          assetId: { type: 'string', format: 'uuid' },
          title: { type: 'string' },
          description: { type: 'string' },
          severity: { type: 'string', enum: ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
          status: {
            type: 'string',
            enum: ['DRAFT', 'CONFIRMED', 'IN_TRIAGE', 'REMEDIATION_PENDING', 'REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'],
          },
          cweIds: { type: 'array', items: { type: 'string' } },
          cvssScore: { type: 'number' },
          cvssVector: { type: 'string' },
          evidenceHash: { type: 'string', minLength: 64, maxLength: 64 },
          metadata: { type: 'object' },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      RecordFindingRequest: {
        type: 'object',
        required: ['title', 'severity', 'rawEvidence'],
        properties: {
          assetId: { type: 'string', format: 'uuid' },
          title: { type: 'string' },
          description: { type: 'string' },
          severity: { type: 'string', enum: ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
          cweIds: { type: 'array', items: { type: 'string' } },
          cvssScore: { type: 'number' },
          cvssVector: { type: 'string' },
          rawEvidence: { type: 'string' },
          metadata: { type: 'object' },
        },
      },
      TransitionFindingRequest: {
        type: 'object',
        required: ['targetStatus'],
        properties: {
          targetStatus: {
            type: 'string',
            enum: ['DRAFT', 'CONFIRMED', 'IN_TRIAGE', 'REMEDIATION_PENDING', 'REMEDIATED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'],
          },
          comment: { type: 'string' },
        },
      },
      FindingHistoryRecord: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          findingId: { type: 'string', format: 'uuid' },
          fromStatus: { type: 'string' },
          toStatus: { type: 'string' },
          comment: { type: 'string' },
          changedBy: { type: 'string', format: 'uuid' },
          changedAt: { type: 'string', format: 'date-time' },
        },
      },
      CapabilityManifest: {
        type: 'object',
        required: ['id', 'name', 'version', 'displayName', 'category', 'riskLevel'],
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          version: { type: 'string' },
          displayName: { type: 'string' },
          description: { type: 'string' },
          category: { type: 'string' },
          riskLevel: { type: 'string' },
          supportedTargets: { type: 'array', items: { type: 'string' } },
          argumentSchema: { type: 'object' },
          outputSchema: { type: 'object' },
          lifecycleState: { type: 'string' },
        },
      },
      DispatchExecutionRequest: {
        type: 'object',
        required: ['capabilityId', 'target', 'scopeId', 'action'],
        properties: {
          capabilityId: { type: 'string' },
          target: { type: 'string' },
          scopeId: { type: 'string', format: 'uuid' },
          action: { type: 'string' },
          arguments: { type: 'object' },
        },
      },
      Execution: {
        type: 'object',
        required: ['id', 'workspaceId', 'capabilityId', 'target', 'status'],
        properties: {
          id: { type: 'string', format: 'uuid' },
          workspaceId: { type: 'string', format: 'uuid' },
          capabilityId: { type: 'string' },
          target: { type: 'string' },
          status: { type: 'string' },
          output: { type: 'object' },
          startedAt: { type: 'string', format: 'date-time' },
          completedAt: { type: 'string', format: 'date-time' },
        },
      },
      AuditEvent: {
        type: 'object',
        required: ['eventId', 'workspaceId', 'eventType', 'occurredAt'],
        properties: {
          eventId: { type: 'string', format: 'uuid' },
          workspaceId: { type: 'string', format: 'uuid' },
          eventType: { type: 'string' },
          actorId: { type: 'string', format: 'uuid' },
          details: { type: 'object' },
          occurredAt: { type: 'string', format: 'date-time' },
        },
      },
    },
  },
} as const;
