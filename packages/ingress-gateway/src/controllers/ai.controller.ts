/**
 * Shadow : Helix Nebula (SHN) — AI Orchestration & Provider Controller
 *
 * Manages configurable AI providers (OpenAI-compatible, Ollama, Anthropic, Local Heuristic),
 * secure key vault integration, evidence-driven recommendations, and conversational assistance.
 */

import { generateUUIDv7 } from '@shn/shared-kernel';
import { ErrorCode, createProblemDetails } from '@shn/error-catalog';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface AiControllerOptions {
  aiProviderRepo?: any;
  aiRecommendationRepo?: any;
  assetRepo?: any;
  findingRepo?: any;
  executionRepo?: any;
  scopeRepo?: any;
  workspaceRepo?: any;
  capabilityDispatcher?: any;
  secretsVault?: any;
}

export class AiController {
  constructor(private readonly opts: AiControllerOptions) {}

  async listProviders(req: IngressRequest, res: IngressResponse): Promise<void> {
    let orgId = req.actor?.organizationId;
    if ((!orgId || (orgId as string) === (req.workspaceId as string)) && this.opts.workspaceRepo && req.workspaceId) {
      try {
        const ws = await this.opts.workspaceRepo.findById(req.workspaceId);
        if (ws) orgId = ws.organization_id || ws.organizationId;
      } catch {}
    }
    if (!orgId) orgId = '01a139c6-0d9b-7438-8ab4-1e7de3e3b052' as any;

    if (!this.opts.aiProviderRepo) {
      res.status(200).json([]);
      return;
    }
    try {
      const providers = await this.opts.aiProviderRepo.listByOrganization(orgId);
      // Redact secret references
      const safe = providers.map((p: any) => ({
        ...p,
        secretId: p.secretId ? '[CONFIGURED]' : null,
      }));
      res.status(200).json(safe);
    } catch (err: any) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: err?.message || 'Failed to list AI providers',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
    }
  }

  async createProvider(req: IngressRequest, res: IngressResponse): Promise<void> {
    let orgId = req.actor?.organizationId;
    if ((!orgId || (orgId as string) === (req.workspaceId as string)) && this.opts.workspaceRepo && req.workspaceId) {
      try {
        const ws = await this.opts.workspaceRepo.findById(req.workspaceId);
        if (ws) orgId = ws.organization_id || ws.organizationId;
      } catch {}
    }
    if (!orgId) orgId = '01a139c6-0d9b-7438-8ab4-1e7de3e3b052' as any;
    const userId = req.actor?.id ?? '01a14abf-c197-74f4-8bbd-555eefc2a4b6';
    const body = req.body ?? {};
    const { providerType, displayName, baseUrl, modelName, apiKey, maxTokens, temperature, isDefault } = body;

    if (!providerType || !displayName || !modelName) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
          detail: 'Missing required provider fields: providerType, displayName, modelName',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
      return;
    }

    if (!this.opts.aiProviderRepo) {
      res.status(201).json({ id: generateUUIDv7(), ...body, secretId: null, healthStatus: 'HEALTHY' });
      return;
    }

    try {
      let secretId: string | null = null;
      if (apiKey && this.opts.secretsVault) {
        // Encrypt secret material in the secrets vault
        const secretRes = await this.opts.secretsVault.storeSecret({
          workspaceId: req.workspaceId ?? '00000000-0000-7000-8000-000000000003',
          organizationId: orgId,
          name: `ai_key_${displayName.toLowerCase().replace(/[^a-z0-9]/g, '_')}_${Date.now()}`,
          secretType: 'API_KEY',
          plaintext: Buffer.from(apiKey, 'utf8'),
          createdBy: userId,
        });
        if (secretRes?.id) {
          secretId = secretRes.id;
        }
      }

      const record = await this.opts.aiProviderRepo.create({
        organizationId: orgId,
        providerType,
        displayName,
        baseUrl: baseUrl || null,
        modelName,
        secretId,
        maxTokens: Number(maxTokens) || 4096,
        temperature: Number(temperature) || 0.2,
        isDefault: Boolean(isDefault),
        createdBy: userId,
        privacyAcknowledged: true,
      });

      res.status(201).json({
        ...record,
        secretId: record.secretId ? '[CONFIGURED]' : null,
      });
    } catch (err: any) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: err?.message || 'Failed to create AI provider',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
    }
  }

  async testConnection(req: IngressRequest, res: IngressResponse): Promise<void> {
    const body = req.body ?? {};
    const { providerType, baseUrl, modelName, apiKey } = body;

    const start = Date.now();
    try {
      if (providerType === 'LOCAL_HEURISTIC') {
        res.status(200).json({
          success: true,
          providerType,
          modelName: 'shn-sovereign-heuristic-v1',
          latencyMs: Date.now() - start,
          message: 'Sovereign local heuristic analysis engine operational',
        });
        return;
      }

      if (providerType === 'OLLAMA') {
        const url = (baseUrl || 'http://localhost:11434').replace(/\/$/, '') + '/api/tags';
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        try {
          const resp = await fetch(url, { signal: controller.signal });
          clearTimeout(timeout);
          if (resp.ok) {
            const data: any = await resp.json();
            res.status(200).json({
              success: true,
              providerType,
              modelName,
              latencyMs: Date.now() - start,
              modelsAvailable: (data?.models || []).map((m: any) => m.name),
              message: 'Ollama local endpoint reachable and verified',
            });
            return;
          }
        } catch {
          clearTimeout(timeout);
        }
        res.status(200).json({
          success: false,
          providerType,
          latencyMs: Date.now() - start,
          message: 'Ollama endpoint not responding at ' + (baseUrl || 'http://localhost:11434') + '. Verify local Ollama service is running.',
        });
        return;
      }

      if (providerType === 'OPENAI_COMPATIBLE' || providerType === 'ANTHROPIC') {
        if (!apiKey) {
          res.status(200).json({
            success: false,
            providerType,
            message: 'API Key is required to test remote provider connectivity',
          });
          return;
        }

        const endpoint = baseUrl ? `${baseUrl.replace(/\/$/, '')}/models` : 'https://api.openai.com/v1/models';
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 6000);
        try {
          const resp = await fetch(endpoint, {
            headers: { Authorization: `Bearer ${apiKey}` },
            signal: controller.signal,
          });
          clearTimeout(timeout);
          if (resp.ok) {
            res.status(200).json({
              success: true,
              providerType,
              modelName,
              latencyMs: Date.now() - start,
              message: 'Remote AI endpoint authenticated and connected successfully',
            });
            return;
          } else {
            const errBody = await resp.text();
            res.status(200).json({
              success: false,
              providerType,
              latencyMs: Date.now() - start,
              message: `HTTP ${resp.status} response from endpoint: ${errBody.slice(0, 120)}`,
            });
            return;
          }
        } catch (fetchErr: any) {
          clearTimeout(timeout);
          res.status(200).json({
            success: false,
            providerType,
            latencyMs: Date.now() - start,
            message: `Connection error: ${fetchErr?.message || 'Network unreachable'}`,
          });
          return;
        }
      }

      res.status(200).json({
        success: true,
        providerType: providerType || 'LOCAL_HEURISTIC',
        latencyMs: 1,
        message: 'Default provider configuration evaluated',
      });
    } catch (err: any) {
      res.status(200).json({
        success: false,
        latencyMs: Date.now() - start,
        message: err?.message || 'Connection test failed',
      });
    }
  }

  async listRecommendations(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId;
    if (!workspaceId) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
          detail: 'Missing workspaceId',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
      return;
    }

    if (!this.opts.aiRecommendationRepo) {
      res.status(200).json([]);
      return;
    }

    try {
      let recs = await this.opts.aiRecommendationRepo.listByWorkspace(workspaceId);
      if (recs.length === 0) {
        let orgId = req.actor?.organizationId;
        if ((!orgId || (orgId as string) === (workspaceId as string)) && this.opts.workspaceRepo) {
          try {
            const ws = await this.opts.workspaceRepo.findById(workspaceId);
            if (ws) orgId = ws.organization_id || ws.organizationId;
          } catch {}
        }
        if (!orgId) orgId = '01a139c6-0d9b-7438-8ab4-1e7de3e3b052' as any;
        // Proactively generate initial recommendation baseline from real assets
        recs = await this.generateBaselineRecommendations(workspaceId, orgId as any);
      }
      res.status(200).json(recs);
    } catch (err: any) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: err?.message || 'Failed to list AI recommendations',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
    }
  }

  async generateRecommendations(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId;
    if (!workspaceId) {
      res.status(400).json({ error: 'Missing workspaceId' });
      return;
    }
    let orgId = req.actor?.organizationId;
    if ((!orgId || (orgId as string) === (workspaceId as string)) && this.opts.workspaceRepo) {
      try {
        const ws = await this.opts.workspaceRepo.findById(workspaceId);
        if (ws) orgId = ws.organization_id || ws.organizationId;
      } catch {}
    }
    if (!orgId) orgId = '01a139c6-0d9b-7438-8ab4-1e7de3e3b052' as any;

    try {
      const recs = await this.generateBaselineRecommendations(workspaceId, orgId as any);
      res.status(200).json(recs);
    } catch (err: any) {
      console.warn('[AI Controller] Error generating recommendations:', err?.message);
      if (this.opts.aiRecommendationRepo) {
        try {
          const existing = await this.opts.aiRecommendationRepo.listByWorkspace(workspaceId);
          res.status(200).json(existing);
          return;
        } catch {}
      }
      res.status(200).json([]);
    }
  }

  async approveRecommendation(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId;
    const id = req.params['id'];
    const userId = req.actor?.id ?? '01a14abf-c197-74f4-8bbd-555eefc2a4b6';
    const orgId = req.actor?.organizationId ?? (req.securityContext?.workspace_id as any);

    if (!this.opts.aiRecommendationRepo || !id || !workspaceId) {
      res.status(404).json({ error: 'Recommendation not found' });
      return;
    }

    try {
      const rec = await this.opts.aiRecommendationRepo.findById(id, workspaceId);
      if (!rec) {
        res.status(404).json({ error: 'Recommendation not found' });
        return;
      }

      let executionResult: any = null;
      if (this.opts.capabilityDispatcher) {
        // Dispatch tool invocation through strict ScopeGatekeeper and ExecutionSupervisor
        try {
          const execRes = await this.opts.capabilityDispatcher.executeCapability({
            workspaceId,
            organizationId: orgId,
            actorId: userId,
            capabilityId: rec.proposedCapability,
            target: rec.target,
            parameters: rec.parameters ?? {},
            securityContext: req.securityContext,
          });
          if (execRes.isOk) {
            executionResult = execRes.value.executionId;
          } else {
            sendProblemDetails(res, execRes.error);
            return;
          }
        } catch (dispatchErr: any) {
          sendProblemDetails(
            res,
            createProblemDetails({
              errorCode: ErrorCode.ADAPTER_EXECUTION_FAILED,
              detail: dispatchErr?.message || 'Recommendation execution dispatch failed',
              instance: req.path,
              correlationId: req.correlationId,
            })
          );
          return;
        }
      }

      const updated = await this.opts.aiRecommendationRepo.updateStatus(id, workspaceId, 'APPROVED', {
        approvedBy: userId,
        executionId: executionResult,
      });

      res.status(200).json({
        recommendation: updated,
        executionDispatched: Boolean(executionResult),
        executionId: executionResult,
        statusMessage: executionResult ? 'Execution queued and dispatched through Scope Gatekeeper' : 'Recommendation approved by operator',
      });
    } catch (err: any) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.ADAPTER_EXECUTION_FAILED,
          detail: err?.message || 'Failed to approve recommendation',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
    }
  }

  async dismissRecommendation(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId;
    const id = req.params['id'];
    if (!this.opts.aiRecommendationRepo || !id || !workspaceId) {
      res.status(404).json({ error: 'Recommendation not found' });
      return;
    }
    const updated = await this.opts.aiRecommendationRepo.updateStatus(id, workspaceId, 'DISMISSED');
    res.status(200).json(updated);
  }

  async chat(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId;
    const body = req.body ?? {};
    const { prompt } = body;

    if (!prompt || typeof prompt !== 'string') {
      res.status(400).json({ error: 'Missing prompt' });
      return;
    }

    // Gather real workspace context
    let assetsSummary = '0 monitored assets';
    let findingsSummary = '0 findings recorded';
    let scopesSummary = 'No active scopes';

    try {
      if (this.opts.assetRepo && workspaceId) {
        const assets = await this.opts.assetRepo.listByWorkspace(workspaceId);
        if (assets.length > 0) {
          assetsSummary = `${assets.length} targets: ` + assets.map((a: any) => `${a.name} (${a.canonical_value || a.canonicalValue})`).join(', ');
        }
      }
      if (this.opts.findingRepo && workspaceId) {
        const findings = await this.opts.findingRepo.listByWorkspace(workspaceId);
        if (findings.length > 0) {
          findingsSummary = `${findings.length} findings: ` + findings.map((f: any) => `${f.title} [${f.severity}]`).slice(0, 5).join('; ');
        }
      }
      if (this.opts.scopeRepo && workspaceId) {
        const scopes = await this.opts.scopeRepo.findActiveByWorkspace(workspaceId);
        if (scopes.length > 0) {
          scopesSummary = `Authorized Scope: "${scopes[0].name}" allowing actions: ${(scopes[0].allowed_actions || []).join(', ')}`;
        }
      }
    } catch {}

    const promptLower = prompt.toLowerCase();
    let reply = '';
    const proposedActions: any[] = [];

    if (promptLower.includes('scan') || promptLower.includes('port') || promptLower.includes('nmap')) {
      reply = `Based on current scope policy (${scopesSummary}) and registered targets (${assetsSummary}), I recommend initiating an authorized non-invasive TCP SYN/connect port scan on the primary host. This will discover open network listening services and provide evidence for further HTTP fingerprinting.`;
      proposedActions.push({
        actionId: 'dispatch-port-scan',
        capabilityUri: 'shn://capabilities/network/port-scan',
        action: 'network:scan',
        riskLevel: 'LOW',
        requiresApproval: false,
        label: 'Run Scoped Port Scan (Ports 80, 443, 3000)',
      });
    } else if (promptLower.includes('http') || promptLower.includes('web') || promptLower.includes('header') || promptLower.includes('probe')) {
      reply = `I have analyzed the HTTP service discovery requirements. We should execute HTTP Fingerprinting against the target to inspect security headers (CSP, HSTS, X-Frame-Options) and detect underlying web framework versions.`;
      proposedActions.push({
        actionId: 'dispatch-http-probe',
        capabilityUri: 'shn://capabilities/web/http-discovery',
        action: 'http:probe',
        riskLevel: 'INFORMATIONAL',
        requiresApproval: false,
        label: 'Run HTTP Service & Header Audit',
      });
    } else if (promptLower.includes('tls') || promptLower.includes('ssl') || promptLower.includes('cert')) {
      reply = `We can execute TLS Certificate Inspection to analyze cipher suites, SAN extensions, and certificate validity against the HTTPS endpoint.`;
      proposedActions.push({
        actionId: 'dispatch-tls-inspect',
        capabilityUri: 'shn://capabilities/web/tls-inspect',
        action: 'recon:passive',
        riskLevel: 'INFORMATIONAL',
        requiresApproval: false,
        label: 'Inspect TLS/SSL Certificate',
      });
    } else if (promptLower.includes('report') || promptLower.includes('summary')) {
      reply = `We have ${findingsSummary} and ${assetsSummary}. You can generate a comprehensive Executive Summary or Technical Assessment report directly from the Reports view. All generated reports will be signed with a content SHA-256 hash and include full evidence traceability.`;
      proposedActions.push({
        actionId: 'generate-report',
        label: 'Generate Executive Assessment Report',
      });
    } else {
      reply = `Shadow Helix Nebula AI Security Assistant initialized. Context loaded: ${assetsSummary}; ${findingsSummary}; ${scopesSummary}. I can help you plan passive discovery, analyze scan outputs, correlate vulnerability advisories (CVE), or recommend authorized testing workflows within your declared scope boundaries.`;
    }

    res.status(200).json({
      reply,
      proposedActions,
      context: {
        assetsSummary,
        findingsSummary,
        scopesSummary,
      },
      timestamp: new Date().toISOString(),
    });
  }

  private async generateBaselineRecommendations(workspaceId: string, preferredOrgId?: string): Promise<any[]> {
    if (!this.opts.aiRecommendationRepo) return [];
    let orgId = preferredOrgId;
    if ((!orgId || orgId === workspaceId) && this.opts.workspaceRepo) {
      try {
        const ws = await this.opts.workspaceRepo.findById(workspaceId);
        if (ws) orgId = ws.organization_id || ws.organizationId;
      } catch {}
    }
    if (!orgId) {
      orgId = '01a139c6-0d9b-7438-8ab4-1e7de3e3b052';
    }

    let targets: Array<{ name: string; target: string }> = [];
    if (this.opts.assetRepo) {
      try {
        const assets = await this.opts.assetRepo.listByWorkspace(workspaceId);
        targets = assets
          .map((a: any) => ({
            name: a.name || 'Asset',
            target: a.canonical_value || a.canonicalValue,
          }))
          .filter((t: any) => Boolean(t.target));
      } catch {}
    }

    // Recommendations must strictly ground in real workspace assets and authorized scope
    if (targets.length === 0) {
      return [];
    }

    let activeScopes: any[] = [];
    if (this.opts.scopeRepo) {
      try {
        activeScopes = await this.opts.scopeRepo.findActiveByWorkspace(workspaceId);
      } catch {}
    }

    if (activeScopes.length === 0) {
      return [];
    }

    const created: any[] = [];
    const primary = targets[0]!;

    // Grounded Recommendation 1: HTTP discovery/baseline
    const rec1 = await this.opts.aiRecommendationRepo.create({
      workspaceId,
      organizationId: orgId,
      recommendationId: `rec_http_audit_${Date.now()}_1`,
      objective: `Perform non-invasive HTTP header and banner discovery on ${primary.name}`,
      rationale: `Target ${primary.target} is within authorized workspace inventory. Probing HTTP response headers evaluates defensive headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options) without service disruption.`,
      proposedCapability: 'shn://capabilities/web/http-discovery',
      parameters: { timeoutMs: 5000, followRedirects: true },
      target: primary.target,
      requiredScopeAction: 'http:probe',
      riskLevel: 'INFORMATIONAL',
      requiresApproval: false,
      confidence: 0.95,
      assumptions: ['Target exposes standard HTTP/HTTPS listener', 'Network route is reachable'],
      expectedImpact: 'Generates negligible network traffic (~1 HTTP GET request)',
    });
    created.push(rec1);

    return created;
  }
}
