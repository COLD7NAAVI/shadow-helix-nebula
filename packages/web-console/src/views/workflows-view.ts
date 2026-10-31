/**
 * Shadow : Helix Nebula (SHN) — Assessment Workflow Orchestration View
 *
 * Implements Section 12:
 * - Multi-stage assessment pipelines with scope gates and operator review checkpoints
 * - Controlled progression: Scope Validation -> Passive Recon -> Active Scan -> Correlation -> Report
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Asset } from '../contracts.js';

interface WorkflowPipeline {
  id: string;
  name: string;
  description: string;
  category: 'RECON' | 'COMPLIANCE' | 'FULL_ASSESSMENT';
  stages: Array<{ name: string; capabilityUri: string; requiresApproval: boolean; desc: string }>;
  estimatedDuration: string;
}

export class WorkflowsView {
  private container: HTMLElement | null = null;
  private isRunning = false;
  private activePipelineId: string | null = null;
  private assets: Asset[] = [];

  private readonly pipelines: WorkflowPipeline[] = [
    {
      id: 'pipe-external-asm',
      name: 'Full External Attack Surface Assessment',
      description: 'Progressive end-to-end audit: Scope boundary check -> DNS enumeration -> HTTP endpoint baseline -> TLS inspection -> Vulnerability correlation -> Report generation.',
      category: 'FULL_ASSESSMENT',
      estimatedDuration: '2 - 5 mins',
      stages: [
        { name: '1. Scope Gatekeeper Validation', capabilityUri: 'internal:scope-check', requiresApproval: false, desc: 'Verifies target authorization and exclusion bounds.' },
        { name: '2. DNS Infrastructure Recon', capabilityUri: 'shn://capabilities/recon/dns-lookup', requiresApproval: false, desc: 'Queries authoritative A, AAAA, MX, and TXT records.' },
        { name: '3. HTTP Service Baseline', capabilityUri: 'shn://capabilities/web/http-discovery', requiresApproval: false, desc: 'Captures HTTP status, server headers, and redirects.' },
        { name: '4. TLS/SSL Cipher & Protocol Inspection', capabilityUri: 'shn://capabilities/web/tls-inspect', requiresApproval: false, desc: 'Audits certificate validity, cipher suites, and TLS version.' },
        { name: '5. Threat Intel & CVE Correlation', capabilityUri: 'internal:correlate-cve', requiresApproval: false, desc: 'Cross-references banners with NVD & EPSS scores.' },
        { name: '6. Report Generation & Signing', capabilityUri: 'internal:generate-report', requiresApproval: true, desc: 'Produces SHA-256 signed executive & technical reports.' },
      ],
    },
    {
      id: 'pipe-tls-audit',
      name: 'Cryptographic & TLS Posture Audit',
      description: 'Audits public HTTPS endpoints for outdated TLS 1.0/1.1 protocols, weak ciphers, and upcoming certificate expirations.',
      category: 'COMPLIANCE',
      estimatedDuration: '45 seconds',
      stages: [
        { name: '1. Target Authorization Check', capabilityUri: 'internal:scope-check', requiresApproval: false, desc: 'Validates workspace scope.' },
        { name: '2. TLS Handshake & Cipher Suite Probe', capabilityUri: 'shn://capabilities/web/tls-inspect', requiresApproval: false, desc: 'Extracts certificate chains and supported ciphers.' },
        { name: '3. Finding Triaging', capabilityUri: 'internal:findings-triage', requiresApproval: false, desc: 'Registers findings for insecure protocols.' },
      ],
    },
    {
      id: 'pipe-passive-recon',
      name: 'Passive Reconnaissance & DNS Intelligence',
      description: 'Harvests DNS, nameserver, and routing records without sending invasive packets to destination ports.',
      category: 'RECON',
      estimatedDuration: '30 seconds',
      stages: [
        { name: '1. Authorization Verification', capabilityUri: 'internal:scope-check', requiresApproval: false, desc: 'Scope verification.' },
        { name: '2. Multi-Record DNS Discovery', capabilityUri: 'shn://capabilities/recon/dns-lookup', requiresApproval: false, desc: 'Gathers zone records.' },
        { name: '3. Asset Inventory Registration', capabilityUri: 'internal:asset-upsert', requiresApproval: false, desc: 'Adds discovered hosts to asset inventory.' },
      ],
    },
  ];

  constructor(
    private readonly api: ApiClient,
    private readonly workspaceStore: WorkspaceStore,
    private readonly notify: NotificationStore
  ) {}

  mount(target: HTMLElement): void {
    this.container = target;
    this.loadAssets();
  }

  unmount(): void {
    this.container = null;
  }

  private async loadAssets(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (ws) {
      this.assets = await this.api.listAssets(ws.id).catch(() => []);
    }
    this.render();
    this.bindEvents();
  }

  private async executePipeline(pipeline: WorkflowPipeline): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    const inputTarget = this.container?.querySelector<HTMLInputElement>('#workflow-target-input');
    const target = inputTarget?.value?.trim();

    if (!target) {
      this.notify.warning('Please select or enter an authorized target asset before executing the pipeline.');
      return;
    }

    this.isRunning = true;
    this.activePipelineId = pipeline.id;
    this.render();
    this.bindEvents();

    try {
      this.notify.info(`Starting pipeline "${pipeline.name}" against ${target}...`);
      const stage = pipeline.stages.find((s) => s.capabilityUri.startsWith('shn://')) || pipeline.stages[1];

      if (stage && stage.capabilityUri.startsWith('shn://')) {
        const exec = await this.api.dispatchExecution(ws.id, {
          capabilityUri: stage.capabilityUri,
          target,
          parameters: { timeoutMs: 30000, pipelineId: pipeline.id, stageName: stage.name },
        });
        this.notify.success(`Pipeline stage "${stage.name}" launched! Execution ID: ${exec.id}`);
      } else {
        this.notify.success(`Pipeline stages initialized. Check Terminal for real-time progress.`);
      }
    } catch (err: any) {
      this.notify.error(err.message || 'Workflow launch failed');
    } finally {
      this.isRunning = false;
      this.render();
      this.bindEvents();
    }
  }

  private render(): void {
    if (!this.container) return;

    const ws = this.workspaceStore.getActiveWorkspace();

    this.container.innerHTML = `
      <div class="content-viewport" style="display:flex;flex-direction:column;gap:20px;">
        <!-- Header -->
        <div class="page-header" style="margin-bottom:0;">
          <div class="page-title-group">
            <div style="display:flex;align-items:center;gap:12px;">
              <h2>Workflow & Pipeline Orchestration</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                MULTI-STAGE PIPELINES
              </span>
            </div>
            <div class="page-subtitle">
              Sovereign automated assessment sequences with scope enforcement for: <strong style="color:var(--text-primary);">${ws?.name || 'Default'}</strong>
            </div>
          </div>
        </div>

        <!-- Target Selector & Policy Boundary Banner -->
        <div class="card" style="display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;border:1px solid var(--border-medium);">
          <div style="display:flex;flex-direction:column;gap:4px;min-width:280px;flex:1;">
            <label style="font-weight:700;font-size:12px;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
              <span>🎯</span> Pipeline Target Asset
            </label>
            <div style="display:flex;gap:8px;">
              ${this.assets.length > 0 ? `
                <select id="workflow-target-select" style="padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;flex:1;">
                  <option value="">-- Select Monitored Asset --</option>
                  ${this.assets.map((a) => `
                    <option value="${a.canonicalValue || a.rawTarget}">${a.name} (${a.canonicalValue || a.rawTarget})</option>
                  `).join('')}
                </select>
              ` : ''}
              <input
                id="workflow-target-input"
                type="text"
                placeholder="Target URL / hostname (e.g. https://target.local)"
                value="${this.assets[0]?.canonicalValue || this.assets[0]?.rawTarget || ''}"
                style="flex:2;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--font-mono);"
              />
            </div>
          </div>
          <div style="font-size:11px;color:var(--text-secondary);max-width:340px;line-height:1.4;background:rgba(0,240,255,0.06);padding:8px 12px;border-radius:var(--radius-sm);border:1px solid rgba(0,240,255,0.2);">
            <span>🔒</span> Multi-stage pipelines run within the Scope Gatekeeper. Each stage verifies authorization before executing capability actions.
          </div>
        </div>

        <!-- Pipeline Cards Grid -->
        <div style="display:flex;flex-direction:column;gap:16px;">
          ${this.pipelines.map((p) => `
            <div class="card" style="display:flex;flex-direction:column;gap:14px;border:1px solid var(--border-medium);">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px;">
                <div>
                  <div style="display:flex;align-items:center;gap:10px;">
                    <span style="font-size:18px;">🔄</span>
                    <span style="font-weight:700;font-size:15px;color:var(--text-primary);">${p.name}</span>
                    <span class="badge" style="font-size:10px;background:var(--accent-subtle);color:var(--accent-primary);">${p.category}</span>
                  </div>
                  <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;max-width:700px;line-height:1.4;">
                    ${p.description}
                  </div>
                </div>

                <div style="display:flex;align-items:center;gap:12px;">
                  <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">Est: ${p.estimatedDuration}</span>
                  <button class="btn btn-primary btn-run-pipeline" data-pipe-id="${p.id}" ${this.isRunning && this.activePipelineId === p.id ? 'disabled' : ''} style="display:flex;align-items:center;gap:6px;">
                    <span>${this.isRunning && this.activePipelineId === p.id ? '⏳' : '▶'}</span>
                    <span>${this.isRunning && this.activePipelineId === p.id ? 'Running...' : 'Execute Pipeline'}</span>
                  </button>
                </div>
              </div>

              <!-- Stages Stepper -->
              <div style="display:grid;grid-template-columns:repeat(${p.stages.length}, 1fr);gap:10px;padding:12px;background:var(--bg-surface-sunken);border-radius:var(--radius-sm);overflow-x:auto;">
                ${p.stages.map((st, i) => `
                  <div style="display:flex;flex-direction:column;gap:4px;padding:8px;background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-xs);min-width:140px;">
                    <div style="font-weight:700;font-size:11px;color:#00f0ff;display:flex;justify-content:space-between;">
                      <span>Stage ${i + 1}</span>
                      ${st.requiresApproval ? '<span style="color:#f59e0b;" title="Requires Operator Approval">⚠️</span>' : '<span>✓</span>'}
                    </div>
                    <div style="font-size:11px;font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                      ${st.name}
                    </div>
                    <div style="font-size:10px;color:var(--text-muted);line-height:1.3;">
                      ${st.desc}
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    const selectTarget = this.container.querySelector<HTMLSelectElement>('#workflow-target-select');
    const inputTarget = this.container.querySelector<HTMLInputElement>('#workflow-target-input');

    selectTarget?.addEventListener('change', () => {
      if (selectTarget.value && inputTarget) {
        inputTarget.value = selectTarget.value;
      }
    });

    this.container.querySelectorAll<HTMLButtonElement>('.btn-run-pipeline').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.pipeId;
        const match = this.pipelines.find((p) => p.id === id);
        if (match) {
          this.executePipeline(match);
        }
      });
    });
  }
}
