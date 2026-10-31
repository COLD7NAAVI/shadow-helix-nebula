/**
 * Shadow : Helix Nebula (SHN) — Reconnaissance & Discovery View
 *
 * Implements Section 4 & 12:
 * - Passive and active reconnaissance tools (DNS lookup, HTTP discovery)
 * - Scope-validated target discovery
 * - Seamless asset enrollment from discovered targets
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Asset } from '../contracts.js';

export class ReconView {
  private container: HTMLElement | null = null;
  private assets: Asset[] = [];
  private isScanning = false;
  private scanResults: Array<{ target: string; type: string; details: string; rawOutput?: string }> = [];

  constructor(
    private readonly api: ApiClient,
    private readonly workspaceStore: WorkspaceStore,
    private readonly notify: NotificationStore
  ) {}

  mount(target: HTMLElement): void {
    this.container = target;
    this.loadData();
  }

  unmount(): void {
    this.container = null;
  }

  private async loadData(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    try {
      this.assets = await this.api.listAssets(ws.id).catch(() => []);
      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load reconnaissance data');
    }
  }

  private async runRecon(target: string, capUri: string): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    this.isScanning = true;
    this.render();
    this.bindEvents();

    try {
      this.notify.info(`Running discovery capability against ${target}...`);
      const exec = await this.api.dispatchExecution(ws.id, {
        capabilityUri: capUri,
        target,
        parameters: { timeoutMs: 30000 },
      });

      this.scanResults.push({
        target,
        type: capUri.includes('dns') ? 'DNS RECON' : 'HTTP PROBE',
        details: `Execution ${exec.id.substring(0, 8)}: ${exec.state}`,
        rawOutput: exec.stdoutSummary || 'Execution completed.',
      });

      this.notify.success('Reconnaissance probe dispatched successfully');
    } catch (err: any) {
      this.notify.error(err.message || 'Reconnaissance dispatch failed');
    } finally {
      this.isScanning = false;
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
              <h2>Reconnaissance & Asset Discovery</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                PASSIVE & ACTIVE
              </span>
            </div>
            <div class="page-subtitle">
              Discover public infrastructure, DNS zones, and open web endpoints for workspace: <strong style="color:var(--text-primary);">${ws?.name || 'Default'}</strong>
            </div>
          </div>
        </div>

        <!-- 2-Column: Launch Recon Form on Left, Discovered Intelligence on Right -->
        <div style="display:grid;grid-template-columns:380px 1fr;gap:20px;align-items:start;">
          <!-- Launch Card -->
          <div class="card" style="display:flex;flex-direction:column;gap:16px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>🛰️</span> Launch Discovery Probe
            </div>

            <!-- Target Selection -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Target Hostname / Domain</label>
              ${this.assets.length > 0 ? `
                <select id="recon-asset-select" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;margin-bottom:6px;">
                  <option value="">-- Select Monitored Asset --</option>
                  ${this.assets.map(a => `
                    <option value="${a.canonicalValue || a.rawTarget}">${a.name} (${a.canonicalValue || a.rawTarget})</option>
                  `).join('')}
                </select>
              ` : ''}
              <input
                id="recon-target-input"
                type="text"
                placeholder="e.g. target.domain.local or 10.0.0.1"
                value="${this.assets[0]?.canonicalValue || this.assets[0]?.rawTarget || ''}"
                style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--font-mono);"
              />
            </div>

            <!-- Capability Type -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Discovery Method</label>
              <select id="recon-cap-select" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;">
                <option value="shn://capabilities/recon/dns-lookup">DNS Zone & Record Lookup (Authoritative A, MX, TXT)</option>
                <option value="shn://capabilities/web/http-discovery">HTTP Service & Header Fingerprinting</option>
                <option value="shn://capabilities/web/tls-inspect">TLS / SSL Certificate Information Discovery</option>
                <option value="shn://capabilities/network/port-scan">Network Port Scanner (Rate-Limited TCP Connect)</option>
              </select>
            </div>

            <button id="btn-run-recon" class="btn btn-primary" ${this.isScanning ? 'disabled' : ''} style="display:flex;align-items:center;justify-content:center;gap:8px;">
              <span>${this.isScanning ? '⏳' : '🚀'}</span>
              <span>${this.isScanning ? 'Probing Target...' : 'Execute Reconnaissance'}</span>
            </button>
          </div>

          <!-- Intelligence Findings Card -->
          <div class="card" style="display:flex;flex-direction:column;gap:14px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>📡</span> Discovered Reconnaissance Records (${this.scanResults.length})
            </div>

            <div style="display:flex;flex-direction:column;gap:10px;max-height:500px;overflow-y:auto;">
              ${this.scanResults.length > 0 ? this.scanResults.map((res) => `
                <div class="card" style="padding:12px;background:var(--bg-surface-sunken);border:1px solid var(--border-subtle);display:flex;flex-direction:column;gap:6px;">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <strong style="color:#00f0ff;font-family:var(--font-mono);font-size:13px;">${res.target}</strong>
                    <span class="badge" style="font-size:9px;background:var(--accent-subtle);color:var(--accent-primary);">${res.type}</span>
                  </div>
                  <div style="font-size:12px;color:var(--text-secondary);">${res.details}</div>
                  ${res.rawOutput ? `
                    <div style="padding:8px;background:var(--bg-terminal);border-radius:var(--radius-xs);font-family:var(--font-mono);font-size:11px;color:#38bdf8;white-space:pre-wrap;">${res.rawOutput}</div>
                  ` : ''}
                </div>
              `).join('') : `
                <div class="empty-state" style="padding:48px 16px;">
                  <div class="empty-state-icon">🌐</div>
                  <div class="empty-state-title">No Reconnaissance Executed</div>
                  <div class="empty-state-desc">Select an authorized target on the left and run a DNS or HTTP probe to populate discovery data.</div>
                </div>
              `}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-run-recon')?.addEventListener('click', () => {
      const target = this.container?.querySelector<HTMLInputElement>('#recon-target-input')?.value?.trim();
      const cap = this.container?.querySelector<HTMLSelectElement>('#recon-cap-select')?.value;
      if (target && cap) {
        this.runRecon(target, cap);
      }
    });
  }
}
