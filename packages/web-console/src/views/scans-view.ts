/**
 * Shadow : Helix Nebula (SHN) — Scans & Security Assessments View
 *
 * Implements Section 4 & 5:
 * - Scans and assessment task management
 * - Scope-gated scan dispatching
 * - Vulnerability discovery metrics
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Execution, Asset } from '../contracts.js';

export class ScansView {
  private container: HTMLElement | null = null;
  private executions: Execution[] = [];
  private assets: Asset[] = [];
  private isScanning = false;

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
      const [execs, assetList] = await Promise.all([
        this.api.listExecutions(ws.id).catch(() => []),
        this.api.listAssets(ws.id).catch(() => []),
      ]);

      this.executions = execs;
      this.assets = assetList;
      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load scans data');
    }
  }

  private async launchScan(scanType: string, target: string): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    this.isScanning = true;
    this.render();
    this.bindEvents();

    try {
      this.notify.info(`Dispatching assessment scan against ${target}...`);
      let capUri = 'shn://capabilities/web/http-baseline';
      if (scanType === 'TLS') capUri = 'shn://capabilities/web/tls-inspect';
      else if (scanType === 'DNS') capUri = 'shn://capabilities/recon/dns-lookup';

      const exec = await this.api.dispatchExecution(ws.id, {
        capabilityUri: capUri,
        target,
        parameters: { timeoutMs: 30000 },
      });

      this.notify.success(`Scan launched! Execution ID: ${exec.id}`);
      await this.loadData();
    } catch (err: any) {
      this.notify.error(err.message || 'Scan dispatch failed');
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
              <h2>Scans & Security Assessments</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                POLICY GOVERNED
              </span>
            </div>
            <div class="page-subtitle">
              Authorized vulnerability probes and compliance scans for workspace: <strong style="color:var(--text-primary);">${ws?.name || 'Default'}</strong>
            </div>
          </div>
          <button id="btn-refresh-scans" class="btn btn-secondary">
            <span>↻</span> Refresh
          </button>
        </div>

        <!-- 2-Column: Launch Scan & Scan History -->
        <div style="display:grid;grid-template-columns:380px 1fr;gap:20px;align-items:start;">
          <!-- Launch Card -->
          <div class="card" style="display:flex;flex-direction:column;gap:16px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>🛡️</span> New Assessment Scan
            </div>

            <!-- Target Selection -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Target Asset</label>
              <select id="scan-target-select" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;">
                ${this.assets.map((a) => `
                  <option value="${a.canonicalValue || a.rawTarget}">${a.name} (${a.canonicalValue || a.rawTarget})</option>
                `).join('')}
              </select>
            </div>

            <!-- Scan Type -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Assessment Profile</label>
              <select id="scan-profile-select" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;">
                <option value="HTTP">HTTP Security Baseline & Server Headers</option>
                <option value="TLS">TLS Cryptographic & Cipher Suite Audit</option>
                <option value="DNS">DNS Routing & Zone Assessment</option>
              </select>
            </div>

            <div style="padding:10px;background:rgba(0,240,255,0.06);border:1px solid rgba(0,240,255,0.2);border-radius:var(--radius-sm);font-size:11px;color:var(--text-secondary);">
              <span>🔒</span> All scans are validated by the Scope Gatekeeper prior to process execution. Out-of-scope targets fail closed.
            </div>

            <button id="btn-launch-scan" class="btn btn-primary" ${this.isScanning ? 'disabled' : ''} style="display:flex;align-items:center;justify-content:center;gap:8px;">
              <span>${this.isScanning ? '⏳' : '🚀'}</span>
              <span>${this.isScanning ? 'Dispatching...' : 'Start Assessment Scan'}</span>
            </button>
          </div>

          <!-- History / Results Card -->
          <div class="card" style="display:flex;flex-direction:column;gap:14px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>📊</span> Assessment Runs & Status (${this.executions.length})
            </div>

            <div class="data-table-container">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Scan Action</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Dispatched</th>
                  </tr>
                </thead>
                <tbody>
                  ${this.executions.length > 0 ? this.executions.map((e) => `
                    <tr>
                      <td><strong style="color:var(--text-primary);">${e.action || e.capabilityUri}</strong></td>
                      <td style="font-family:var(--font-mono);font-size:11px;">${e.target}</td>
                      <td>
                        <span class="badge" style="font-size:10px;background:${e.state === 'COMPLETED' ? '#10b981' : e.state === 'FAILED' ? '#ef4444' : '#00f0ff'};color:#fff;">
                          ${e.state}
                        </span>
                      </td>
                      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${new Date(e.createdAt || '').toLocaleTimeString()}</td>
                    </tr>
                  `).join('') : `
                    <tr>
                      <td colspan="4" style="text-align:center;padding:24px;color:var(--text-muted);">No scan executions recorded yet.</td>
                    </tr>
                  `}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-refresh-scans')?.addEventListener('click', () => {
      this.loadData();
    });

    this.container.querySelector('#btn-launch-scan')?.addEventListener('click', () => {
      const target = this.container?.querySelector<HTMLSelectElement>('#scan-target-select')?.value;
      const profile = this.container?.querySelector<HTMLSelectElement>('#scan-profile-select')?.value || 'HTTP';
      if (target) {
        this.launchScan(profile, target);
      }
    });
  }
}
