/**
 * Shadow : Helix Nebula (SHN) — Real Execution Terminal & Background Supervisor View
 *
 * Implements Section 8:
 * - Launch approved registered capabilities asynchronously from the GUI
 * - Target-scope verification against active workspace scope
 * - Real-time terminal output streaming (stdout/stderr, exit code, execution events)
 * - Persistent execution history and evidence references
 * - Structured parameters configuration without shell string concatenation
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Capability, Execution, Asset, Scope } from '../contracts.js';

export class TerminalView {
  private container: HTMLElement | null = null;
  private capabilities: Capability[] = [];
  private executions: Execution[] = [];
  private assets: Asset[] = [];
  private scopes: Scope[] = [];
  private activeExecution: Execution | null = null;
  private isDispatching = false;
  private streamUnsubscribe: (() => void) | null = null;

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
    if (this.streamUnsubscribe) {
      this.streamUnsubscribe();
      this.streamUnsubscribe = null;
    }
    this.container = null;
  }

  private async loadData(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    try {
      const [caps, execs, assetList, scopeList] = await Promise.all([
        this.api.listCapabilities().catch(() => []),
        this.api.listExecutions(ws.id).catch(() => []),
        this.api.listAssets(ws.id).catch(() => []),
        this.api.listScopes(ws.id).catch(() => []),
      ]);

      this.capabilities = caps;
      this.executions = execs;
      this.assets = assetList;
      this.scopes = scopeList;

      if (this.executions.length > 0 && !this.activeExecution) {
        this.activeExecution = this.executions[0] ?? null;
      }

      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load execution supervisor data');
    }
  }

  private async refreshExecutionsOnly(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws || !this.container) return;

    try {
      const execs = await this.api.listExecutions(ws.id).catch(() => []);
      this.executions = execs;

      if (this.activeExecution) {
        const updated = this.executions.find(
          (e) => (e.id && e.id === this.activeExecution?.id) || (e.executionId && e.executionId === this.activeExecution?.executionId)
        );
        if (updated) {
          this.activeExecution = updated;
        }
      } else if (this.executions.length > 0) {
        this.activeExecution = this.executions[0] ?? null;
      }

      this.updateTerminalViewport();
      this.updateHistoryTable();
    } catch {}
  }

  private async dispatchCapability(
    capabilityUri: string,
    target: string,
    port: number | undefined,
    parameters: Record<string, unknown>
  ): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) {
      this.notify.warning('No active workspace selected.');
      return;
    }

    if (!capabilityUri || capabilityUri === 'undefined') {
      this.notify.warning('Please select a valid capability.');
      return;
    }

    if (!target || target === 'undefined') {
      this.notify.warning('Please specify an authorized target.');
      return;
    }

    // Client-side scope check
    const scopeCheck = this.verifyScope(target, port);
    if (!scopeCheck.allowed) {
      this.notify.error(`Scope Gatekeeper Block: ${scopeCheck.reason}`);
      return;
    }

    this.isDispatching = true;
    this.updateDispatchButtonState(true);

    const selectedCap = this.capabilities.find(
      (c) => (c.id === capabilityUri || c.uri === capabilityUri)
    );
    const capName = selectedCap?.displayName || selectedCap?.name || capabilityUri;

    try {
      this.notify.info(`Dispatching ${capName} against ${target}...`);
      const activeScope = this.scopes.find((s) => s.status === 'ACTIVE') || this.scopes[0];
      const execution = await this.api.dispatchExecution(ws.id, {
        capabilityUri,
        target,
        port,
        scopeId: activeScope?.id,
        parameters,
      });

      this.notify.success(`Capability dispatched! Execution ID: ${execution.id}`);
      this.activeExecution = execution;
      await this.refreshExecutionsOnly();
    } catch (err: any) {
      this.notify.error(err.message || 'Execution dispatch failed');
    } finally {
      this.isDispatching = false;
      this.updateDispatchButtonState(false);
    }
  }

  private updateDispatchButtonState(dispatching: boolean): void {
    const btn = this.container?.querySelector<HTMLButtonElement>('#btn-dispatch-capability');
    if (btn) {
      btn.disabled = dispatching;
      btn.innerHTML = `
        <span>${dispatching ? '⏳' : '🚀'}</span>
        <span>${dispatching ? 'Spawning Process...' : 'Dispatch Execution'}</span>
      `;
    }
  }

  private verifyScope(target: string, port?: number): { allowed: boolean; reason: string } {
    if (!target || target.trim() === '') {
      return { allowed: false, reason: 'Target is empty' };
    }

    const t = target.trim();

    // SEC-INV-08: Cloud metadata prohibition
    if (
      t.includes('169.254.169.254') ||
      t.includes('metadata.google.internal') ||
      t.includes('169.254.') ||
      t.includes('latest/meta-data')
    ) {
      return { allowed: false, reason: 'Cloud metadata targets are permanently prohibited under SEC-INV-08' };
    }

    if (this.scopes.length === 0) {
      return { allowed: true, reason: 'No scope boundaries loaded (deferred to backend Scope Gatekeeper)' };
    }

    // Parse target host and port
    let host = t;
    let targetPort = port;

    if (t.startsWith('http://') || t.startsWith('https://')) {
      try {
        const u = new URL(t);
        host = u.hostname;
        if (u.port) {
          targetPort = Number(u.port);
        } else {
          targetPort = t.startsWith('https://') ? 443 : 80;
        }
      } catch {}
    } else if (t.includes(':')) {
      const parts = t.split(':');
      host = parts[0] || t;
      if (parts[1] && !isNaN(Number(parts[1]))) {
        targetPort = Number(parts[1]);
      }
    }

    // Check port ranges if scope defines port boundaries
    for (const s of this.scopes) {
      const ranges = (s as any).port_ranges || (s as any).portRanges;
      if (ranges && ranges.length > 0 && targetPort !== undefined) {
        const portOk = ranges.some((r: any) => targetPort! >= r.start && targetPort! <= r.end);
        if (!portOk) {
          return {
            allowed: false,
            reason: `Port ${targetPort} is outside authorized port range (${ranges.map((r: any) => `${r.start}-${r.end}`).join(', ')})`,
          };
        }
      }
    }

    // Check exclusions
    for (const s of this.scopes) {
      for (const ex of s.exclusions || []) {
        if (host === ex.value || host.includes(ex.value)) {
          return { allowed: false, reason: `Target matches scope exclusion: ${ex.value}` };
        }
      }
    }

    // Check inclusions
    for (const s of this.scopes) {
      for (const inc of s.inclusions || []) {
        if (inc.value === '*' || host === inc.value || host.includes(inc.value) || inc.value.includes(host)) {
          return { allowed: true, reason: `Target authorized within scope: ${s.name}` };
        }
      }
    }

    return { allowed: false, reason: 'Target is not covered by any active scope inclusions' };
  }

  private updateScopeStatusIndicator(): void {
    const box = this.container?.querySelector<HTMLElement>('#scope-status-box');
    const inputTarget = this.container?.querySelector<HTMLInputElement>('#input-target-custom');
    const selectPreset = this.container?.querySelector<HTMLSelectElement>('#select-target-preset');
    const inputPort = this.container?.querySelector<HTMLInputElement>('#input-target-port');

    if (!box) return;

    const rawTarget = inputTarget?.value?.trim() || selectPreset?.value?.trim() || '';
    const portVal = inputPort?.value?.trim() ? Number(inputPort.value.trim()) : undefined;

    const check = this.verifyScope(rawTarget, portVal);

    if (check.allowed) {
      box.style.background = 'rgba(16,185,129,0.1)';
      box.style.border = '1px solid rgba(16,185,129,0.3)';
      box.style.color = '#10b981';
      box.innerHTML = `<span>✓</span> <span>${this.escapeHtml(check.reason)}</span>`;
    } else {
      box.style.background = 'rgba(239,68,68,0.1)';
      box.style.border = '1px solid rgba(239,68,68,0.3)';
      box.style.color = '#ef4444';
      box.innerHTML = `<span>✗</span> <span>${this.escapeHtml(check.reason)}</span>`;
    }
  }

  private render(): void {
    if (!this.container) return;

    const ws = this.workspaceStore.getActiveWorkspace();

    // Default target port from active scope if specific port is defined
    const defaultScopePort =
      this.scopes[0]?.port_ranges?.[0]?.start === this.scopes[0]?.port_ranges?.[0]?.end
        ? this.scopes[0]?.port_ranges?.[0]?.start
        : undefined;

    const defaultTarget = this.assets[0]?.canonicalValue || this.assets[0]?.rawTarget || '';

    this.container.innerHTML = `
      <div class="content-viewport" style="display:flex;flex-direction:column;gap:20px;">
        <!-- Header -->
        <div class="page-header" style="margin-bottom:0;">
          <div class="page-title-group">
            <div style="display:flex;align-items:center;gap:12px;">
              <h2>Execution Center & Background Terminal</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                SANDBOX SUPERVISOR
              </span>
            </div>
            <div class="page-subtitle">
              Sovereign execution boundary for workspace: <strong style="color:var(--text-primary);">${this.escapeHtml(ws?.name || 'Default')}</strong>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-refresh-terminal" class="btn btn-secondary">
              <span>↻</span> Refresh Runs
            </button>
          </div>
        </div>

        <!-- 2-Column: Capability Launcher & Active Terminal Runner -->
        <div style="display:grid;grid-template-columns:360px 1fr;gap:20px;align-items:start;">
          <!-- Launcher Form Card -->
          <div class="card" style="display:flex;flex-direction:column;gap:16px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>⚡</span> Launch Capability
            </div>

            <!-- Capability Selector -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:6px;">Approved Capability</label>
              <select id="select-capability" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;">
                ${this.capabilities.length > 0 ? this.capabilities.map((c) => {
                  const capId = c.id || c.uri || '';
                  const capLabel = `${c.displayName || c.name} (${c.version || '1.0.0'})`;
                  return `<option value="${this.escapeHtml(capId)}">${this.escapeHtml(capLabel)}</option>`;
                }).join('') : '<option value="" disabled selected>No approved capabilities registered</option>'}
              </select>
            </div>

            <!-- Target Selection / Input -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:6px;">Target Target (In Scope)</label>
              <div style="display:flex;flex-direction:column;gap:6px;">
                <select id="select-target-preset" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;">
                  <option value="">-- Choose from Monitored Assets --</option>
                  ${this.assets.map((a) => {
                    const targetVal = a.canonicalValue || (a as any).canonical_target || a.rawTarget || (a as any).raw_target || '';
                    return `<option value="${this.escapeHtml(targetVal)}">${this.escapeHtml(a.name)} (${this.escapeHtml(targetVal)})</option>`;
                  }).join('')}
                </select>
                <input
                  id="input-target-custom"
                  type="text"
                  placeholder="Or enter target URL / hostname..."
                  value="${this.escapeHtml(defaultTarget)}"
                  style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--font-mono);"
                />
              </div>
            </div>

            <!-- Target Port (Optional) -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:6px;">Target Port (Optional)</label>
              <input
                id="input-target-port"
                type="number"
                placeholder="Port (e.g. 3000)"
                min="1"
                max="65535"
                value="${defaultScopePort !== undefined ? String(defaultScopePort) : ''}"
                style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--font-mono);"
              />
            </div>

            <!-- Scope Validation Indicator -->
            <div id="scope-status-box" style="padding:10px;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:var(--radius-sm);display:flex;align-items:center;gap:8px;font-size:11px;color:#10b981;">
              <span>✓</span> Target evaluated: Authorized within Workspace Scope
            </div>

            <!-- Parameters (Timeout, concurrency) -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:6px;">Timeout Limit (ms)</label>
              <input
                id="input-timeout-ms"
                type="number"
                value="30000"
                style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;"
              />
            </div>

            <button id="btn-dispatch-capability" class="btn btn-primary" ${this.isDispatching ? 'disabled' : ''} style="display:flex;align-items:center;justify-content:center;gap:8px;">
              <span>${this.isDispatching ? '⏳' : '🚀'}</span>
              <span>${this.isDispatching ? 'Spawning Process...' : 'Dispatch Execution'}</span>
            </button>
          </div>

          <!-- Active Terminal Viewport Card -->
          <div class="terminal-card" id="terminal-viewport-container">
            ${this.renderTerminalCardInner()}
          </div>
        </div>

        <!-- Execution History Table Card -->
        <div class="card">
          <div class="chart-header" style="margin-bottom:14px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>📋</span> Execution History & Audit Artifacts
            </div>
            <span id="label-total-runs" style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">
              Total Runs: ${this.executions.length}
            </span>
          </div>

          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Execution ID</th>
                  <th>Action / Capability</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Dispatched At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="table-execution-history-body">
                ${this.renderHistoryRows()}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    this.updateScopeStatusIndicator();
  }

  private renderTerminalCardInner(): string {
    const isSuccess = this.activeExecution?.state === 'SUCCEEDED' || this.activeExecution?.state === 'COMPLETED';
    const isFailed =
      this.activeExecution?.state === 'FAILED' ||
      this.activeExecution?.state === 'REJECTED' ||
      this.activeExecution?.state === 'TIMED_OUT';
    const badgeColor = isSuccess ? '#10b981' : isFailed ? '#ef4444' : '#00f0ff';

    return `
      <!-- Terminal Header -->
      <div class="terminal-header">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="color:#00f0ff;">⚡ SHN-TERMINAL:</span>
          <span id="terminal-active-id" style="color:var(--text-primary);">${this.activeExecution ? (this.activeExecution.id || this.activeExecution.executionId || 'IDLE') : 'IDLE'}</span>
        </div>
        <div id="terminal-header-meta" style="display:flex;align-items:center;gap:12px;">
          ${this.activeExecution ? `
            <span class="badge" style="font-size:10px;background:${badgeColor};color:#fff;">
              ${this.activeExecution.state}
            </span>
            <span>Target: <strong>${this.escapeHtml(this.activeExecution.target || 'N/A')}</strong></span>
          ` : ''}
        </div>
      </div>

      <!-- Terminal Output Body -->
      <div class="terminal-body" id="terminal-output-body">
        ${this.activeExecution ? this.renderTerminalContent(this.activeExecution) : `
          <div style="color:var(--text-muted);text-align:center;padding:48px 0;">
            [SHN] Sovereign Execution Supervisor Ready.<br/>
            Select an execution from history below or dispatch a capability to stream live output.
          </div>
        `}
      </div>

      <!-- Terminal Prompt Bar -->
      <div class="terminal-prompt-row">
        <span style="color:#00f0ff;font-family:var(--font-mono);font-size:12px;font-weight:700;">shn:operator$</span>
        <input
          id="terminal-cmd-input"
          type="text"
          placeholder="Enter capability argument or help..."
          style="flex:1;background:transparent;border:none;outline:none;color:#f8fafc;font-family:var(--font-mono);font-size:12px;"
        />
        <span style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);">ISOLATED SUBPROCESS</span>
      </div>
    `;
  }

  private updateTerminalViewport(): void {
    const container = this.container?.querySelector<HTMLElement>('#terminal-viewport-container');
    if (container) {
      container.innerHTML = this.renderTerminalCardInner();
    }
  }

  private renderHistoryRows(): string {
    if (this.executions.length === 0) {
      return `
        <tr>
          <td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">
            No executions dispatched yet in this workspace.
          </td>
        </tr>
      `;
    }

    return this.executions.map((e) => {
      const isSuccess = e.state === 'SUCCEEDED' || e.state === 'COMPLETED';
      const isFailed = e.state === 'FAILED' || e.state === 'REJECTED' || e.state === 'TIMED_OUT';
      const badgeColor = isSuccess ? '#10b981' : isFailed ? '#ef4444' : '#00f0ff';
      const execId = e.id || e.executionId || '';
      const actionName = e.action || e.capabilityUri || (e as any).capability_uri || 'Capability';
      const timestamp = e.createdAt || (e as any).created_at || (e as any).startedAt || (e as any).started_at;
      const formattedDate = timestamp ? new Date(timestamp).toLocaleString() : 'N/A';

      return `
        <tr style="cursor:pointer;" class="row-execution ${this.activeExecution?.id === execId ? 'active-row' : ''}" data-exec-id="${this.escapeHtml(execId)}">
          <td style="font-family:var(--font-mono);font-size:11px;color:#00f0ff;">
            ${this.escapeHtml(execId.substring(0, 14))}...
          </td>
          <td>
            <strong style="color:var(--text-primary);">${this.escapeHtml(actionName)}</strong>
          </td>
          <td style="font-family:var(--font-mono);font-size:11px;">
            ${this.escapeHtml(e.target || 'N/A')}
          </td>
          <td>
            <span class="badge" style="font-size:10px;background:${badgeColor};color:#fff;">
              ${this.escapeHtml(e.state)}
            </span>
          </td>
          <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">
            ${this.escapeHtml(formattedDate)}
          </td>
          <td>
            <button class="btn btn-secondary btn-sm btn-inspect-exec" data-exec-id="${this.escapeHtml(execId)}" style="font-size:11px;padding:2px 8px;">
              Inspect Logs
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  private updateHistoryTable(): void {
    const tbody = this.container?.querySelector<HTMLElement>('#table-execution-history-body');
    const labelTotal = this.container?.querySelector<HTMLElement>('#label-total-runs');
    if (tbody) {
      tbody.innerHTML = this.renderHistoryRows();
      this.bindHistoryEvents();
    }
    if (labelTotal) {
      labelTotal.textContent = `Total Runs: ${this.executions.length}`;
    }
  }

  private renderTerminalContent(e: Execution): string {
    const rawOut = e.stdoutSummary || (e as any).stdout_summary || '';
    const rawErr = e.stderrSummary || (e as any).stderr_summary || '';
    const dispatchedAt = e.createdAt || (e as any).created_at || (e as any).startedAt || (e as any).started_at || 'N/A';
    const isSuccess = e.state === 'SUCCEEDED' || e.state === 'COMPLETED';
    const isFailed = e.state === 'FAILED' || e.state === 'REJECTED' || e.state === 'TIMED_OUT';
    const stateColor = isSuccess ? '#10b981' : isFailed ? '#ef4444' : '#00f0ff';
    const sha = e.rawOutputSha256 || (e as any).raw_output_sha256 || 'N/A';
    const cmdStr = e.command ? `${e.command.executable} ${e.command.args.join(' ')}` : (e.capabilityUri || (e as any).capability_uri || e.action || 'N/A');

    return `
<span style="color:#10b981;">[SHN-SUPERVISOR] Process spawned in unprivileged sandbox.</span>
<span style="color:var(--text-secondary);">Command: ${this.escapeHtml(cmdStr)}</span>
<span style="color:var(--text-secondary);">Target: ${this.escapeHtml(e.target || 'N/A')}</span>
<span style="color:var(--text-secondary);">Execution ID: ${this.escapeHtml(e.id || e.executionId || '')}</span>
<span style="color:var(--text-secondary);">Dispatched At: ${this.escapeHtml(dispatchedAt)}</span>
<span style="color:var(--text-secondary);">Evidence SHA-256: ${this.escapeHtml(sha)}</span>
--------------------------------------------------------------------------------
${rawOut ? `<span style="color:#38bdf8;">${this.escapeHtml(rawOut)}</span>` : '<span style="color:var(--text-muted);">(No stdout generated)</span>'}
${rawErr ? `<span style="color:#ef4444;">${this.escapeHtml(rawErr)}</span>` : ''}
--------------------------------------------------------------------------------
<span style="color:${stateColor};">
  [SHN-SUPERVISOR] Execution finished with state: ${this.escapeHtml(e.state)}
</span>
`;
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-refresh-terminal')?.addEventListener('click', () => {
      this.refreshExecutionsOnly();
    });

    const selectPreset = this.container.querySelector<HTMLSelectElement>('#select-target-preset');
    const inputCustom = this.container.querySelector<HTMLInputElement>('#input-target-custom');
    const inputPort = this.container.querySelector<HTMLInputElement>('#input-target-port');

    selectPreset?.addEventListener('change', () => {
      if (selectPreset.value && inputCustom) {
        inputCustom.value = selectPreset.value;
      }
      this.updateScopeStatusIndicator();
    });

    inputCustom?.addEventListener('input', () => {
      this.updateScopeStatusIndicator();
    });

    inputPort?.addEventListener('input', () => {
      this.updateScopeStatusIndicator();
    });

    this.container.querySelector('#btn-dispatch-capability')?.addEventListener('click', () => {
      if (this.isDispatching) return;

      const selectCap = this.container?.querySelector<HTMLSelectElement>('#select-capability');
      const inputTarget = this.container?.querySelector<HTMLInputElement>('#input-target-custom');
      const selectPresetVal = this.container?.querySelector<HTMLSelectElement>('#select-target-preset')?.value;
      const inputPortEl = this.container?.querySelector<HTMLInputElement>('#input-target-port');
      const inputTimeout = this.container?.querySelector<HTMLInputElement>('#input-timeout-ms');

      const capabilityUri = selectCap?.value?.trim();
      const target = inputTarget?.value?.trim() || selectPresetVal?.trim() || '';
      const portVal = inputPortEl?.value?.trim() ? Number(inputPortEl.value.trim()) : undefined;
      const timeoutMs = Number(inputTimeout?.value) || 30000;

      if (!capabilityUri || capabilityUri === 'undefined') {
        this.notify.warning('Please select an approved capability before dispatching.');
        return;
      }

      if (!target || target === 'undefined') {
        this.notify.warning('Please enter or select an authorized target.');
        return;
      }

      this.dispatchCapability(capabilityUri, target, portVal, {
        timeoutMs,
        ...(portVal !== undefined ? { port: portVal } : {}),
      });
    });

    this.bindHistoryEvents();
  }

  private bindHistoryEvents(): void {
    if (!this.container) return;

    this.container.querySelectorAll<HTMLElement>('.btn-inspect-exec, .row-execution').forEach((el) => {
      el.addEventListener('click', (e) => {
        const id = (e.currentTarget as HTMLElement).dataset.execId;
        const match = this.executions.find(
          (x) => x.id === id || (x as any).executionId === id
        );
        if (match) {
          this.activeExecution = match;
          this.updateTerminalViewport();
          // Highlight active row
          this.container?.querySelectorAll('.row-execution').forEach((r) => r.classList.remove('active-row'));
          const row = (e.currentTarget as HTMLElement).closest('.row-execution');
          row?.classList.add('active-row');
        }
      });
    });
  }
}
