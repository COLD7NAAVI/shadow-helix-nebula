/**
 * Shadow : Helix Nebula (SHN) — Execution Supervisor & Worker Sandbox View
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Execution, Capability, Scope } from '../contracts.js';

export function renderExecutionsView(
  container: HTMLElement,
  deps: { api: ApiClient; workspaceStore: WorkspaceStore; notify: NotificationStore }
): void {
  let executions: Execution[] = [];
  let capabilities: Capability[] = [];
  let scopes: Scope[] = [];
  let isLoading = true;
  let showLaunchModal = false;
  let inspectedExecution: Execution | null = null;
  let isDispatching = false;

  const currentWks = deps.workspaceStore.getState().activeWorkspace;

  async function loadData() {
    if (!currentWks) return;
    isLoading = true;
    render();

    try {
      const [eList, cList, sList] = await Promise.all([
        deps.api.listExecutions(currentWks.id).catch(() => []),
        deps.api.listCapabilities().catch(() => []),
        deps.api.listScopes(currentWks.id).catch(() => []),
      ]);
      executions = eList;
      capabilities = cList;
      scopes = sList;
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to load execution data');
    } finally {
      isLoading = false;
      render();
    }
  }

  function render() {
    container.innerHTML = `
      <div class="content-viewport">
        <!-- Page Header -->
        <div class="page-header">
          <div class="page-title-group">
            <h2>Execution Supervisor & Sandboxed Workers</h2>
            <div class="page-subtitle">
              Supervised worker execution with scratch isolation, scope authorization, and sealed evidence capture.
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-refresh-execs" class="btn btn-secondary">↻ Refresh Runs</button>
            <button id="btn-open-launch-modal" class="btn btn-primary">
              <span>⚡</span> Launch Capability
            </button>
          </div>
        </div>

        <!-- Executions Table -->
        <div class="card" style="padding:0;overflow:hidden;">
          <div class="data-table-container" style="border:none;">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Action / Capability</th>
                  <th>Target Endpoint</th>
                  <th>Execution State</th>
                  <th>Dispatched At</th>
                  <th>Evidence SHA-256</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${executions.length > 0 ? executions.map((e) => {
                  const isSuccess = e.state === 'COMPLETED' || e.state === 'SUCCEEDED';
                  const isRunning = e.state === 'RUNNING';
                  const isFailed = e.state === 'FAILED' || e.state === 'REJECTED' || e.state === 'TIMED_OUT';
                  const statusClass = isSuccess ? 'badge-active' : isRunning ? 'badge-info' : isFailed ? 'badge-critical' : 'badge-low';
                  const sha = e.rawOutputSha256 || e.raw_output_sha256;

                  return `
                    <tr>
                      <td>
                        <strong style="color:var(--text-primary);">${e.action}</strong>
                        <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${e.capabilityUri || e.capability_uri || 'cap:standard'}</div>
                      </td>
                      <td style="font-family:var(--font-mono);font-size:13px;color:var(--accent-primary);">
                        ${e.target}
                      </td>
                      <td>
                        <span class="badge ${statusClass}">
                          ${isRunning ? '<span class="pulse-dot"></span>' : ''}
                          ${e.state}
                        </span>
                      </td>
                      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-secondary);">
                        ${new Date(e.createdAt || e.created_at || '').toLocaleTimeString()}
                      </td>
                      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">
                        ${sha ? sha.substring(0, 16) + '...' : 'In Progress'}
                      </td>
                      <td>
                        <button class="btn btn-secondary btn-sm btn-inspect-exec" data-exec-id="${e.id}">
                          Inspect Output
                        </button>
                      </td>
                    </tr>
                  `;
                }).join('') : `
                  <tr>
                    <td colspan="6" style="text-align:center;padding:36px;color:var(--text-muted);">
                      ${isLoading ? 'Loading execution logs...' : 'No capability executions recorded for this workspace.'}
                    </td>
                  </tr>
                `}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Modal: Launch Capability Execution -->
      <div id="modal-launch-exec" class="modal-overlay ${showLaunchModal ? 'active' : ''}">
        <div class="modal-dialog">
          <div class="modal-header">
            <h3>Dispatch Security Capability</h3>
            <button class="btn btn-ghost btn-sm btn-close-modal">✕</button>
          </div>
          <form id="form-launch-exec">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label" for="launch-cap-select">Capability Tool</label>
                <select class="form-select" id="launch-cap-select" required>
                  ${capabilities.length > 0 ? capabilities.map((c) => `
                    <option value="${c.id || c.uri}">${c.displayName || c.name} (${c.id || c.uri})</option>
                  `).join('') : `
                    <option value="" disabled selected>No capabilities registered in catalog</option>
                  `}
                </select>
              </div>

              <div class="form-group">
                <label class="form-label" for="launch-target">Target IP / Domain / URL</label>
                <input class="form-input" id="launch-target" type="text" placeholder="192.168.1.10 or https://api.internal.network" required />
              </div>

              <div class="form-group">
                <label class="form-label" for="launch-port">Target Port (Optional)</label>
                <input class="form-input" id="launch-port" type="number" placeholder="e.g. 443" min="1" max="65535" />
              </div>

              <div class="form-group">
                <label class="form-label" for="launch-scope-select">Authorized Scope Boundary</label>
                <select class="form-select" id="launch-scope-select">
                  ${scopes.map((s) => `
                    <option value="${s.id}">${s.name} (${s.inclusions?.length || 0} inclusions)</option>
                  `).join('') || '<option value="">Default Workspace Scope</option>'}
                </select>
              </div>

              <div style="padding:10px 12px;border-radius:var(--radius-sm);background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.25);font-size:11px;color:var(--text-secondary);">
                <span>🛡 Zero-trust gatekeeper evaluates scope containment prior to process spawn. Cloud metadata and loopback destinations are permanently blocked.</span>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary btn-close-modal">Cancel</button>
              <button type="submit" class="btn btn-primary" ${isDispatching ? 'disabled' : ''}>
                ${isDispatching ? 'Dispatching...' : 'Dispatch Execution'}
              </button>
            </div>
          </form>
        </div>
      </div>

      <!-- Drawer: Execution Output Inspection -->
      <div id="drawer-exec-overlay" class="drawer-overlay ${inspectedExecution ? 'active' : ''}"></div>
      <div id="drawer-exec-panel" class="drawer-panel ${inspectedExecution ? 'active' : ''}">
        ${inspectedExecution ? `
          <div class="modal-header">
            <div>
              <h3>Execution Telemetry & Output</h3>
              <code style="font-size:11px;color:var(--accent-primary);">${inspectedExecution.id}</code>
            </div>
            <button class="btn btn-ghost btn-sm btn-close-drawer">✕</button>
          </div>
          <div style="flex:1;overflow-y:auto;padding:24px;display:flex;flex-direction:column;gap:18px;">
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:12px;">Execution Metadata</h4>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px;">
                <div><span style="color:var(--text-muted);">Action:</span> <strong>${inspectedExecution.action}</strong></div>
                <div><span style="color:var(--text-muted);">Target:</span> <code style="color:var(--accent-primary);">${inspectedExecution.target}</code></div>
                <div><span style="color:var(--text-muted);">State:</span> <strong style="color:var(--status-active);">${inspectedExecution.state}</strong></div>
                <div><span style="color:var(--text-muted);">Started:</span> <span>${inspectedExecution.startedAt || inspectedExecution.started_at ? new Date(inspectedExecution.startedAt || inspectedExecution.started_at!).toLocaleTimeString() : 'N/A'}</span></div>
              </div>
            </div>

            <!-- Terminal Output -->
            <div class="card" style="padding:16px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);">Worker Terminal Output (stdout)</h4>
                <span class="badge badge-active" style="font-size:10px;">Sealed Sandbox</span>
              </div>
              <div class="terminal-view">${inspectedExecution.stdoutSummary || inspectedExecution.stdout_summary || '[No stdout output captured or process completed silently]'}</div>
            </div>

            <!-- Evidence Block -->
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px;">Evidence Hash Verification (INV-05)</h4>
              <p style="font-size:11px;color:var(--text-secondary);margin-bottom:8px;">Cryptographic digest of raw output stream:</p>
              <code style="word-break:break-all;font-size:11px;color:var(--accent-primary);display:block;padding:8px;background:var(--bg-terminal);border-radius:var(--radius-xs);">
                ${inspectedExecution.rawOutputSha256 || inspectedExecution.raw_output_sha256 || 'Hash calculation pending completion'}
              </code>
            </div>
          </div>
        ` : ''}
      </div>
    `;

    // Event Bindings
    container.querySelector('#btn-open-launch-modal')?.addEventListener('click', () => {
      showLaunchModal = true;
      render();
    });

    container.querySelector('#btn-refresh-execs')?.addEventListener('click', () => {
      loadData();
    });

    container.querySelectorAll('.btn-close-modal').forEach((btn) => {
      btn.addEventListener('click', () => {
        showLaunchModal = false;
        render();
      });
    });

    container.querySelectorAll('.btn-inspect-exec').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const id = (e.currentTarget as HTMLElement).getAttribute('data-exec-id');
        inspectedExecution = executions.find((ex) => ex.id === id) || null;
        render();
      });
    });

    container.querySelector('.btn-close-drawer')?.addEventListener('click', () => {
      inspectedExecution = null;
      render();
    });
    container.querySelector('#drawer-exec-overlay')?.addEventListener('click', () => {
      inspectedExecution = null;
      render();
    });

    // Handle Launch Submit
    container.querySelector('#form-launch-exec')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!currentWks) return;

      const capId = (container.querySelector('#launch-cap-select') as HTMLSelectElement).value;
      const target = (container.querySelector('#launch-target') as HTMLInputElement).value.trim();
      const portVal = (container.querySelector('#launch-port') as HTMLInputElement).value;
      const scopeId = (container.querySelector('#launch-scope-select') as HTMLSelectElement).value || undefined;

      isDispatching = true;
      render();

      try {
        const payload: {
          capabilityId: string;
          target: string;
          port?: number | undefined;
          scopeId?: string | undefined;
        } = {
          capabilityId: capId,
          target,
        };
        if (portVal) payload.port = parseInt(portVal, 10);
        if (scopeId) payload.scopeId = scopeId;

        await deps.api.executeCapability(currentWks.id, payload);
        deps.notify.success(`Capability dispatched against ${target}`, 'Execution Queued');
        showLaunchModal = false;
        isDispatching = false;
        loadData();
      } catch (err: any) {
        isDispatching = false;
        deps.notify.error(err.message || 'Execution authorization failed');
        render();
      }
    });
  }

  loadData();
}
