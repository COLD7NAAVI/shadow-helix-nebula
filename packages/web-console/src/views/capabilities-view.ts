/**
 * Shadow : Helix Nebula (SHN) — Capability Registry & Tool Adapters View
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Capability } from '../contracts.js';

export function renderCapabilitiesView(
  container: HTMLElement,
  deps: { api: ApiClient; workspaceStore: WorkspaceStore; notify: NotificationStore }
): void {
  let capabilities: Capability[] = [];
  let isLoading = true;

  const currentWks = deps.workspaceStore.getState().activeWorkspace;

  async function loadData() {
    isLoading = true;
    render();

    try {
      capabilities = await deps.api.listCapabilities();
    } catch (err: any) {
      capabilities = [];
      deps.notify.error(err.message || 'Failed to query capability registry');
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
            <h2>Capability Registry & Tool Discovery</h2>
            <div class="page-subtitle">
              Abstract capability manifests, containerized tool adapters, and sandboxed execution specs ${currentWks ? `for workspace: ${currentWks.name}` : ''}.
            </div>
          </div>
          <div>
            <button id="btn-refresh-caps" class="btn btn-secondary" ${isLoading ? 'disabled' : ''}>
              ${isLoading ? 'Refreshing...' : '↻ Refresh Catalog'}
            </button>
          </div>
        </div>

        <!-- Capability Cards Grid -->
        ${capabilities.length === 0 ? `
          <div class="empty-state">
            <div class="empty-state-icon">⚡</div>
            <div class="empty-state-title">No Capabilities Discovered</div>
            <div class="empty-state-description">
              No capability manifests are currently registered in this workspace catalog. Ensure tool adapters are initialized in the backend Capability Registry.
            </div>
          </div>
        ` : `
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(360px, 1fr));gap:20px;">
            ${capabilities.map((cap: any) => {
              const capName = cap.displayName || cap.name;
              const capUri = cap.uri || cap.id;
              const capState = cap.state || cap.lifecycleState || 'ACTIVE';
              const schema = cap.parametersSchema || cap.argumentSchema;
              const isActive = capState === 'ACTIVE';
              return `
              <div class="card" style="display:flex;flex-direction:column;justify-content:space-between;gap:16px;">
                <div>
                  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:8px;">
                    <div>
                      <h3 style="font-size:16px;">${capName}</h3>
                      <code style="font-size:11px;color:var(--accent-primary);">${capUri}</code>
                    </div>
                    <span class="badge ${isActive ? 'badge-active' : 'badge-low'}">${capState}</span>
                  </div>

                  <p style="font-size:13px;line-height:1.6;margin-top:8px;">
                    ${cap.description}
                  </p>

                  <!-- Tags / Metadata -->
                  <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;">
                    <span class="badge badge-info">Category: ${cap.category}</span>
                    <span class="badge" style="background:rgba(255,255,255,0.06);">v${cap.version}</span>
                    <span class="badge ${isActive ? 'badge-active' : 'badge-low'}">Sandbox: Process / Scratch Isolation</span>
                  </div>

                  <!-- Parameters Schema preview -->
                  ${schema ? `
                    <div style="margin-top:16px;padding:12px;border-radius:var(--radius-sm);background:rgba(0,0,0,0.25);border:1px solid var(--border-subtle);font-size:11px;">
                      <div style="font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Parameters Schema</div>
                      <pre style="color:var(--text-secondary);">${JSON.stringify(schema, null, 2)}</pre>
                    </div>
                  ` : ''}
                </div>

                <div style="border-top:1px solid var(--border-subtle);padding-top:14px;display:flex;align-items:center;justify-content:space-between;">
                  <span style="font-size:11px;color:var(--text-muted);">
                    ${isActive ? 'Scope Authorization Required' : 'Integration Inactive'}
                  </span>
                  ${isActive ? `
                    <a href="#executions?cap=${encodeURIComponent(capUri)}" class="btn btn-primary btn-sm">
                      <span>⚡</span> Dispatch Capability
                    </a>
                  ` : `
                    <button class="btn btn-secondary btn-sm" disabled>Unavailable</button>
                  `}
                </div>
              </div>
            `;
            }).join('')}
          </div>
        `}
      </div>
    `;

    container.querySelector('#btn-refresh-caps')?.addEventListener('click', () => {
      loadData();
    });
  }

  loadData();
}
