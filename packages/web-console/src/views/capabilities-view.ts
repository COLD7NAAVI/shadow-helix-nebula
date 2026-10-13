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
      if (capabilities.length === 0) {
        // Fallback reference capabilities
        capabilities = [
          {
            id: 'cap-portscan-v1',
            uri: 'cap:network:port-scan:v1',
            name: 'Network Port Scanner',
            version: '1.0.0',
            category: 'RECONNAISSANCE',
            description: 'Hardened network probe utilizing TCP SYN scanning with automatic rate limiting and scope boundary enforcement.',
            state: 'ACTIVE',
            parametersSchema: {
              target: { type: 'string', description: 'Target IPv4 or FQDN' },
              ports: { type: 'string', description: 'Port range (e.g. 22-443)' },
              speed: { type: 'string', enum: ['T3', 'T4'], default: 'T3' },
            },
          },
          {
            id: 'cap-http-v1',
            uri: 'cap:http:service-discovery:v1',
            name: 'HTTP Service & Header Fingerprinting',
            version: '1.0.0',
            category: 'DISCOVERY',
            description: 'Analyzes HTTP/HTTPS endpoints, extracts security headers (HSTS, CSP, X-Frame-Options), and identifies server banners.',
            state: 'ACTIVE',
            parametersSchema: {
              target: { type: 'string', description: 'HTTP/HTTPS URL' },
              timeoutMs: { type: 'number', default: 5000 },
            },
          },
        ];
      }
    } catch {
      capabilities = [];
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
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(360px, 1fr));gap:20px;">
          ${capabilities.map((cap) => `
            <div class="card" style="display:flex;flex-direction:column;justify-content:space-between;gap:16px;">
              <div>
                <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:8px;">
                  <div>
                    <h3 style="font-size:16px;">${cap.name}</h3>
                    <code style="font-size:11px;color:var(--accent-primary);">${cap.uri}</code>
                  </div>
                  <span class="badge badge-active">${cap.state}</span>
                </div>

                <p style="font-size:13px;line-height:1.6;margin-top:8px;">
                  ${cap.description}
                </p>

                <!-- Tags / Metadata -->
                <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;">
                  <span class="badge badge-info">Category: ${cap.category}</span>
                  <span class="badge" style="background:rgba(255,255,255,0.06);">v${cap.version}</span>
                  <span class="badge badge-active">Sandbox: Process / Scratch Isolation</span>
                </div>

                <!-- Parameters Schema preview -->
                ${cap.parametersSchema ? `
                  <div style="margin-top:16px;padding:12px;border-radius:var(--radius-sm);background:rgba(0,0,0,0.25);border:1px solid var(--border-subtle);font-size:11px;">
                    <div style="font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Parameters Schema</div>
                    <pre style="color:var(--text-secondary);">${JSON.stringify(cap.parametersSchema, null, 2)}</pre>
                  </div>
                ` : ''}
              </div>

              <div style="border-top:1px solid var(--border-subtle);padding-top:14px;display:flex;align-items:center;justify-content:space-between;">
                <span style="font-size:11px;color:var(--text-muted);">
                  Scope Authorization Required
                </span>
                <a href="#executions?cap=${encodeURIComponent(cap.uri)}" class="btn btn-primary btn-sm">
                  <span>⚡</span> Dispatch Capability
                </a>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;

    container.querySelector('#btn-refresh-caps')?.addEventListener('click', () => {
      loadData();
    });
  }

  loadData();
}
