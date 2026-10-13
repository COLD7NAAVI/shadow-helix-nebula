/**
 * Shadow : Helix Nebula (SHN) — Workspaces & Scope Gatekeeper View
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Scope } from '../contracts.js';

export function renderWorkspacesView(
  container: HTMLElement,
  deps: { api: ApiClient; workspaceStore: WorkspaceStore; notify: NotificationStore }
): void {
  let scopes: Scope[] = [];
  let isLoading = true;
  let showCreateWorkspaceModal = false;
  let showCreateScopeModal = false;
  let verificationTarget = '';
  let verificationVerdict: { status: 'AUTHORIZED' | 'DENIED' | null; reason: string } | null = null;

  const currentWks = deps.workspaceStore.getState().activeWorkspace;

  async function loadData() {
    if (!currentWks) return;
    isLoading = true;
    render();

    try {
      scopes = await deps.api.listScopes(currentWks.id);
    } catch {
      scopes = [];
    } finally {
      isLoading = false;
      render();
    }
  }

  function evaluateTargetScope(target: string): { status: 'AUTHORIZED' | 'DENIED'; reason: string } {
    const trimmed = target.trim();
    if (!trimmed) return { status: 'DENIED', reason: 'Target cannot be empty' };

    // SEC-INV-08: Always block cloud metadata and loopback
    if (trimmed.includes('169.254.169.254') || trimmed.includes('metadata.google.internal')) {
      return { status: 'DENIED', reason: 'Blocked: Cloud Metadata Protection (SEC-INV-08)' };
    }
    if (trimmed.startsWith('127.') || trimmed.includes('localhost') || trimmed === '::1') {
      return { status: 'DENIED', reason: 'Blocked: Loopback Address Containment (SEC-INV-08)' };
    }

    if (scopes.length === 0) {
      return { status: 'DENIED', reason: 'No active scope boundaries defined for this workspace' };
    }

    // Check inclusions
    for (const scope of scopes) {
      for (const inc of scope.inclusions) {
        if (trimmed === inc.value || trimmed.startsWith(inc.value)) {
          return { status: 'AUTHORIZED', reason: `Authorized by Scope "${scope.name}" (Rule: ${inc.value})` };
        }
        if (inc.type === 'CIDR' && (trimmed.startsWith('10.') || trimmed.startsWith('192.168.'))) {
          return { status: 'AUTHORIZED', reason: `Authorized within CIDR block "${inc.value}" in Scope "${scope.name}"` };
        }
      }
    }

    return { status: 'DENIED', reason: 'Target does not match any authorized scope inclusion rules' };
  }

  function render() {
    const wksState = deps.workspaceStore.getState();
    const allWorkspaces = wksState.workspaces;

    container.innerHTML = `
      <div class="content-viewport">
        <!-- Page Header -->
        <div class="page-header">
          <div class="page-title-group">
            <h2>Workspaces & Scope Gatekeeper</h2>
            <div class="page-subtitle">
              Manage sovereign tenants, authorized boundary policies, and evaluate zero-trust scope containment${isLoading ? ' (loading...)' : ''}.
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-open-new-scope" class="btn btn-secondary">
              <span>+</span> Define Scope Boundary
            </button>
            <button id="btn-open-new-wks" class="btn btn-primary">
              <span>+</span> Create Workspace
            </button>
          </div>
        </div>

        <!-- Section 1: Workspaces List -->
        <div class="card">
          <h3 style="margin-bottom:14px;font-size:15px;">Available Sovereign Workspaces</h3>
          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Workspace Name</th>
                  <th>Workspace Slug</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${allWorkspaces.map((w) => `
                  <tr>
                    <td>
                      <strong style="color:var(--text-primary);">${w.name}</strong>
                      ${w.id === currentWks?.id ? '<span class="badge badge-active" style="margin-left:8px;">Active</span>' : ''}
                    </td>
                    <td style="font-family:var(--font-mono);font-size:12px;">${w.slug}</td>
                    <td><span class="badge badge-active">PROVISIONED</span></td>
                    <td>
                      ${w.id !== currentWks?.id ? `
                        <button class="btn btn-secondary btn-sm btn-switch-wks" data-wks-id="${w.id}">
                          Switch Context
                        </button>
                      ` : `
                        <span style="font-size:11px;color:var(--text-muted);">Current Context</span>
                      `}
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Section 2: Authorized Scopes for Active Workspace -->
        <div class="card">
          <div class="chart-header" style="margin-bottom:16px;">
            <div>
              <h3 style="font-size:15px;">Authorized Scope Policies (Active Workspace)</h3>
              <p style="font-size:12px;margin-top:2px;">Enforces strict boundary containment across all capability executions.</p>
            </div>
            <button id="btn-refresh-scopes" class="btn btn-ghost btn-sm">↻ Refresh</button>
          </div>

          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Scope Policy Name</th>
                  <th>Status</th>
                  <th>Target Inclusions</th>
                  <th>Exclusions</th>
                  <th>Port Ranges</th>
                  <th>Integrity Fingerprint</th>
                </tr>
              </thead>
              <tbody>
                ${scopes.length > 0 ? scopes.map((s) => `
                  <tr>
                    <td>
                      <strong style="color:var(--text-primary);">${s.name}</strong>
                      ${s.description ? `<div style="font-size:11px;color:var(--text-muted);">${s.description}</div>` : ''}
                    </td>
                    <td><span class="badge badge-active">${s.status}</span></td>
                    <td>
                      <div style="display:flex;flex-wrap:wrap;gap:4px;">
                        ${(s.inclusions || []).map((inc) => `
                          <code style="padding:2px 6px;background:var(--bg-input);border-radius:3px;font-size:11px;color:var(--accent-primary);">${inc.value}</code>
                        `).join('')}
                      </div>
                    </td>
                    <td>
                      <div style="display:flex;flex-wrap:wrap;gap:4px;">
                        ${(s.exclusions || []).map((exc) => `
                          <code style="padding:2px 6px;background:rgba(239,68,68,0.1);color:#ef4444;border-radius:3px;font-size:11px;">${exc.value}</code>
                        `).join('')}
                      </div>
                    </td>
                    <td style="font-family:var(--font-mono);font-size:11px;">
                      ${(s.port_ranges || []).map((p) => `${p.start}-${p.end}`).join(', ') || '1-65535'}
                    </td>
                    <td style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);">
                      ${s.scope_sha256 ? s.scope_sha256.substring(0, 16) + '...' : 'Verified'}
                    </td>
                  </tr>
                `).join('') : `
                  <tr>
                    <td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">
                      No scope boundaries configured for this workspace. Click "Define Scope Boundary" to add one.
                    </td>
                  </tr>
                `}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Section 3: Scope Verification Testing Tool -->
        <div class="card" style="border:1px solid var(--accent-border);background:var(--accent-subtle);">
          <h3 style="font-size:15px;color:var(--accent-primary);margin-bottom:6px;">Scope Containment Simulator</h3>
          <p style="font-size:12px;margin-bottom:16px;">
            Test any target IP, CIDR, or URL against active workspace scope rules prior to capability execution.
          </p>

          <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
            <input
              id="scope-test-input"
              class="form-input"
              type="text"
              placeholder="e.g. 10.240.0.1 or 169.254.169.254 or api.sovereign.internal"
              value="${verificationTarget}"
              style="flex:1;min-width:240px;"
            />
            <button id="btn-evaluate-scope" class="btn btn-primary">
              Evaluate Containment
            </button>
          </div>

          ${verificationVerdict ? `
            <div style="margin-top:16px;padding:14px;border-radius:var(--radius-md);background:${verificationVerdict.status === 'AUTHORIZED' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'};border:1px solid ${verificationVerdict.status === 'AUTHORIZED' ? 'rgba(16,185,129,0.35)' : 'rgba(239,68,68,0.35)'};display:flex;align-items:center;gap:12px;">
              <span class="badge ${verificationVerdict.status === 'AUTHORIZED' ? 'badge-active' : 'badge-critical'}">
                ${verificationVerdict.status}
              </span>
              <span style="font-size:13px;color:var(--text-primary);font-weight:500;">
                ${verificationVerdict.reason}
              </span>
            </div>
          ` : ''}
        </div>
      </div>

      <!-- Modal: Create Workspace -->
      <div id="modal-create-wks" class="modal-overlay ${showCreateWorkspaceModal ? 'active' : ''}">
        <div class="modal-dialog">
          <div class="modal-header">
            <h3>Provision New Workspace</h3>
            <button class="btn btn-ghost btn-sm btn-close-modal">✕</button>
          </div>
          <form id="form-create-wks">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label" for="new-wks-name">Workspace Name</label>
                <input class="form-input" id="new-wks-name" type="text" placeholder="e.g. Security Operations Center Beta" required />
              </div>
              <div class="form-group">
                <label class="form-label" for="new-wks-slug">Workspace Slug (Optional)</label>
                <input class="form-input" id="new-wks-slug" type="text" placeholder="e.g. soc-beta" />
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary btn-close-modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Provision Workspace</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Modal: Define Scope Boundary -->
      <div id="modal-create-scope" class="modal-overlay ${showCreateScopeModal ? 'active' : ''}">
        <div class="modal-dialog" style="max-width:650px;">
          <div class="modal-header">
            <h3>Define Scope Boundary Policy</h3>
            <button class="btn btn-ghost btn-sm btn-close-modal">✕</button>
          </div>
          <form id="form-create-scope">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label" for="scope-name">Policy Name</label>
                <input class="form-input" id="scope-name" type="text" placeholder="e.g. Production Perimeter Inclusions" required />
              </div>
              <div class="form-group">
                <label class="form-label" for="scope-desc">Description</label>
                <input class="form-input" id="scope-desc" type="text" placeholder="Authorized operational targets" />
              </div>
              <div class="form-group">
                <label class="form-label" for="scope-inclusions">Target Inclusions (Comma-separated IPs or CIDRs)</label>
                <input class="form-input" id="scope-inclusions" type="text" placeholder="10.240.0.0/24, 192.168.1.1, api.sovereign.internal" required />
              </div>
              <div class="form-group">
                <label class="form-label" for="scope-ports">Port Range (Start-End)</label>
                <input class="form-input" id="scope-ports" type="text" placeholder="1-65535" value="1-65535" />
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary btn-close-modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Save Scope Boundary</button>
            </div>
          </form>
        </div>
      </div>
    `;

    // Bindings
    container.querySelectorAll('.btn-switch-wks').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const id = (e.currentTarget as HTMLElement).getAttribute('data-wks-id');
        if (id) {
          deps.workspaceStore.setActiveWorkspace(id);
          deps.notify.success('Switched active workspace', 'Context Updated');
          loadData();
        }
      });
    });

    container.querySelector('#btn-open-new-wks')?.addEventListener('click', () => {
      showCreateWorkspaceModal = true;
      render();
    });

    container.querySelector('#btn-open-new-scope')?.addEventListener('click', () => {
      showCreateScopeModal = true;
      render();
    });

    container.querySelectorAll('.btn-close-modal').forEach((btn) => {
      btn.addEventListener('click', () => {
        showCreateWorkspaceModal = false;
        showCreateScopeModal = false;
        render();
      });
    });

    container.querySelector('#btn-refresh-scopes')?.addEventListener('click', () => {
      loadData();
    });

    // Handle Create Workspace Submit
    container.querySelector('#form-create-wks')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = (container.querySelector('#new-wks-name') as HTMLInputElement).value.trim();
      try {
        await deps.workspaceStore.createWorkspace(name);
        deps.notify.success(`Workspace "${name}" provisioned`, 'Success');
        showCreateWorkspaceModal = false;
        loadData();
      } catch (err: any) {
        deps.notify.error(err.message || 'Failed to create workspace');
      }
    });

    // Handle Create Scope Submit
    container.querySelector('#form-create-scope')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!currentWks) return;
      const name = (container.querySelector('#scope-name') as HTMLInputElement).value.trim();
      const desc = (container.querySelector('#scope-desc') as HTMLInputElement).value.trim();
      const incStr = (container.querySelector('#scope-inclusions') as HTMLInputElement).value.trim();
      const inclusions = incStr.split(',').map((s) => s.trim()).filter(Boolean).map((v) => ({
        type: v.includes('/') ? 'CIDR' : v.includes('://') ? 'URL' : v.includes('.') ? 'IPV4' : 'DOMAIN',
        value: v,
      }));

      try {
        await deps.api.createScope(currentWks.id, {
          name,
          description: desc,
          inclusions,
        });
        deps.notify.success(`Scope policy "${name}" created`, 'Scope Enforced');
        showCreateScopeModal = false;
        loadData();
      } catch (err: any) {
        deps.notify.error(err.message || 'Failed to define scope');
      }
    });

    // Scope verification button
    container.querySelector('#btn-evaluate-scope')?.addEventListener('click', () => {
      const input = (container.querySelector('#scope-test-input') as HTMLInputElement).value;
      verificationTarget = input;
      verificationVerdict = evaluateTargetScope(input);
      render();
    });
  }

  loadData();
}
