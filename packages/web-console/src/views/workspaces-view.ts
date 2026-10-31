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

  async function loadData() {
    const currentWks = deps.workspaceStore.getActiveWorkspace();
    if (!currentWks) {
      scopes = [];
      isLoading = false;
      render();
      return;
    }
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

  function ipv4ToInt(ip: string): number | null {
    const parts = ip.split('.').map(p => parseInt(p, 10));
    const p0 = parts[0];
    const p1 = parts[1];
    const p2 = parts[2];
    const p3 = parts[3];
    if (parts.length !== 4 || p0 === undefined || p1 === undefined || p2 === undefined || p3 === undefined) return null;
    if (isNaN(p0) || isNaN(p1) || isNaN(p2) || isNaN(p3) || p0 < 0 || p0 > 255 || p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255 || p3 < 0 || p3 > 255) return null;
    return ((p0 << 24) | (p1 << 16) | (p2 << 8) | p3) >>> 0;
  }

  function isIpInCidr(ip: string, cidr: string): boolean {
    const [netStr, maskStr] = cidr.split('/');
    if (!netStr || !maskStr) return false;
    const mask = parseInt(maskStr, 10);
    if (isNaN(mask) || mask < 0 || mask > 32) return false;
    const ipNum = ipv4ToInt(ip);
    const netNum = ipv4ToInt(netStr);
    if (ipNum === null || netNum === null) return false;
    if (mask === 0) return true;
    const bitmask = ((0xFFFFFFFF << (32 - mask)) >>> 0);
    return (ipNum & bitmask) === (netNum & bitmask);
  }

  function evaluateTargetScope(target: string): { status: 'AUTHORIZED' | 'DENIED'; reason: string } {
    const trimmed = target.trim();
    if (!trimmed) return { status: 'DENIED', reason: 'Target cannot be empty' };

    // SEC-INV-08: Always block cloud metadata
    if (trimmed.includes('169.254.169.254') || trimmed.includes('metadata.google.internal')) {
      return { status: 'DENIED', reason: 'Blocked: Cloud Metadata Protection (SEC-INV-08)' };
    }
    // Block loopback unless explicitly included in active scope
    if (trimmed.startsWith('127.') || trimmed.includes('localhost') || trimmed === '::1') {
      const isExplicitlyAuthorized = scopes.some((s) =>
        (s.inclusions || []).some((inc) => inc.value.includes('127.0.0.1') || inc.value.includes('localhost') || inc.value === '::1')
      );
      if (!isExplicitlyAuthorized) {
        return { status: 'DENIED', reason: 'Blocked: Loopback Address Containment (SEC-INV-08)' };
      }
    }

    if (scopes.length === 0) {
      return { status: 'DENIED', reason: 'No active scope boundaries defined for this workspace' };
    }

    // Check explicit exclusions first
    for (const scope of scopes) {
      if (scope.exclusions && Array.isArray(scope.exclusions)) {
        for (const exc of scope.exclusions) {
          if (trimmed === exc.value) {
            return { status: 'DENIED', reason: `Blocked: Target explicitly excluded by Scope "${scope.name}" (${exc.reason || exc.value})` };
          }
          if (exc.type === 'CIDR' && isIpInCidr(trimmed, exc.value)) {
            return { status: 'DENIED', reason: `Blocked: Target within excluded CIDR block "${exc.value}" in Scope "${scope.name}"` };
          }
        }
      }
    }

    // Check inclusions
    for (const scope of scopes) {
      if (scope.inclusions && Array.isArray(scope.inclusions)) {
        for (const inc of scope.inclusions) {
          if (trimmed === inc.value) {
            return { status: 'AUTHORIZED', reason: `Authorized by Scope "${scope.name}" (Rule: ${inc.value})` };
          }
          if (inc.type === 'CIDR' && isIpInCidr(trimmed, inc.value)) {
            return { status: 'AUTHORIZED', reason: `Authorized within CIDR block "${inc.value}" in Scope "${scope.name}"` };
          }
          if (inc.type === 'DOMAIN' && (trimmed.toLowerCase() === inc.value.toLowerCase() || trimmed.toLowerCase().endsWith('.' + inc.value.toLowerCase()))) {
            return { status: 'AUTHORIZED', reason: `Authorized domain match "${inc.value}" in Scope "${scope.name}"` };
          }
          if (inc.type === 'URL' && trimmed.startsWith(inc.value)) {
            return { status: 'AUTHORIZED', reason: `Authorized URL prefix "${inc.value}" in Scope "${scope.name}"` };
          }
        }
      }
    }

    return { status: 'DENIED', reason: 'Target does not match any authorized scope inclusion rules' };
  }

  function render() {
    const wksState = deps.workspaceStore.getState();
    const allWorkspaces = wksState.workspaces;
    const activeWks = deps.workspaceStore.getActiveWorkspace();

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
                      ${w.id === activeWks?.id ? '<span class="badge badge-active" style="margin-left:8px;">Active</span>' : ''}
                    </td>
                    <td style="font-family:var(--font-mono);font-size:12px;">${w.slug}</td>
                    <td><span class="badge badge-active">PROVISIONED</span></td>
                    <td>
                      ${w.id !== activeWks?.id ? `
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
              placeholder="e.g. 192.168.1.50 or 169.254.169.254 or api.internal.corp"
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
                <input class="form-input" id="scope-name" type="text" placeholder="e.g. Authorized Network Perimeter" required />
              </div>
              <div class="form-group">
                <label class="form-label" for="scope-desc">Description</label>
                <input class="form-input" id="scope-desc" type="text" placeholder="Authorized operational targets" />
              </div>
              <div class="form-group">
                <label class="form-label" for="scope-inclusions">Target Inclusions (Comma-separated IPs, CIDRs, or FQDNs)</label>
                <input class="form-input" id="scope-inclusions" type="text" placeholder="10.0.0.0/16, 192.168.1.1, api.internal.corp" required />
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
      btn.addEventListener('click', async (e) => {
        const id = (e.currentTarget as HTMLElement).getAttribute('data-wks-id');
        if (id) {
          const current = deps.workspaceStore.getActiveWorkspace();
          if (current?.id === id) return;
          try {
            const switched = await deps.workspaceStore.setActiveWorkspace(id);
            if (switched) {
              deps.notify.success('Switched active workspace', 'Context Updated');
              await loadData();
            }
          } catch (err: any) {
            deps.notify.error(err.message || 'Failed to switch workspace');
          }
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
      const activeWks = deps.workspaceStore.getActiveWorkspace();
      if (!activeWks) {
        deps.notify.error('No active workspace selected.');
        return;
      }
      const name = (container.querySelector('#scope-name') as HTMLInputElement).value.trim();
      const desc = (container.querySelector('#scope-desc') as HTMLInputElement).value.trim();
      const incStr = (container.querySelector('#scope-inclusions') as HTMLInputElement).value.trim();
      const portStr = (container.querySelector('#scope-ports') as HTMLInputElement)?.value.trim() || '1-65535';

      const inclusions = incStr.split(',').map((s) => s.trim()).filter(Boolean).map((v) => ({
        type: v.includes('/') ? 'CIDR' : v.includes('://') ? 'URL' : v.includes('.') ? 'IPV4' : 'DOMAIN',
        value: v,
      }));

      const [startStr, endStr] = portStr.split('-');
      const pStart = parseInt(startStr || '1', 10);
      const pEnd = parseInt(endStr || startStr || '65535', 10);
      const port_ranges = [{
        start: isNaN(pStart) ? 1 : pStart,
        end: isNaN(pEnd) ? 65535 : pEnd,
      }];

      try {
        await deps.api.createScope(activeWks.id, {
          name,
          description: desc,
          inclusions,
          port_ranges,
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
