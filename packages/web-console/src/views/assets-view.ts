/**
 * Shadow : Helix Nebula (SHN) — Asset Inventory View
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Asset, Finding } from '../contracts.js';

export function renderAssetsView(
  container: HTMLElement,
  deps: { api: ApiClient; workspaceStore: WorkspaceStore; notify: NotificationStore }
): void {
  let assets: Asset[] = [];
  let findings: Finding[] = [];
  let isLoading = true;
  let searchQuery = '';
  let selectedType = 'ALL';
  let selectedCriticality = 'ALL';
  let showRegisterModal = false;
  let inspectedAsset: Asset | null = null;
  let isUpdatingAsset = false;

  async function loadData() {
    const currentWks = deps.workspaceStore.getActiveWorkspace();
    if (!currentWks) {
      assets = [];
      findings = [];
      isLoading = false;
      render();
      return;
    }
    isLoading = true;
    render();

    try {
      const [aList, fList] = await Promise.all([
        deps.api.listAssets(currentWks.id),
        deps.api.listFindings(currentWks.id).catch(() => []),
      ]);
      assets = aList;
      findings = fList;
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to load assets');
    } finally {
      isLoading = false;
      render();
    }
  }

  function getFilteredAssets(): Asset[] {
    return assets.filter((a) => {
      const target = a.canonicalValue || a.canonical_target || a.rawTarget || a.raw_target || '';
      const name = a.name || '';
      const matchSearch = !searchQuery || target.toLowerCase().includes(searchQuery.toLowerCase()) || name.toLowerCase().includes(searchQuery.toLowerCase());
      const matchType = selectedType === 'ALL' || a.type === selectedType;
      const matchCrit = selectedCriticality === 'ALL' || a.criticality === selectedCriticality;
      return matchSearch && matchType && matchCrit;
    });
  }

  function render() {
    const displayed = getFilteredAssets();

    container.innerHTML = `
      <div class="content-viewport">
        <!-- Page Header -->
        <div class="page-header">
          <div class="page-title-group">
            <h2>Asset Inventory & Attack Surface</h2>
            <div class="page-subtitle">
              Sovereign target registry with canonical normalization and criticality classification.
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-open-register-modal" class="btn btn-primary">
              <span>+</span> Register New Asset
            </button>
          </div>
        </div>

        <!-- Filter & Search Toolbar -->
        <div class="card" style="padding:16px;">
          <div class="filter-bar">
            <div class="search-input-wrapper">
              <span class="search-icon">🔍</span>
              <input
                id="search-assets-input"
                class="form-input"
                type="text"
                placeholder="Search by target IP, host, or name..."
                value="${searchQuery}"
              />
            </div>

            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
              <!-- Type Filter -->
              <select id="select-filter-type" class="form-select" style="width:auto;">
                <option value="ALL" ${selectedType === 'ALL' ? 'selected' : ''}>All Target Types</option>
                <option value="IPV4" ${selectedType === 'IPV4' ? 'selected' : ''}>IPv4 Addresses</option>
                <option value="CIDR" ${selectedType === 'CIDR' ? 'selected' : ''}>CIDR Blocks</option>
                <option value="DOMAIN" ${selectedType === 'DOMAIN' ? 'selected' : ''}>Domains / Hosts</option>
                <option value="URL" ${selectedType === 'URL' ? 'selected' : ''}>HTTP / URLs</option>
              </select>

              <!-- Criticality Filter -->
              <select id="select-filter-crit" class="form-select" style="width:auto;">
                <option value="ALL" ${selectedCriticality === 'ALL' ? 'selected' : ''}>All Criticalities</option>
                <option value="CRITICAL" ${selectedCriticality === 'CRITICAL' ? 'selected' : ''}>Critical Tier</option>
                <option value="HIGH" ${selectedCriticality === 'HIGH' ? 'selected' : ''}>High Tier</option>
                <option value="MEDIUM" ${selectedCriticality === 'MEDIUM' ? 'selected' : ''}>Medium Tier</option>
                <option value="LOW" ${selectedCriticality === 'LOW' ? 'selected' : ''}>Low Tier</option>
              </select>

              <button id="btn-refresh-assets" class="btn btn-secondary btn-sm">↻ Refresh</button>
            </div>
          </div>
        </div>

        <!-- Assets Data Table -->
        <div class="card" style="padding:0;overflow:hidden;">
          <div class="data-table-container" style="border:none;">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Target / Canonical</th>
                  <th>Type</th>
                  <th>Asset Name</th>
                  <th>Criticality</th>
                  <th>Status</th>
                  <th>Tags</th>
                  <th>Vulnerabilities</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${displayed.length > 0 ? displayed.map((a) => {
                  const target = a.canonicalValue || a.canonical_target || a.rawTarget || a.raw_target || 'N/A';
                  const critBadgeClass = a.criticality === 'CRITICAL' ? 'badge-critical' : a.criticality === 'HIGH' ? 'badge-high' : a.criticality === 'MEDIUM' ? 'badge-medium' : 'badge-low';
                  const relatedFindings = findings.filter((f) => f.assetId === a.id || f.asset_id === a.id);

                  return `
                    <tr>
                      <td style="font-family:var(--font-mono);font-size:13px;font-weight:600;color:var(--text-primary);">
                        ${target}
                      </td>
                      <td><span class="badge badge-info">${a.type}</span></td>
                      <td>${a.name}</td>
                      <td><span class="badge ${critBadgeClass}">${a.criticality}</span></td>
                      <td><span class="badge badge-active">${a.status}</span></td>
                      <td>
                        <div style="display:flex;gap:4px;flex-wrap:wrap;">
                          ${(a.tags || []).map((t) => `<span style="font-size:10px;padding:2px 6px;background:var(--bg-input);border-radius:3px;color:var(--text-muted);">${t}</span>`).join('')}
                        </div>
                      </td>
                      <td>
                        ${relatedFindings.length > 0 ? `
                          <span class="badge badge-critical" style="cursor:pointer;" title="${relatedFindings.length} findings linked">
                            ${relatedFindings.length} Open
                          </span>
                        ` : `
                          <span style="font-size:11px;color:var(--text-muted);">None</span>
                        `}
                      </td>
                      <td>
                        <button class="btn btn-secondary btn-sm btn-inspect-asset" data-asset-id="${a.id}">
                          Inspect Target
                        </button>
                      </td>
                    </tr>
                  `;
                }).join('') : `
                  <tr>
                    <td colspan="8" style="text-align:center;padding:36px;color:var(--text-muted);">
                      ${isLoading ? 'Loading assets...' : 'No monitored assets registered for this workspace.'}
                    </td>
                  </tr>
                `}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Modal: Register Asset -->
      <div id="modal-register-asset" class="modal-overlay ${showRegisterModal ? 'active' : ''}">
        <div class="modal-dialog">
          <div class="modal-header">
            <h3>Register Target Asset</h3>
            <button class="btn btn-ghost btn-sm btn-close-modal">✕</button>
          </div>
          <form id="form-register-asset">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label" for="reg-asset-target">Target Endpoint / Address</label>
                <input class="form-input" id="reg-asset-target" type="text" placeholder="192.168.1.100 or service.internal.corp" required />
              </div>
              <div class="form-group">
                <label class="form-label" for="reg-asset-name">Friendly Name</label>
                <input class="form-input" id="reg-asset-name" type="text" placeholder="Primary Ingress Controller" />
              </div>
              <div class="form-group">
                <label class="form-label" for="reg-asset-type">Asset Type</label>
                <select class="form-select" id="reg-asset-type">
                  <option value="IPV4">IPv4 Address</option>
                  <option value="CIDR">CIDR Subnet</option>
                  <option value="DOMAIN">Domain / FQDN</option>
                  <option value="URL">HTTP/HTTPS URL</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label" for="reg-asset-crit">Criticality Classification</label>
                <select class="form-select" id="reg-asset-crit">
                  <option value="CRITICAL">Critical Infrastructure</option>
                  <option value="HIGH">High Priority</option>
                  <option value="MEDIUM" selected>Medium Priority</option>
                  <option value="LOW">Low Priority</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label" for="reg-asset-tags">Tags (Comma-separated)</label>
                <input class="form-input" id="reg-asset-tags" type="text" placeholder="production, k8s, gateway" />
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary btn-close-modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Register Target Asset</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Drawer: Asset Inspection -->
      <div id="drawer-asset-overlay" class="drawer-overlay ${inspectedAsset ? 'active' : ''}"></div>
      <div id="drawer-asset-panel" class="drawer-panel ${inspectedAsset ? 'active' : ''}">
        ${inspectedAsset ? `
          <div class="modal-header">
            <div>
              <h3>${inspectedAsset.name}</h3>
              <code style="font-size:12px;color:var(--accent-primary);">${inspectedAsset.canonicalValue || inspectedAsset.canonical_target || inspectedAsset.rawTarget}</code>
            </div>
            <button class="btn btn-ghost btn-sm btn-close-drawer">✕</button>
          </div>
          <div style="flex:1;overflow-y:auto;padding:24px;display:flex;flex-direction:column;gap:20px;">
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:12px;">Asset Metadata</h4>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px;">
                <div><span style="color:var(--text-muted);">Type:</span> <strong>${inspectedAsset.type}</strong></div>
                <div><span style="color:var(--text-muted);">Criticality:</span> <strong>${inspectedAsset.criticality}</strong></div>
                <div><span style="color:var(--text-muted);">Status:</span> <strong>${inspectedAsset.status}</strong></div>
                <div><span style="color:var(--text-muted);">Registered:</span> <span>${new Date(inspectedAsset.createdAt || inspectedAsset.created_at || '').toLocaleDateString()}</span></div>
              </div>
            </div>

            <!-- Linked Findings -->
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:12px;">Associated Vulnerabilities</h4>
              ${findings.filter((f) => f.assetId === inspectedAsset!.id || f.asset_id === inspectedAsset!.id).map((f) => `
                <div style="padding:10px;border-radius:var(--radius-sm);background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);margin-bottom:8px;">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span class="badge ${f.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${f.severity}</span>
                    <span style="font-family:var(--font-mono);font-size:11px;color:var(--accent-primary);">${f.cveId || f.cve_id || 'CVE Pending'}</span>
                  </div>
                  <div style="font-weight:600;font-size:13px;margin-top:6px;">${f.title}</div>
                </div>
              `).join('') || '<p style="font-size:12px;color:var(--text-muted);">No open vulnerabilities recorded against this asset.</p>'}
            </div>

            <!-- Update Status Form -->
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:12px;">Modify Criticality & Lifecycle</h4>
              <div class="form-group">
                <label class="form-label">Criticality</label>
                <select id="update-crit-select" class="form-select">
                  <option value="CRITICAL" ${inspectedAsset.criticality === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                  <option value="HIGH" ${inspectedAsset.criticality === 'HIGH' ? 'selected' : ''}>HIGH</option>
                  <option value="MEDIUM" ${inspectedAsset.criticality === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                  <option value="LOW" ${inspectedAsset.criticality === 'LOW' ? 'selected' : ''}>LOW</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label">Status</label>
                <select id="update-status-select" class="form-select">
                  <option value="ACTIVE" ${inspectedAsset.status === 'ACTIVE' ? 'selected' : ''}>ACTIVE</option>
                  <option value="INACTIVE" ${inspectedAsset.status === 'INACTIVE' ? 'selected' : ''}>INACTIVE</option>
                  <option value="ARCHIVED" ${inspectedAsset.status === 'ARCHIVED' ? 'selected' : ''}>ARCHIVED</option>
                </select>
              </div>
              <button id="btn-save-asset-update" class="btn btn-primary" style="width:100%;" ${isUpdatingAsset ? 'disabled' : ''}>
                ${isUpdatingAsset ? 'Saving Changes...' : 'Save Updates'}
              </button>
            </div>
          </div>
        ` : ''}
      </div>
    `;

    // Event Bindings
    container.querySelector('#search-assets-input')?.addEventListener('input', (e) => {
      searchQuery = (e.target as HTMLInputElement).value;
      render();
    });

    container.querySelector('#select-filter-type')?.addEventListener('change', (e) => {
      selectedType = (e.target as HTMLSelectElement).value;
      render();
    });

    container.querySelector('#select-filter-crit')?.addEventListener('change', (e) => {
      selectedCriticality = (e.target as HTMLSelectElement).value;
      render();
    });

    container.querySelector('#btn-refresh-assets')?.addEventListener('click', () => {
      loadData();
    });

    container.querySelector('#btn-open-register-modal')?.addEventListener('click', () => {
      showRegisterModal = true;
      render();
    });

    container.querySelectorAll('.btn-close-modal').forEach((btn) => {
      btn.addEventListener('click', () => {
        showRegisterModal = false;
        render();
      });
    });

    container.querySelectorAll('.btn-inspect-asset').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const id = (e.currentTarget as HTMLElement).getAttribute('data-asset-id');
        inspectedAsset = assets.find((a) => a.id === id) || null;
        render();
      });
    });

    container.querySelector('.btn-close-drawer')?.addEventListener('click', () => {
      inspectedAsset = null;
      render();
    });
    container.querySelector('#drawer-asset-overlay')?.addEventListener('click', () => {
      inspectedAsset = null;
      render();
    });

    // Handle Register Asset Submit
    container.querySelector('#form-register-asset')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const activeWks = deps.workspaceStore.getActiveWorkspace();
      if (!activeWks) {
        deps.notify.error('No active workspace selected.');
        return;
      }

      const rawTarget = (container.querySelector('#reg-asset-target') as HTMLInputElement).value.trim();
      const name = (container.querySelector('#reg-asset-name') as HTMLInputElement).value.trim();
      const type = (container.querySelector('#reg-asset-type') as HTMLSelectElement).value;
      const crit = (container.querySelector('#reg-asset-crit') as HTMLSelectElement).value;
      const tagsStr = (container.querySelector('#reg-asset-tags') as HTMLInputElement).value.trim();
      const tags = tagsStr.split(',').map((t) => t.trim()).filter(Boolean);

      try {
        await deps.api.registerAsset(activeWks.id, {
          rawTarget,
          name: name || rawTarget,
          type,
          criticality: crit,
          tags,
        });
        deps.notify.success(`Asset "${rawTarget}" registered`, 'Target Enrolled');
        showRegisterModal = false;
        loadData();
      } catch (err: any) {
        deps.notify.error(err.message || 'Failed to register asset');
      }
    });

    // Handle Asset Updates
    container.querySelector('#btn-save-asset-update')?.addEventListener('click', async () => {
      const activeWks = deps.workspaceStore.getActiveWorkspace();
      if (!activeWks || !inspectedAsset) return;
      isUpdatingAsset = true;
      render();

      const crit = (container.querySelector('#update-crit-select') as HTMLSelectElement).value;
      const status = (container.querySelector('#update-status-select') as HTMLSelectElement).value;

      try {
        const updated = await deps.api.updateAsset(activeWks.id, inspectedAsset.id, {
          criticality: crit as any,
          status: status as any,
        });
        deps.notify.success(`Asset ${updated.name} updated`, 'Success');
        inspectedAsset = updated;
        isUpdatingAsset = false;
        loadData();
      } catch (err: any) {
        isUpdatingAsset = false;
        deps.notify.error(err.message || 'Failed to update asset');
        render();
      }
    });
  }

  loadData();
}
