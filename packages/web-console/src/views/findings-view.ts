/**
 * Shadow : Helix Nebula (SHN) — Finding Lifecycle & Vulnerability Management View
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Finding, Asset, FindingTransition } from '../contracts.js';

export function renderFindingsView(
  container: HTMLElement,
  deps: { api: ApiClient; workspaceStore: WorkspaceStore; notify: NotificationStore }
): void {
  let findings: Finding[] = [];
  let assets: Asset[] = [];
  let isLoading = true;
  let selectedSeverity = 'ALL';
  let selectedStatus = 'ALL';
  let searchQuery = '';
  let showRecordModal = false;
  let inspectedFinding: Finding | null = null;
  let findingHistory: FindingTransition[] = [];
  let isTransitioning = false;

  const currentWks = deps.workspaceStore.getState().activeWorkspace;

  async function loadData() {
    if (!currentWks) return;
    isLoading = true;
    render();

    try {
      const [fList, aList] = await Promise.all([
        deps.api.listFindings(currentWks.id),
        deps.api.listAssets(currentWks.id).catch(() => []),
      ]);
      findings = fList;
      assets = aList;
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to load vulnerability findings');
    } finally {
      isLoading = false;
      render();
    }
  }

  function getFilteredFindings(): Finding[] {
    return findings.filter((f) => {
      const matchSev = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
      const matchStat = selectedStatus === 'ALL' || f.status === selectedStatus;
      const q = searchQuery.toLowerCase();
      const matchSearch =
        !searchQuery ||
        f.title.toLowerCase().includes(q) ||
        (f.cveId || f.cve_id || '').toLowerCase().includes(q) ||
        (f.category || '').toLowerCase().includes(q);
      return matchSev && matchStat && matchSearch;
    });
  }

  async function openInspectDrawer(finding: Finding) {
    inspectedFinding = finding;
    if (currentWks) {
      try {
        findingHistory = await deps.api.getFindingHistory(currentWks.id, finding.id);
      } catch {
        findingHistory = [];
      }
    }
    render();
  }

  function render() {
    const displayed = getFilteredFindings();

    container.innerHTML = `
      <div class="content-viewport">
        <!-- Page Header -->
        <div class="page-header">
          <div class="page-title-group">
            <h2>Vulnerability Findings & Lifecycle Triage</h2>
            <div class="page-subtitle">
              Sovereign finding ingestion with formal state transitions and cryptographic evidence verification (INV-05).
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-open-record-modal" class="btn btn-primary">
              <span>+</span> Record Vulnerability Finding
            </button>
          </div>
        </div>

        <!-- Filter & Search Toolbar -->
        <div class="card" style="padding:16px;">
          <div class="filter-bar">
            <div class="search-input-wrapper">
              <span class="search-icon">🔍</span>
              <input
                id="search-findings-input"
                class="form-input"
                type="text"
                placeholder="Search by CVE, CWE, title, or category..."
                value="${searchQuery}"
              />
            </div>

            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
              <!-- Severity Filter -->
              <select id="select-filter-sev" class="form-select" style="width:auto;">
                <option value="ALL" ${selectedSeverity === 'ALL' ? 'selected' : ''}>All Severities</option>
                <option value="CRITICAL" ${selectedSeverity === 'CRITICAL' ? 'selected' : ''}>Critical</option>
                <option value="HIGH" ${selectedSeverity === 'HIGH' ? 'selected' : ''}>High</option>
                <option value="MEDIUM" ${selectedSeverity === 'MEDIUM' ? 'selected' : ''}>Medium</option>
                <option value="LOW" ${selectedSeverity === 'LOW' ? 'selected' : ''}>Low</option>
                <option value="INFORMATIONAL" ${selectedSeverity === 'INFORMATIONAL' ? 'selected' : ''}>Informational</option>
              </select>

              <!-- Status Filter -->
              <select id="select-filter-stat" class="form-select" style="width:auto;">
                <option value="ALL" ${selectedStatus === 'ALL' ? 'selected' : ''}>All Lifecycle States</option>
                <option value="OPEN" ${selectedStatus === 'OPEN' ? 'selected' : ''}>Open</option>
                <option value="TRIAGED" ${selectedStatus === 'TRIAGED' ? 'selected' : ''}>Triaged</option>
                <option value="CONFIRMED" ${selectedStatus === 'CONFIRMED' ? 'selected' : ''}>Confirmed</option>
                <option value="RESOLVED" ${selectedStatus === 'RESOLVED' ? 'selected' : ''}>Resolved</option>
                <option value="FALSE_POSITIVE" ${selectedStatus === 'FALSE_POSITIVE' ? 'selected' : ''}>False Positive</option>
                <option value="ACCEPTED_RISK" ${selectedStatus === 'ACCEPTED_RISK' ? 'selected' : ''}>Accepted Risk</option>
              </select>

              <button id="btn-refresh-findings" class="btn btn-secondary btn-sm">↻ Refresh</button>
            </div>
          </div>
        </div>

        <!-- Findings Table -->
        <div class="card" style="padding:0;overflow:hidden;">
          <div class="data-table-container" style="border:none;">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Vulnerability Title</th>
                  <th>Severity</th>
                  <th>CVSS Score</th>
                  <th>CVE / CWE ID</th>
                  <th>Lifecycle Status</th>
                  <th>Associated Target</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${displayed.length > 0 ? displayed.map((f) => {
                  const critBadgeClass = f.severity === 'CRITICAL' ? 'badge-critical' : f.severity === 'HIGH' ? 'badge-high' : f.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low';
                  const cvss = f.cvssScore !== undefined && f.cvssScore !== null ? f.cvssScore : f.cvss_score;
                  const cve = f.cveId || f.cve_id || f.cweId || f.cwe_id || 'N/A';
                  const targetAsset = assets.find((a) => a.id === f.assetId || a.id === f.asset_id);
                  const targetLabel = targetAsset ? (targetAsset.canonicalValue || targetAsset.canonical_target || targetAsset.name) : 'Asset';

                  return `
                    <tr>
                      <td>
                        <strong style="color:var(--text-primary);">${f.title}</strong>
                        <div style="font-size:11px;color:var(--text-muted);">${f.category}</div>
                      </td>
                      <td><span class="badge ${critBadgeClass}">${f.severity}</span></td>
                      <td style="font-family:var(--font-mono);font-weight:700;">
                        ${cvss !== undefined && cvss !== null ? `
                          <span style="color:${cvss >= 9 ? 'var(--color-critical)' : cvss >= 7 ? 'var(--color-high)' : 'var(--color-medium)'};">${cvss}</span>
                        ` : '—'}
                      </td>
                      <td style="font-family:var(--font-mono);font-size:12px;color:var(--accent-primary);">
                        ${cve}
                      </td>
                      <td><span class="badge badge-active">${f.status}</span></td>
                      <td style="font-family:var(--font-mono);font-size:12px;">
                        ${targetLabel}
                      </td>
                      <td>
                        <button class="btn btn-secondary btn-sm btn-inspect-finding" data-finding-id="${f.id}">
                          Triage & Evidence
                        </button>
                      </td>
                    </tr>
                  `;
                }).join('') : `
                  <tr>
                    <td colspan="7" style="text-align:center;padding:36px;color:var(--text-muted);">
                      ${isLoading ? 'Loading vulnerability findings...' : 'No vulnerability findings recorded for this workspace.'}
                    </td>
                  </tr>
                `}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Modal: Record Finding -->
      <div id="modal-record-finding" class="modal-overlay ${showRecordModal ? 'active' : ''}">
        <div class="modal-dialog" style="max-width:640px;">
          <div class="modal-header">
            <h3>Record Vulnerability Finding</h3>
            <button class="btn btn-ghost btn-sm btn-close-modal">✕</button>
          </div>
          <form id="form-record-finding">
            <div class="modal-body">
              <div class="form-group">
                <label class="form-label" for="fnd-asset">Target Affected Asset</label>
                <select class="form-select" id="fnd-asset" required>
                  ${assets.map((a) => `
                    <option value="${a.id}">${a.name} (${a.canonicalValue || a.canonical_target || a.rawTarget})</option>
                  `).join('') || '<option value="">No assets registered</option>'}
                </select>
              </div>

              <div class="form-group">
                <label class="form-label" for="fnd-title">Finding Title</label>
                <input class="form-input" id="fnd-title" type="text" placeholder="e.g. OpenSSH Remote Code Execution Vulnerability" required />
              </div>

              <div class="form-group">
                <label class="form-label" for="fnd-desc">Vulnerability Description</label>
                <textarea class="form-textarea" id="fnd-desc" placeholder="Detailed vulnerability overview, attack vector, and impacts..." required></textarea>
              </div>

              <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                <div class="form-group">
                  <label class="form-label" for="fnd-category">Category</label>
                  <input class="form-input" id="fnd-category" type="text" placeholder="REMOTE_CODE_EXECUTION" required />
                </div>
                <div class="form-group">
                  <label class="form-label" for="fnd-severity">Severity</label>
                  <select class="form-select" id="fnd-severity">
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH" selected>HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                    <option value="INFORMATIONAL">INFORMATIONAL</option>
                  </select>
                </div>
              </div>

              <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                <div class="form-group">
                  <label class="form-label" for="fnd-cve">CVE Identifier</label>
                  <input class="form-input" id="fnd-cve" type="text" placeholder="CVE-2024-6387" />
                </div>
                <div class="form-group">
                  <label class="form-label" for="fnd-cvss">CVSS v3.1 Score (0.0 - 10.0)</label>
                  <input class="form-input" id="fnd-cvss" type="number" step="0.1" min="0" max="10" placeholder="8.1" />
                </div>
              </div>

              <div class="form-group">
                <label class="form-label" for="fnd-evidence-hash">Raw Evidence SHA-256 Hash (INV-05 Mandatory)</label>
                <input class="form-input" id="fnd-evidence-hash" type="text" placeholder="64-character lowercase hexadecimal SHA-256 hash" required minlength="64" maxlength="64" />
              </div>

              <div class="form-group">
                <label class="form-label" for="fnd-remediation">Remediation Guidance</label>
                <textarea class="form-textarea" id="fnd-remediation" placeholder="Recommended fix, patch instructions, and compensating controls..."></textarea>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary btn-close-modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Ingest Vulnerability Finding</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Drawer: Finding Triage & Evidence Inspection -->
      <div id="drawer-finding-overlay" class="drawer-overlay ${inspectedFinding ? 'active' : ''}"></div>
      <div id="drawer-finding-panel" class="drawer-panel ${inspectedFinding ? 'active' : ''}">
        ${inspectedFinding ? `
          <div class="modal-header">
            <div>
              <h3>${inspectedFinding.title}</h3>
              <span class="badge ${inspectedFinding.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${inspectedFinding.severity}</span>
            </div>
            <button class="btn btn-ghost btn-sm btn-close-drawer">✕</button>
          </div>
          <div style="flex:1;overflow-y:auto;padding:24px;display:flex;flex-direction:column;gap:18px;">
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px;">Description</h4>
              <p style="font-size:13px;line-height:1.6;">${inspectedFinding.description}</p>
            </div>

            <!-- Vulnerability Details Grid -->
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:12px;">Security Classification</h4>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px;">
                <div><span style="color:var(--text-muted);">CVE ID:</span> <strong style="color:var(--accent-primary);">${inspectedFinding.cveId || inspectedFinding.cve_id || 'None'}</strong></div>
                <div><span style="color:var(--text-muted);">CVSS Score:</span> <strong>${inspectedFinding.cvssScore || inspectedFinding.cvss_score || 'N/A'}</strong></div>
                <div><span style="color:var(--text-muted);">Current State:</span> <strong style="color:var(--status-active);">${inspectedFinding.status}</strong></div>
                <div><span style="color:var(--text-muted);">Category:</span> <span>${inspectedFinding.category}</span></div>
              </div>
            </div>

            <!-- Evidence Block -->
            <div class="card" style="padding:16px;">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px;">Evidence Hash Verification (INV-05)</h4>
              <code style="word-break:break-all;font-size:11px;color:var(--accent-primary);display:block;padding:8px;background:var(--bg-terminal);border-radius:var(--radius-xs);">
                ${inspectedFinding.rawEvidenceSha256 || inspectedFinding.raw_evidence_sha256}
              </code>
            </div>

            ${inspectedFinding.remediationGuidance || inspectedFinding.remediation_guidance ? `
              <div class="card" style="padding:16px;">
                <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px;">Remediation Guidance</h4>
                <p style="font-size:12px;color:var(--text-secondary);">${inspectedFinding.remediationGuidance || inspectedFinding.remediation_guidance}</p>
              </div>
            ` : ''}

            <!-- State Machine Triage Workflow -->
            <div class="card" style="padding:16px;border:1px solid var(--accent-border);">
              <h4 style="font-size:12px;text-transform:uppercase;color:var(--accent-primary);margin-bottom:12px;">Triage Lifecycle Transition</h4>
              <div class="form-group">
                <label class="form-label">Next Target State</label>
                <select id="transition-target-select" class="form-select">
                  <option value="TRIAGED">TRIAGED (Assigned for validation)</option>
                  <option value="CONFIRMED">CONFIRMED (Exploitable & Verified)</option>
                  <option value="RESOLVED">RESOLVED (Patched / Compensating control)</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE (Closed as benign)</option>
                  <option value="ACCEPTED_RISK">ACCEPTED_RISK (Risk waiver granted)</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label">Transition Justification / Reason</label>
                <input class="form-input" id="transition-reason-input" type="text" placeholder="Audited remediation verification..." />
              </div>
              <button id="btn-submit-transition" class="btn btn-primary" style="width:100%;" ${isTransitioning ? 'disabled' : ''}>
                ${isTransitioning ? 'Recording Transition...' : 'Execute State Transition'}
              </button>
            </div>

            <!-- Transition Audit History -->
            ${findingHistory.length > 0 ? `
              <div class="card" style="padding:16px;">
                <h4 style="font-size:12px;text-transform:uppercase;color:var(--text-muted);margin-bottom:12px;">Audit Transition Timeline</h4>
                ${findingHistory.map((h) => `
                  <div style="padding:8px;border-left:2px solid var(--accent-primary);margin-bottom:8px;font-size:12px;">
                    <div>To: <strong style="color:var(--status-active);">${h.toStatus}</strong> (from ${h.fromStatus})</div>
                    <div style="font-size:11px;color:var(--text-muted);">${h.reason || 'No reason specified'} · ${new Date(h.createdAt || '').toLocaleString()}</div>
                  </div>
                `).join('')}
              </div>
            ` : ''}
          </div>
        ` : ''}
      </div>
    `;

    // Event Bindings
    container.querySelector('#search-findings-input')?.addEventListener('input', (e) => {
      searchQuery = (e.target as HTMLInputElement).value;
      render();
    });

    container.querySelector('#select-filter-sev')?.addEventListener('change', (e) => {
      selectedSeverity = (e.target as HTMLSelectElement).value;
      render();
    });

    container.querySelector('#select-filter-stat')?.addEventListener('change', (e) => {
      selectedStatus = (e.target as HTMLSelectElement).value;
      render();
    });

    container.querySelector('#btn-refresh-findings')?.addEventListener('click', () => {
      loadData();
    });

    container.querySelector('#btn-open-record-modal')?.addEventListener('click', () => {
      showRecordModal = true;
      render();
    });

    container.querySelectorAll('.btn-close-modal').forEach((btn) => {
      btn.addEventListener('click', () => {
        showRecordModal = false;
        render();
      });
    });

    container.querySelectorAll('.btn-inspect-finding').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const id = (e.currentTarget as HTMLElement).getAttribute('data-finding-id');
        const found = findings.find((f) => f.id === id);
        if (found) openInspectDrawer(found);
      });
    });

    container.querySelector('.btn-close-drawer')?.addEventListener('click', () => {
      inspectedFinding = null;
      render();
    });
    container.querySelector('#drawer-finding-overlay')?.addEventListener('click', () => {
      inspectedFinding = null;
      render();
    });

    // Handle Record Finding Submit
    container.querySelector('#form-record-finding')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!currentWks) return;

      const assetId = (container.querySelector('#fnd-asset') as HTMLSelectElement).value;
      const title = (container.querySelector('#fnd-title') as HTMLInputElement).value.trim();
      const description = (container.querySelector('#fnd-desc') as HTMLTextAreaElement).value.trim();
      const category = (container.querySelector('#fnd-category') as HTMLInputElement).value.trim();
      const severity = (container.querySelector('#fnd-severity') as HTMLSelectElement).value;
      const cveId = (container.querySelector('#fnd-cve') as HTMLInputElement).value.trim() || undefined;
      const cvssVal = (container.querySelector('#fnd-cvss') as HTMLInputElement).value;
      const rawEvidenceSha256 = (container.querySelector('#fnd-evidence-hash') as HTMLInputElement).value.trim();
      const remediation = (container.querySelector('#fnd-remediation') as HTMLTextAreaElement).value.trim() || undefined;

      try {
        await deps.api.recordFinding(currentWks.id, {
          assetId,
          title,
          description,
          category,
          severity,
          cveId,
          cvssScore: cvssVal ? parseFloat(cvssVal) : undefined,
          rawEvidenceSha256,
          remediationGuidance: remediation,
        });
        deps.notify.success(`Finding "${title}" recorded`, 'Vulnerability Ingested');
        showRecordModal = false;
        loadData();
      } catch (err: any) {
        deps.notify.error(err.message || 'Failed to record finding');
      }
    });

    // Handle Transition Submit
    container.querySelector('#btn-submit-transition')?.addEventListener('click', async () => {
      if (!currentWks || !inspectedFinding) return;
      isTransitioning = true;
      render();

      const toStatus = (container.querySelector('#transition-target-select') as HTMLSelectElement).value;
      const reason = (container.querySelector('#transition-reason-input') as HTMLInputElement).value.trim();

      try {
        await deps.api.transitionFinding(currentWks.id, inspectedFinding.id, toStatus, reason);
        deps.notify.success(`Status transitioned to ${toStatus}`, 'Triage Updated');
        inspectedFinding.status = toStatus as any;
        isTransitioning = false;
        loadData();
      } catch (err: any) {
        isTransitioning = false;
        deps.notify.error(err.message || 'Transition rejected by state machine');
        render();
      }
    });
  }

  loadData();
}
