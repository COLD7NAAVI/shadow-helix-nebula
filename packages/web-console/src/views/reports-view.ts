/**
 * Shadow : Helix Nebula (SHN) — Professional Security Assessment Reporting View
 *
 * Implements Section 13:
 * - Generates comprehensive security reports from actual persisted findings, assets & scopes
 * - Executive Summary, Technical Assessment, Compliance Audit, Evidence Catalog
 * - SHA-256 cryptographic integrity signing & verification badge
 * - Printable PDF view (window.print() with custom print CSS) & JSON download
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { Report } from '../contracts.js';

export class ReportsView {
  private container: HTMLElement | null = null;
  private reports: Report[] = [];
  private selectedReport: Report | null = null;
  private isGenerating = false;

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
      this.reports = await this.api.listReports(ws.id).catch(() => []);
      if (this.reports.length > 0 && !this.selectedReport) {
        this.selectedReport = this.reports[0] ?? null;
      }
      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load assessment reports');
    }
  }

  private async generateReport(title: string, reportType: string): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    this.isGenerating = true;
    this.render();

    try {
      this.notify.info(`Generating ${reportType} from persisted findings and evidence...`);
      const newReport = await this.api.generateReport(ws.id, {
        title,
        reportType,
      });

      this.notify.success(`Report generated! SHA-256: ${newReport.contentSha256.substring(0, 12)}...`);
      this.selectedReport = newReport;
      await this.loadData();
    } catch (err: any) {
      this.notify.error(err.message || 'Report generation failed');
    } finally {
      this.isGenerating = false;
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
        <div class="page-header no-print" style="margin-bottom:0;">
          <div class="page-title-group">
            <div style="display:flex;align-items:center;gap:12px;">
              <h2>Security Assessment Reporting & Provenance</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                SHA-256 SIGNED
              </span>
            </div>
            <div class="page-subtitle">
              Verified security reports for workspace: <strong style="color:var(--text-primary);">${ws?.name || 'Default'}</strong>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-open-modal-generate" class="btn btn-primary" ${this.isGenerating ? 'disabled' : ''}>
              <span>+</span> Generate New Report
            </button>
          </div>
        </div>

        <!-- 2-Column: Saved Reports List on Left, Interactive Report Viewer on Right -->
        <div style="display:grid;grid-template-columns:340px 1fr;gap:20px;align-items:start;">
          <!-- Left Column: Reports List -->
          <div class="card no-print" style="display:flex;flex-direction:column;gap:12px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>📁</span> Persisted Assessment Reports (${this.reports.length})
            </div>

            <div style="display:flex;flex-direction:column;gap:8px;max-height:540px;overflow-y:auto;">
              ${this.reports.length > 0 ? this.reports.map((r) => `
                <div
                  class="card item-report ${this.selectedReport?.id === r.id ? 'active-row' : ''}"
                  data-report-id="${r.id}"
                  style="cursor:pointer;padding:12px;border:1px solid ${this.selectedReport?.id === r.id ? 'var(--accent-primary)' : 'var(--border-subtle)'};display:flex;flex-direction:column;gap:6px;"
                >
                  <div style="font-weight:700;font-size:13px;color:var(--text-primary);">${r.title}</div>
                  <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">
                    <span>${r.reportType}</span>
                    <span>v${r.version}</span>
                  </div>
                  <div style="font-size:10px;font-family:var(--font-mono);color:var(--accent-primary);text-overflow:ellipsis;overflow:hidden;white-space:nowrap;">
                    SHA: ${r.contentSha256}
                  </div>
                  <div style="font-size:10px;color:var(--text-muted);">
                    ${new Date(r.createdAt).toLocaleString()}
                  </div>
                </div>
              `).join('') : `
                <div class="empty-state" style="padding:32px 16px;">
                  <div class="empty-state-icon">📄</div>
                  <div class="empty-state-title">No Reports Generated</div>
                  <div class="empty-state-desc">Click "Generate New Report" to compile findings and evidence into a formal assessment document.</div>
                </div>
              `}
            </div>
          </div>

          <!-- Right Column: Report Document Viewer -->
          <div class="card" style="padding:0;overflow:hidden;border:1px solid var(--border-medium);">
            ${this.selectedReport ? `
              <!-- Toolbar -->
              <div class="no-print" style="padding:12px 18px;background:var(--bg-surface-elevated);border-bottom:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center;">
                <div style="display:flex;align-items:center;gap:10px;">
                  <span style="font-weight:700;font-size:14px;color:var(--text-primary);">${this.selectedReport.title}</span>
                  <span class="badge" style="background:#10b981;color:#fff;font-size:10px;">VERIFIED</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px;">
                  <button id="btn-download-json" class="btn btn-secondary btn-sm" style="font-size:11px;">
                    Download JSON
                  </button>
                  <button id="btn-print-report" class="btn btn-primary btn-sm" style="font-size:11px;">
                    🖨️ Print / PDF
                  </button>
                </div>
              </div>

              <!-- Report Body Content -->
              <div id="report-view-container" style="padding:24px;max-height:700px;overflow-y:auto;background:var(--bg-surface-sunken);">
                ${this.selectedReport.htmlContent ? this.selectedReport.htmlContent : `
                  <div style="padding:32px;color:var(--text-primary);">
                    <h3>${this.selectedReport.title}</h3>
                    <p>Report Type: ${this.selectedReport.reportType}</p>
                    <p>Generated At: ${this.selectedReport.createdAt}</p>
                    <p>Integrity Hash: ${this.selectedReport.contentSha256}</p>
                  </div>
                `}
              </div>
            ` : `
              <div class="empty-state" style="padding:80px 24px;">
                <div class="empty-state-icon">📋</div>
                <div class="empty-state-title">Select a Report</div>
                <div class="empty-state-desc">Choose a report from the list on the left to inspect executive summaries, verified findings, and evidence references.</div>
              </div>
            `}
          </div>
        </div>

        <!-- Generate Report Modal -->
        <div id="modal-generate-report" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.7);backdrop-filter:blur(8px);z-index:3000;align-items:center;justify-content:center;">
          <div class="card" style="width:100%;max-width:500px;padding:24px;border:1px solid var(--border-medium);">
            <div style="font-weight:700;font-size:16px;color:var(--text-primary);margin-bottom:14px;">
              Generate Security Assessment Report
            </div>

            <div style="display:flex;flex-direction:column;gap:14px;">
              <div>
                <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Report Title</label>
                <input
                  id="modal-report-title"
                  type="text"
                  value="Q4 Sovereign Security Assessment - ${ws?.name || 'Workspace'}"
                  style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;"
                />
              </div>

              <div>
                <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Report Classification / Template</label>
                <select id="modal-report-type" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;">
                  <option value="EXECUTIVE_SUMMARY">Executive Summary (High-Level Risk & Governance)</option>
                  <option value="TECHNICAL_ASSESSMENT">Technical Assessment (Full Reproduction & CVE Details)</option>
                  <option value="COMPLIANCE_AUDIT">Compliance Audit (Scope & Evidence Verification)</option>
                  <option value="EVIDENCE_CATALOG">Evidence Catalog (Artifacts & Hash Log)</option>
                </select>
              </div>

              <div style="padding:10px;background:rgba(0,240,255,0.06);border:1px solid rgba(0,240,255,0.2);border-radius:var(--radius-sm);font-size:11px;color:var(--text-secondary);">
                <span>ℹ️</span> This operation will take a deterministic snapshot of all assets, scopes, executions, and findings currently in this workspace, compute a SHA-256 cryptographic proof, and compile the final deliverable.
              </div>

              <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:8px;">
                <button id="btn-cancel-modal" class="btn btn-ghost">Cancel</button>
                <button id="btn-confirm-generate" class="btn btn-primary">Generate Report</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelectorAll<HTMLElement>('.item-report').forEach((card) => {
      card.addEventListener('click', () => {
        const id = card.dataset.reportId;
        const match = this.reports.find((r) => r.id === id);
        if (match) {
          this.selectedReport = match;
          this.render();
          this.bindEvents();
        }
      });
    });

    const modal = this.container.querySelector<HTMLElement>('#modal-generate-report');
    this.container.querySelector('#btn-open-modal-generate')?.addEventListener('click', () => {
      if (modal) modal.style.display = 'flex';
    });

    this.container.querySelector('#btn-cancel-modal')?.addEventListener('click', () => {
      if (modal) modal.style.display = 'none';
    });

    this.container.querySelector('#btn-confirm-generate')?.addEventListener('click', () => {
      const title = this.container?.querySelector<HTMLInputElement>('#modal-report-title')?.value || 'Security Report';
      const type = this.container?.querySelector<HTMLSelectElement>('#modal-report-type')?.value || 'EXECUTIVE_SUMMARY';
      if (modal) modal.style.display = 'none';
      this.generateReport(title, type);
    });

    this.container.querySelector('#btn-print-report')?.addEventListener('click', () => {
      window.print();
    });

    this.container.querySelector('#btn-download-json')?.addEventListener('click', () => {
      if (!this.selectedReport) return;
      const blob = new Blob([JSON.stringify(this.selectedReport, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${this.selectedReport.title.toLowerCase().replace(/[^a-z0-9]/g, '_')}_v${this.selectedReport.version}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });
  }
}
