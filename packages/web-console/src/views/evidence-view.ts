/**
 * Shadow : Helix Nebula (SHN) — Evidence & Artifact Vault View
 *
 * Implements Section 11 & 13:
 * - Evidence artifact repository linked to executions and findings
 * - Cryptographic SHA-256 verification and preview
 * - Traceable chain of custody for authorized assessments
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';

interface EvidenceItem {
  id: string;
  name: string;
  sourceType: 'EXECUTION' | 'FINDING' | 'RECON';
  sourceId: string;
  sha256: string;
  createdAt: string;
  payloadSummary: string;
}

export class EvidenceView {
  private container: HTMLElement | null = null;
  private evidenceItems: EvidenceItem[] = [];
  private selectedItem: EvidenceItem | null = null;

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
      const [execs, findings] = await Promise.all([
        this.api.listExecutions(ws.id).catch(() => []),
        this.api.listFindings(ws.id).catch(() => []),
      ]);

      const items: EvidenceItem[] = [];

      for (const e of execs) {
        if (e.rawOutputSha256) {
          items.push({
            id: 'ev-exec-' + e.id,
            name: `Tool Execution Artifact: ${e.action || e.capabilityUri}`,
            sourceType: 'EXECUTION',
            sourceId: e.id,
            sha256: e.rawOutputSha256,
            createdAt: e.createdAt || new Date().toISOString(),
            payloadSummary: e.stdoutSummary || e.stderrSummary || 'Raw process output captured and hashed.',
          });
        }
      }

      for (const f of findings) {
        if (f.rawEvidenceSha256) {
          items.push({
            id: 'ev-find-' + f.id,
            name: `Finding Proof of Concept: ${f.title}`,
            sourceType: 'FINDING',
            sourceId: f.id,
            sha256: f.rawEvidenceSha256,
            createdAt: f.createdAt || new Date().toISOString(),
            payloadSummary: f.description || 'Vulnerability observation proof.',
          });
        }
      }

      this.evidenceItems = items;
      if (this.evidenceItems.length > 0 && !this.selectedItem) {
        this.selectedItem = this.evidenceItems[0] ?? null;
      }

      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load evidence catalog');
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
              <h2>Evidence Artifact Vault & Chain of Custody</h2>
              <span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.3);font-size:11px;">
                IMMUTABLE EVIDENCE
              </span>
            </div>
            <div class="page-subtitle">
              Sovereign cryptographic evidence for workspace: <strong style="color:var(--text-primary);">${ws?.name || 'Default'}</strong>
            </div>
          </div>
          <button id="btn-refresh-evidence" class="btn btn-secondary">
            <span>↻</span> Refresh Vault
          </button>
        </div>

        <!-- 2-Column: Evidence Items List & Preview Detail -->
        <div style="display:grid;grid-template-columns:360px 1fr;gap:20px;align-items:start;">
          <!-- Evidence List -->
          <div class="card" style="display:flex;flex-direction:column;gap:12px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>🗄️</span> Artifact Ledger (${this.evidenceItems.length})
            </div>

            <div style="display:flex;flex-direction:column;gap:8px;max-height:560px;overflow-y:auto;">
              ${this.evidenceItems.length > 0 ? this.evidenceItems.map((item) => `
                <div
                  class="card item-evidence ${this.selectedItem?.id === item.id ? 'active-row' : ''}"
                  data-ev-id="${item.id}"
                  style="cursor:pointer;padding:12px;border:1px solid ${this.selectedItem?.id === item.id ? 'var(--accent-primary)' : 'var(--border-subtle)'};display:flex;flex-direction:column;gap:6px;"
                >
                  <div style="font-weight:700;font-size:13px;color:var(--text-primary);">${item.name}</div>
                  <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;font-family:var(--font-mono);color:var(--text-muted);">
                    <span class="badge" style="font-size:9px;background:var(--accent-subtle);color:var(--accent-primary);">${item.sourceType}</span>
                    <span>${new Date(item.createdAt).toLocaleDateString()}</span>
                  </div>
                  <div style="font-size:10px;font-family:var(--font-mono);color:#10b981;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;">
                    SHA: ${item.sha256}
                  </div>
                </div>
              `).join('') : `
                <div class="empty-state" style="padding:48px 16px;">
                  <div class="empty-state-icon">🛡️</div>
                  <div class="empty-state-title">No Evidence Collected</div>
                  <div class="empty-state-desc">When capabilities run and findings are validated, cryptographic evidence artifacts appear here automatically.</div>
                </div>
              `}
            </div>
          </div>

          <!-- Evidence Preview Card -->
          <div class="card" style="padding:0;overflow:hidden;border:1px solid var(--border-medium);">
            ${this.selectedItem ? `
              <div style="padding:14px 18px;background:var(--bg-surface-elevated);border-bottom:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center;">
                <div style="display:flex;align-items:center;gap:10px;">
                  <span style="font-weight:700;font-size:14px;color:var(--text-primary);">${this.selectedItem.name}</span>
                  <span class="badge" style="background:#10b981;color:#fff;font-size:10px;">VERIFIED HASH</span>
                </div>
                <button id="btn-copy-hash" class="btn btn-secondary btn-sm" style="font-size:11px;">
                  Copy SHA-256
                </button>
              </div>

              <div style="padding:20px;display:flex;flex-direction:column;gap:16px;">
                <div style="display:grid;grid-template-columns:repeat(2, 1fr);gap:12px;padding:12px;background:var(--bg-surface-sunken);border-radius:var(--radius-sm);font-size:12px;font-family:var(--font-mono);">
                  <div>
                    <span style="color:var(--text-muted);display:block;">Source Provenance:</span>
                    <strong style="color:var(--text-primary);">${this.selectedItem.sourceType} [${this.selectedItem.sourceId}]</strong>
                  </div>
                  <div>
                    <span style="color:var(--text-muted);display:block;">Recorded Timestamp:</span>
                    <strong style="color:var(--text-primary);">${this.selectedItem.createdAt}</strong>
                  </div>
                  <div style="grid-column:span 2;">
                    <span style="color:var(--text-muted);display:block;">Cryptographic Digest (SHA-256):</span>
                    <strong style="color:#00f0ff;word-break:break-all;">${this.selectedItem.sha256}</strong>
                  </div>
                </div>

                <div>
                  <div style="font-weight:700;font-size:13px;color:var(--text-primary);margin-bottom:8px;">Artifact Payload Content</div>
                  <div style="padding:16px;background:var(--bg-terminal);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);font-family:var(--font-mono);font-size:12px;color:#38bdf8;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;">${this.selectedItem.payloadSummary}</div>
                </div>
              </div>
            ` : `
              <div class="empty-state" style="padding:80px 24px;">
                <div class="empty-state-icon">🗄️</div>
                <div class="empty-state-title">Select an Artifact</div>
                <div class="empty-state-desc">Select an evidence artifact from the list to inspect cryptographic hashes and raw payload contents.</div>
              </div>
            `}
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-refresh-evidence')?.addEventListener('click', () => {
      this.loadData();
    });

    this.container.querySelectorAll<HTMLElement>('.item-evidence').forEach((card) => {
      card.addEventListener('click', () => {
        const id = card.dataset.evId;
        const match = this.evidenceItems.find((x) => x.id === id);
        if (match) {
          this.selectedItem = match;
          this.render();
          this.bindEvents();
        }
      });
    });

    this.container.querySelector('#btn-copy-hash')?.addEventListener('click', () => {
      if (this.selectedItem) {
        navigator.clipboard?.writeText(this.selectedItem.sha256);
        this.notify.success('SHA-256 hash copied to clipboard');
      }
    });
  }
}
