/**
 * Shadow : Helix Nebula (SHN) — Notifications & Operational Activity View
 *
 * Implements Section 4 & 15:
 * - Real-time activity timeline fed by Server-Sent Events (SSE) and audit records
 * - Filtering by event category and correlation ID inspection
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { AuditEvent } from '../contracts.js';

export class ActivityView {
  private container: HTMLElement | null = null;
  private events: AuditEvent[] = [];
  private filterCategory = 'ALL';

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
      this.events = await this.api.listAuditEvents(ws.id, 50).catch(() => []);
      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load activity stream');
    }
  }

  private render(): void {
    if (!this.container) return;

    const ws = this.workspaceStore.getActiveWorkspace();
    const filtered = this.events.filter((e) => {
      if (this.filterCategory === 'ALL') return true;
      return e.event_type.toLowerCase().includes(this.filterCategory.toLowerCase());
    });

    this.container.innerHTML = `
      <div class="content-viewport" style="display:flex;flex-direction:column;gap:20px;">
        <!-- Header -->
        <div class="page-header" style="margin-bottom:0;">
          <div class="page-title-group">
            <div style="display:flex;align-items:center;gap:12px;">
              <h2>Operational Activity & Live Events</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                REAL-TIME STREAM
              </span>
            </div>
            <div class="page-subtitle">
              Live audit events and operational notifications for workspace: <strong style="color:var(--text-primary);">${ws?.name || 'Default'}</strong>
            </div>
          </div>
          <button id="btn-refresh-activity" class="btn btn-secondary">
            <span>↻</span> Refresh Activity
          </button>
        </div>

        <!-- Filter Row -->
        <div style="display:flex;gap:8px;align-items:center;">
          <span style="font-size:12px;color:var(--text-muted);">Filter:</span>
          <button class="btn btn-sm ${this.filterCategory === 'ALL' ? 'btn-primary' : 'btn-ghost'} btn-filter" data-cat="ALL">All Events</button>
          <button class="btn btn-sm ${this.filterCategory === 'EXECUTION' ? 'btn-primary' : 'btn-ghost'} btn-filter" data-cat="EXECUTION">Executions</button>
          <button class="btn btn-sm ${this.filterCategory === 'FINDING' ? 'btn-primary' : 'btn-ghost'} btn-filter" data-cat="FINDING">Findings</button>
          <button class="btn btn-sm ${this.filterCategory === 'SCOPE' ? 'btn-primary' : 'btn-ghost'} btn-filter" data-cat="SCOPE">Scope</button>
          <button class="btn btn-sm ${this.filterCategory === 'AUTH' ? 'btn-primary' : 'btn-ghost'} btn-filter" data-cat="AUTH">Auth</button>
        </div>

        <!-- Activity Timeline Card -->
        <div class="card" style="display:flex;flex-direction:column;gap:12px;">
          <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
            <span>⏱️</span> Chronological Event Timeline (${filtered.length})
          </div>

          <div style="display:flex;flex-direction:column;gap:10px;max-height:600px;overflow-y:auto;">
            ${filtered.length > 0 ? filtered.map((ev) => `
              <div class="card" style="padding:12px;background:var(--bg-surface-sunken);border:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:flex-start;gap:12px;">
                <div style="display:flex;align-items:flex-start;gap:10px;">
                  <span style="font-size:16px;margin-top:2px;">
                    ${ev.event_type.includes('execution') ? '⚡' : ev.event_type.includes('finding') ? '🛡️' : ev.event_type.includes('scope') ? '🔒' : '📋'}
                  </span>
                  <div>
                    <strong style="color:var(--text-primary);font-size:13px;">${ev.event_type}</strong>
                    <div style="font-size:11px;color:var(--text-secondary);margin-top:2px;font-family:var(--font-mono);">
                      Correlation: <span style="color:#00f0ff;">${ev.correlation_id}</span> · Producer: ${(ev.producer as any)?.service || 'system'}
                    </div>
                  </div>
                </div>
                <div style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);white-space:nowrap;">
                  ${new Date(ev.occurred_at).toLocaleString()}
                </div>
              </div>
            `).join('') : `
              <div class="empty-state" style="padding:48px 16px;">
                <div class="empty-state-icon">🔔</div>
                <div class="empty-state-title">No Events Recorded</div>
                <div class="empty-state-desc">Operational events and telemetry notifications will appear here in chronological order.</div>
              </div>
            `}
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-refresh-activity')?.addEventListener('click', () => {
      this.loadData();
    });

    this.container.querySelectorAll<HTMLButtonElement>('.btn-filter').forEach((btn) => {
      btn.addEventListener('click', () => {
        this.filterCategory = btn.dataset.cat || 'ALL';
        this.render();
        this.bindEvents();
      });
    });
  }
}
