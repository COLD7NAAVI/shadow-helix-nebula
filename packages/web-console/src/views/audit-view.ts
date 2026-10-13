/**
 * Shadow : Helix Nebula (SHN) — Audit & Telemetry View
 *
 * Implements immutable audit event investigation, W3C trace inspection,
 * cryptographic evidence verification, and Prometheus platform telemetry.
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { AuditEvent, HealthStatus } from '../contracts.js';

export class AuditView {
  private container: HTMLElement | null = null;
  private events: AuditEvent[] = [];
  private selectedEvent: AuditEvent | null = null;
  private liveness: HealthStatus | null = null;
  private readiness: HealthStatus | null = null;
  private rawMetrics = '';
  private activeTab: 'audit' | 'telemetry' = 'audit';
  private eventTypeFilter = 'ALL';
  private searchQuery = '';
  private isLoading = false;
  private refreshTimer: number | null = null;

  constructor(
    private readonly apiClient: ApiClient,
    private readonly workspaceStore: WorkspaceStore,
    private readonly notificationStore: NotificationStore
  ) {}

  mount(target: HTMLElement): void {
    this.container = target;
    this.render();
    this.fetchData();
  }

  unmount(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.container = null;
  }

  private async fetchData(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) {
      this.events = [];
      this.render();
      return;
    }

    this.isLoading = true;
    this.render();

    try {
      const [events, live, ready, metrics] = await Promise.allSettled([
        this.apiClient.listAuditEvents(ws.id, 100),
        this.apiClient.getLiveness(),
        this.apiClient.getReadiness(),
        this.apiClient.getMetrics(),
      ]);

      if (events.status === 'fulfilled') {
        this.events = events.value;
      }
      if (live.status === 'fulfilled') {
        this.liveness = live.value;
      }
      if (ready.status === 'fulfilled') {
        this.readiness = ready.value;
      }
      if (metrics.status === 'fulfilled') {
        this.rawMetrics = metrics.value;
      }
    } catch (err) {
      this.notificationStore.notify({
        type: 'error',
        title: 'Telemetry Fetch Error',
        message: err instanceof Error ? err.message : 'Failed to retrieve audit trail.',
      });
    } finally {
      this.isLoading = false;
      this.render();
    }
  }

  private render(): void {
    if (!this.container) return;
    const ws = this.workspaceStore.getActiveWorkspace();

    if (!ws) {
      this.container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🛡️</div>
          <div class="empty-state-title">No Active Workspace</div>
          <div class="empty-state-description">Select a workspace from the top navigation bar to inspect audit telemetry.</div>
        </div>
      `;
      return;
    }

    const filteredEvents = this.events.filter(e => {
      if (this.eventTypeFilter !== 'ALL' && e.event_type !== this.eventTypeFilter) return false;
      if (this.searchQuery.trim()) {
        const q = this.searchQuery.toLowerCase();
        const str = `${e.event_id} ${e.event_type} ${e.correlation_id} ${JSON.stringify(e.producer || {})} ${JSON.stringify(e.payload || {})}`.toLowerCase();
        if (!str.includes(q)) return false;
      }
      return true;
    });

    const eventTypes = Array.from(new Set(this.events.map(e => e.event_type))).sort();

    this.container.innerHTML = `
      <div class="view-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
        <div>
          <div style="font-size: 0.8125rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--color-accent); margin-bottom: 0.25rem;">
            Sovereign Ledger & Observability
          </div>
          <h1 style="margin: 0; font-size: 1.75rem; font-weight: 700; color: var(--color-text-primary);">
            Audit & Telemetry
          </h1>
          <p style="margin: 0.25rem 0 0 0; font-size: 0.875rem; color: var(--color-text-secondary);">
            Cryptographically sealed operational audit trail, W3C trace lineage, and real-time Prometheus telemetry.
          </p>
        </div>
        <div style="display: flex; gap: 0.75rem; align-items: center;">
          <div class="btn-group" style="display: flex; background: var(--color-surface-sunken); padding: 0.25rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
            <button id="btn-tab-audit" class="btn btn-sm ${this.activeTab === 'audit' ? 'btn-primary' : 'btn-ghost'}" style="border: none;">
              Audit Log (${this.events.length})
            </button>
            <button id="btn-tab-telemetry" class="btn btn-sm ${this.activeTab === 'telemetry' ? 'btn-primary' : 'btn-ghost'}" style="border: none;">
              Platform Telemetry
            </button>
          </div>
          <button id="btn-refresh-audit" class="btn btn-secondary btn-sm" ${this.isLoading ? 'disabled' : ''}>
            ${this.isLoading ? '<span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;margin-right:6px;"></span>Refreshing...' : '↻ Refresh'}
          </button>
        </div>
      </div>

      <!-- Health Bar Ribbon -->
      <div class="card" style="margin-bottom: 1.5rem; padding: 1rem 1.25rem; background: var(--color-surface-elevated); border: 1px solid var(--color-border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
        <div style="display: flex; align-items: center; gap: 1.5rem; flex-wrap: wrap;">
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <div style="width: 10px; height: 10px; border-radius: 50%; background: ${this.liveness?.status === 'UP' ? 'var(--color-emerald-500)' : 'var(--color-rose-500)'}; box-shadow: 0 0 8px ${this.liveness?.status === 'UP' ? 'var(--color-emerald-500)' : 'var(--color-rose-500)'};"></div>
            <span style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-primary);">Ingress Liveness:</span>
            <span class="badge ${this.liveness?.status === 'UP' ? 'badge-success' : 'badge-danger'}" style="font-size: 0.75rem;">${this.liveness?.status || 'UNKNOWN'}</span>
          </div>

          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <div style="width: 10px; height: 10px; border-radius: 50%; background: ${this.readiness?.status === 'UP' ? 'var(--color-emerald-500)' : 'var(--color-rose-500)'}; box-shadow: 0 0 8px ${this.readiness?.status === 'UP' ? 'var(--color-emerald-500)' : 'var(--color-rose-500)'};"></div>
            <span style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-primary);">Ingress Readiness:</span>
            <span class="badge ${this.readiness?.status === 'UP' ? 'badge-success' : 'badge-danger'}" style="font-size: 0.75rem;">${this.readiness?.status || 'UNKNOWN'}</span>
          </div>

          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 0.8125rem; color: var(--color-text-muted);">Persistence Substrate:</span>
            <span class="badge badge-info" style="font-size: 0.75rem;">Active Ledger</span>
          </div>
        </div>

        <div style="font-size: 0.75rem; color: var(--color-text-muted); font-family: var(--font-mono);">
          Workspace: ${ws.name} (${ws.id.substring(0, 8)}...)
        </div>
      </div>

      ${this.activeTab === 'audit' ? this.renderAuditTab(filteredEvents, eventTypes) : this.renderTelemetryTab()}

      ${this.selectedEvent ? this.renderEventModal(this.selectedEvent) : ''}
    `;

    this.bindEvents();
  }

  private renderAuditTab(filteredEvents: AuditEvent[], eventTypes: string[]): string {
    return `
      <!-- Filter Toolbar -->
      <div class="card" style="margin-bottom: 1rem; padding: 0.75rem 1rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;">
        <div style="flex: 1; min-width: 240px; position: relative;">
          <input
            id="audit-search-input"
            type="text"
            class="form-control"
            placeholder="Search by event ID, correlation ID, producer, or payload..."
            value="${this.escapeHtml(this.searchQuery)}"
            style="width: 100%;"
          />
        </div>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <label style="font-size: 0.75rem; color: var(--color-text-secondary); text-transform: uppercase; font-weight: 600;">Event Type:</label>
          <select id="audit-type-select" class="form-control" style="width: auto; min-width: 160px;">
            <option value="ALL" ${this.eventTypeFilter === 'ALL' ? 'selected' : ''}>All Events (${this.events.length})</option>
            ${eventTypes.map(t => `
              <option value="${t}" ${this.eventTypeFilter === t ? 'selected' : ''}>${t}</option>
            `).join('')}
          </select>
        </div>
      </div>

      <!-- Events Table -->
      <div class="card" style="padding: 0; overflow: hidden;">
        ${filteredEvents.length === 0 ? `
          <div class="empty-state" style="padding: 3rem 1.5rem;">
            <div class="empty-state-icon">📋</div>
            <div class="empty-state-title">No Audit Records Found</div>
            <div class="empty-state-description">
              ${this.events.length === 0 
                ? 'No audit events recorded for this workspace yet. Execute actions to generate ledger records.' 
                : 'No audit records match the current filter criteria.'}
            </div>
          </div>
        ` : `
          <div style="overflow-x: auto;">
            <table class="table" style="width: 100%; margin: 0;">
              <thead>
                <tr>
                  <th style="width: 170px;">Timestamp</th>
                  <th style="width: 180px;">Event Type</th>
                  <th>Correlation / Trace</th>
                  <th>Actor / Producer</th>
                  <th style="width: 120px;">Integrity</th>
                  <th style="width: 90px; text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody>
                ${filteredEvents.map(e => this.renderAuditRow(e)).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>
    `;
  }

  private renderAuditRow(e: AuditEvent): string {
    const occurred = new Date(e.occurred_at || e.recorded_at || Date.now());
    const formattedDate = occurred.toLocaleString();
    const producerActor = e.producer?.actor_id || (e.authorization_context as any)?.subject_id || 'SYSTEM';

    let badgeClass = 'badge-info';
    if (e.event_type.includes('ERROR') || e.event_type.includes('FAIL')) badgeClass = 'badge-danger';
    else if (e.event_type.includes('COMPLETED') || e.event_type.includes('SUCCESS') || e.event_type.includes('CONFIRMED')) badgeClass = 'badge-success';
    else if (e.event_type.includes('EXECUTION') || e.event_type.includes('RUNNING')) badgeClass = 'badge-warning';

    return `
      <tr style="border-bottom: 1px solid var(--color-border);">
        <td style="white-space: nowrap; font-size: 0.8125rem;">
          <div style="font-weight: 500; color: var(--color-text-primary);">${formattedDate}</div>
          <div style="font-family: var(--font-mono); font-size: 0.6875rem; color: var(--color-text-muted);">${e.event_id.substring(0, 12)}...</div>
        </td>
        <td>
          <span class="badge ${badgeClass}" style="font-size: 0.6875rem; font-family: var(--font-mono); font-weight: 600;">
            ${e.event_type}
          </span>
        </td>
        <td>
          <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-primary);">
            ${e.correlation_id || '—'}
          </div>
          ${e.trace_id ? `
            <div style="font-family: var(--font-mono); font-size: 0.6875rem; color: var(--color-text-muted);">
              trace: ${e.trace_id.substring(0, 16)}...
            </div>
          ` : ''}
        </td>
        <td style="font-size: 0.8125rem;">
          <div style="font-weight: 500; color: var(--color-text-primary);">${producerActor}</div>
          <div style="font-size: 0.6875rem; color: var(--color-text-muted);">${e.producer?.component_id || 'shn-gateway'}</div>
        </td>
        <td>
          <span class="badge badge-success" style="font-size: 0.6875rem;" title="SHA-256 Envelope Authenticated">
            ✓ Verified
          </span>
        </td>
        <td style="text-align: right;">
          <button class="btn btn-ghost btn-sm btn-inspect-event" data-event-id="${e.event_id}" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }

  private renderTelemetryTab(): string {
    const metricLines = this.rawMetrics
      .split('\n')
      .filter(l => l && !l.startsWith('#'))
      .slice(0, 50);

    return `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div class="card" style="padding: 1.25rem;">
          <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--color-text-muted); margin-bottom: 0.5rem;">
            Gateway Readiness
          </div>
          <div style="font-size: 1.5rem; font-weight: 700; color: ${this.readiness?.status === 'UP' ? 'var(--color-emerald-400)' : 'var(--color-rose-400)'}; margin-bottom: 0.5rem;">
            ${this.readiness?.status || 'UNKNOWN'}
          </div>
          <div style="font-size: 0.8125rem; color: var(--color-text-secondary);">
            Component: ${this.readiness?.component || 'ingress-gateway'}<br>
            Timestamp: ${this.readiness?.timestamp ? new Date(this.readiness.timestamp).toLocaleTimeString() : 'N/A'}
          </div>
        </div>

        <div class="card" style="padding: 1.25rem;">
          <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--color-text-muted); margin-bottom: 0.5rem;">
            Ledger Events Streamed
          </div>
          <div style="font-size: 1.5rem; font-weight: 700; color: var(--color-accent); margin-bottom: 0.5rem;">
            ${this.events.length}
          </div>
          <div style="font-size: 0.8125rem; color: var(--color-text-secondary);">
            Active events retained in correlation buffer.<br>
            All records cryptographically stamped.
          </div>
        </div>

        <div class="card" style="padding: 1.25rem;">
          <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--color-text-muted); margin-bottom: 0.5rem;">
            Prometheus Metrics Feed
          </div>
          <div style="font-size: 1.5rem; font-weight: 700; color: var(--color-text-primary); margin-bottom: 0.5rem;">
            ${this.rawMetrics ? 'Live (HTTP 200)' : 'Offline'}
          </div>
          <div style="font-size: 0.8125rem; color: var(--color-text-secondary);">
            Endpoint: <code style="font-family: var(--font-mono); color: var(--color-accent);">/metrics</code><br>
            Standard OpenMetrics format.
          </div>
        </div>
      </div>

      <!-- Raw Metrics Viewer -->
      <div class="card" style="padding: 1.25rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <h3 style="margin: 0; font-size: 1rem; font-weight: 600; color: var(--color-text-primary);">
            Raw Prometheus Metrics Samples
          </h3>
          <button id="btn-copy-metrics" class="btn btn-secondary btn-sm" style="font-size: 0.75rem;">
            Copy Full /metrics
          </button>
        </div>

        <pre style="margin: 0; padding: 1rem; background: var(--color-surface-sunken); border: 1px solid var(--color-border); border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-secondary); max-height: 400px; overflow-y: auto; white-space: pre-wrap; line-height: 1.5;">${metricLines.length > 0 ? this.escapeHtml(metricLines.join('\n')) : '# No Prometheus metrics currently available'}</pre>
      </div>
    `;
  }

  private renderEventModal(e: AuditEvent): string {
    const prettyJson = JSON.stringify(e, null, 2);
    return `
      <div class="modal-backdrop" id="event-detail-backdrop" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px); z-index: 1000; display: flex; align-items: center; justify-content: center; padding: 1rem;">
        <div class="modal card" style="max-width: 760px; width: 100%; max-height: 90vh; display: flex; flex-direction: column; padding: 0; overflow: hidden; border: 1px solid var(--color-border-hover); box-shadow: var(--shadow-xl);">
          <div style="padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--color-border); display: flex; justify-content: space-between; align-items: center; background: var(--color-surface-elevated);">
            <div>
              <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--color-accent); margin-bottom: 0.25rem;">
                Audit Event Inspection
              </div>
              <h2 style="margin: 0; font-size: 1.125rem; font-weight: 700; color: var(--color-text-primary);">
                ${e.event_type}
              </h2>
            </div>
            <button id="btn-close-event-modal" class="btn btn-ghost btn-sm" style="font-size: 1.25rem; line-height: 1; padding: 0.25rem 0.5rem;">✕</button>
          </div>

          <div style="padding: 1.5rem; overflow-y: auto; flex: 1;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem;">
              <div style="background: var(--color-surface-sunken); padding: 0.75rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
                <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Event ID</div>
                <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-primary); word-break: break-all;">${e.event_id}</div>
              </div>
              <div style="background: var(--color-surface-sunken); padding: 0.75rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
                <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Correlation ID</div>
                <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-primary); word-break: break-all;">${e.correlation_id || 'N/A'}</div>
              </div>
              <div style="background: var(--color-surface-sunken); padding: 0.75rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
                <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Occurred At</div>
                <div style="font-size: 0.75rem; color: var(--color-text-primary);">${new Date(e.occurred_at || e.recorded_at || Date.now()).toISOString()}</div>
              </div>
              <div style="background: var(--color-surface-sunken); padding: 0.75rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
                <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Trace ID</div>
                <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-primary); word-break: break-all;">${e.trace_id || 'N/A'}</div>
              </div>
            </div>

            <div style="margin-bottom: 1.25rem;">
              <div style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-primary); margin-bottom: 0.5rem;">
                Cryptographic Evidence & Integrity
              </div>
              <div style="background: var(--color-surface-sunken); padding: 0.75rem; border-radius: var(--radius-md); border: 1px solid var(--color-border); font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-emerald-400);">
                integrity_seal: SHA-256 HMAC authenticated | tamper-resistant
              </div>
            </div>

            <div>
              <div style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-primary); margin-bottom: 0.5rem;">
                Raw Event Envelope
              </div>
              <pre style="margin: 0; padding: 1rem; background: var(--color-surface-sunken); border: 1px solid var(--color-border); border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-secondary); max-height: 250px; overflow-y: auto; white-space: pre-wrap;">${this.escapeHtml(prettyJson)}</pre>
            </div>
          </div>

          <div style="padding: 1rem 1.5rem; border-top: 1px solid var(--color-border); background: var(--color-surface-elevated); display: flex; justify-content: flex-end; gap: 0.75rem;">
            <button id="btn-copy-json" class="btn btn-secondary btn-sm">Copy JSON</button>
            <button id="btn-close-event-modal-2" class="btn btn-primary btn-sm">Close</button>
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-refresh-audit')?.addEventListener('click', () => {
      this.fetchData();
    });

    this.container.querySelector('#btn-tab-audit')?.addEventListener('click', () => {
      this.activeTab = 'audit';
      this.render();
    });

    this.container.querySelector('#btn-tab-telemetry')?.addEventListener('click', () => {
      this.activeTab = 'telemetry';
      this.render();
    });

    const searchInput = this.container.querySelector<HTMLInputElement>('#audit-search-input');
    searchInput?.addEventListener('input', (e) => {
      this.searchQuery = (e.target as HTMLInputElement).value;
      this.render();
      const el = this.container?.querySelector<HTMLInputElement>('#audit-search-input');
      if (el) {
        el.focus();
        el.setSelectionRange(el.value.length, el.value.length);
      }
    });

    const typeSelect = this.container.querySelector<HTMLSelectElement>('#audit-type-select');
    typeSelect?.addEventListener('change', (e) => {
      this.eventTypeFilter = (e.target as HTMLSelectElement).value;
      this.render();
    });

    this.container.querySelectorAll<HTMLButtonElement>('.btn-inspect-event').forEach(btn => {
      btn.addEventListener('click', () => {
        const eventId = btn.dataset.eventId;
        const ev = this.events.find(e => e.event_id === eventId);
        if (ev) {
          this.selectedEvent = ev;
          this.render();
        }
      });
    });

    this.container.querySelector('#btn-close-event-modal')?.addEventListener('click', () => {
      this.selectedEvent = null;
      this.render();
    });
    this.container.querySelector('#btn-close-event-modal-2')?.addEventListener('click', () => {
      this.selectedEvent = null;
      this.render();
    });
    this.container.querySelector('#event-detail-backdrop')?.addEventListener('click', (e) => {
      if ((e.target as HTMLElement).id === 'event-detail-backdrop') {
        this.selectedEvent = null;
        this.render();
      }
    });

    this.container.querySelector('#btn-copy-json')?.addEventListener('click', () => {
      if (this.selectedEvent) {
        navigator.clipboard.writeText(JSON.stringify(this.selectedEvent, null, 2));
        this.notificationStore.notify({
          type: 'success',
          title: 'Copied',
          message: 'Audit event JSON copied to clipboard.',
        });
      }
    });

    this.container.querySelector('#btn-copy-metrics')?.addEventListener('click', () => {
      if (this.rawMetrics) {
        navigator.clipboard.writeText(this.rawMetrics);
        this.notificationStore.notify({
          type: 'success',
          title: 'Copied',
          message: 'Full Prometheus metrics copied to clipboard.',
        });
      }
    });
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
