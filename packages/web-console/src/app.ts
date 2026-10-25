/**
 * Shadow : Helix Nebula (SHN) — Application Shell & Master Orchestrator
 *
 * Implements the responsive sovereign application shell: collapsible sidebar,
 * top navigation bar, workspace switcher, command palette (Ctrl+K),
 * notification center, live health status pulse, and view routing.
 */

import type { ApiClient } from './services/api-client.js';
import type { AuthStore, AuthState } from './state/auth-store.js';
import type { WorkspaceStore, WorkspaceState } from './state/workspace-store.js';
import type { SettingsStore } from './state/settings-store.js';
import type { NotificationStore, ToastMessage } from './state/notification-store.js';
import type { Router, RouteMatch, RouteId } from './router.js';

import { renderLoginView } from './views/login-view.js';
import { renderDashboardView } from './views/dashboard-view.js';
import { renderWorkspacesView } from './views/workspaces-view.js';
import { renderAssetsView } from './views/assets-view.js';
import { renderCapabilitiesView } from './views/capabilities-view.js';
import { renderExecutionsView } from './views/executions-view.js';
import { renderFindingsView } from './views/findings-view.js';
import { AuditView } from './views/audit-view.js';
import { SettingsView } from './views/settings-view.js';
import { GraphView } from './views/graph-view.js';
import { TerminalView } from './views/terminal-view.js';
import { AiAssistantView } from './views/ai-assistant-view.js';
import { AiProvidersView } from './views/ai-providers-view.js';
import { ReportsView } from './views/reports-view.js';
import { EvidenceView } from './views/evidence-view.js';
import { WorkflowsView } from './views/workflows-view.js';
import { ReconView } from './views/recon-view.js';
import { ScansView } from './views/scans-view.js';
import { ActivityView } from './views/activity-view.js';

interface ViewWithUnmount {
  mount(target: HTMLElement): void;
  unmount(): void;
}

export class AppShell {
  private currentViewInstance: ViewWithUnmount | null = null;
  private isSidebarCollapsed = false;
  private isCommandPaletteOpen = false;
  private isNotificationsOpen = false;
  private isWorkspaceMenuOpen = false;
  private isUserMenuOpen = false;
  private healthInterval: number | null = null;
  private isHealthy = true;
  private streamUnsubscribe: (() => void) | null = null;

  private readonly auditView: AuditView;
  private readonly settingsView: SettingsView;
  private readonly graphView: GraphView;
  private readonly terminalView: TerminalView;
  private readonly aiAssistantView: AiAssistantView;
  private readonly aiProvidersView: AiProvidersView;
  private readonly reportsView: ReportsView;
  private readonly evidenceView: EvidenceView;
  private readonly workflowsView: WorkflowsView;
  private readonly reconView: ReconView;
  private readonly scansView: ScansView;
  private readonly activityView: ActivityView;

  constructor(
    private readonly root: HTMLElement,
    private readonly apiClient: ApiClient,
    private readonly authStore: AuthStore,
    private readonly workspaceStore: WorkspaceStore,
    private readonly settingsStore: SettingsStore,
    private readonly notificationStore: NotificationStore,
    private readonly router: Router
  ) {
    this.auditView = new AuditView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.settingsView = new SettingsView(this.settingsStore, this.authStore, this.notificationStore);
    this.graphView = new GraphView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.terminalView = new TerminalView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.aiAssistantView = new AiAssistantView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.aiProvidersView = new AiProvidersView(this.apiClient, this.notificationStore);
    this.reportsView = new ReportsView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.evidenceView = new EvidenceView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.workflowsView = new WorkflowsView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.reconView = new ReconView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.scansView = new ScansView(this.apiClient, this.workspaceStore, this.notificationStore);
    this.activityView = new ActivityView(this.apiClient, this.workspaceStore, this.notificationStore);
  }

  init(): void {
    this.settingsStore.setApiClient(this.apiClient);
    this.authStore.subscribe((state) => this.handleAuthState(state));
    this.workspaceStore.subscribe((state) => this.handleWorkspaceState(state));
    this.notificationStore.subscribe((toasts) => this.renderToasts(toasts));
    this.router.subscribe((match) => this.handleRouteChange(match));

    this.initKeyboardShortcuts();
    this.startHealthPolling();
    this.router.start();
  }

  private handleAuthState(state: AuthState): void {
    if (!state.isAuthenticated) {
      if (this.streamUnsubscribe) {
        this.streamUnsubscribe();
        this.streamUnsubscribe = null;
      }
      this.renderLoginShell();
    } else {
      if (!this.root.querySelector('.app-shell')) {
        this.renderAuthenticatedShell();
        this.workspaceStore.loadWorkspaces();
      }
    }
  }

  private handleWorkspaceState(state: WorkspaceState): void {
    const badge = this.root.querySelector<HTMLElement>('#topbar-workspace-name');
    if (badge) {
      badge.textContent = state.activeWorkspace?.name || 'Select Workspace';
    }
    this.renderWorkspaceMenu();
    if (state.activeWorkspace?.id) {
      this.startEventStream(state.activeWorkspace.id);
    }
  }

  private startEventStream(workspaceId: string): void {
    if (this.streamUnsubscribe) {
      this.streamUnsubscribe();
      this.streamUnsubscribe = null;
    }

    const dot = this.root.querySelector<HTMLElement>('#stream-pulse-dot');
    const text = this.root.querySelector<HTMLElement>('#stream-status-text');

    this.streamUnsubscribe = this.apiClient.subscribeToWorkspaceEvents(
      workspaceId,
      (evt) => {
        if (dot && text) {
          dot.style.background = '#10b981';
          dot.style.boxShadow = '0 0 8px #10b981';
          text.textContent = 'SSE: Live';
        }
        if (evt.type === 'execution.dispatched') {
          this.notificationStore.info(`Execution dispatched: ${(evt.payload as any)?.executionId || 'Active'}`);
        } else if (evt.type === 'execution.completed') {
          this.notificationStore.success(`Execution completed: ${(evt.payload as any)?.executionId || 'Finished'}`);
        } else if (evt.type === 'finding.created') {
          this.notificationStore.warning(`New finding recorded: ${(evt.payload as any)?.title || 'Vulnerability'}`);
        } else if (evt.type === 'finding.transitioned') {
          this.notificationStore.info(`Finding transitioned: ${(evt.payload as any)?.toStatus || 'Updated'}`);
        } else if (evt.type === 'asset.registered') {
          this.notificationStore.success(`Asset discovered: ${(evt.payload as any)?.canonicalValue || 'Target'}`);
        }
      },
      () => {
        if (dot && text) {
          dot.style.background = '#f59e0b';
          dot.style.boxShadow = '0 0 8px #f59e0b';
          text.textContent = 'SSE: Reconnecting...';
        }
      }
    );
  }

  private handleRouteChange(match: RouteMatch): void {
    if (!this.authStore.getState().isAuthenticated) {
      if (match.route !== 'login') {
        this.router.navigate('login');
      }
      return;
    }

    if (match.route === 'login') {
      this.router.navigate('dashboard');
      return;
    }

    if (!this.root.querySelector('.app-shell')) {
      this.renderAuthenticatedShell();
    }

    this.updateActiveNav(match.route);
    this.mountView(match.route);
  }

  private renderLoginShell(): void {
    if (this.currentViewInstance) {
      this.currentViewInstance.unmount();
      this.currentViewInstance = null;
    }

    this.root.innerHTML = `
      <div id="login-viewport" style="width: 100vw; height: 100vh; display: flex; align-items: center; justify-content: center; position: relative; z-index: 10;"></div>
      <div id="toast-container"></div>
    `;

    const mount = this.root.querySelector<HTMLElement>('#login-viewport');
    if (mount) {
      renderLoginView(mount, {
        api: this.apiClient,
        authStore: this.authStore,
        notify: this.notificationStore,
        onLoginSuccess: () => {
          this.router.navigate('dashboard');
        },
      });
    }
  }

  private renderAuthenticatedShell(): void {
    const auth = this.authStore.getState();
    const ws = this.workspaceStore.getActiveWorkspace();
    const userDisplayName = auth.user?.displayName || 'Operator';
    const userInitials = (userDisplayName[0] || 'O').toUpperCase();
    const primaryRole = auth.roles[0] || 'ORG_ADMIN';

    this.root.innerHTML = `
      <div class="app-shell">
        <!-- Sidebar Navigation -->
        <aside class="sidebar ${this.isSidebarCollapsed ? 'collapsed' : ''}" id="app-sidebar">
          <div class="sidebar-header">
            <div class="brand-badge" id="brand-home-link">
              <div class="brand-logo-icon">HN</div>
              <div class="brand-text">
                <span class="brand-title">SHADOW HELIX</span>
                <span class="brand-subtitle">SOVEREIGN SEC</span>
              </div>
            </div>
            <button id="btn-toggle-sidebar" class="btn btn-ghost btn-sm" style="padding: 4px; border: none; font-size: 14px;" title="Toggle sidebar">
              ${this.isSidebarCollapsed ? '▶' : '◀'}
            </button>
          </div>

          <nav class="sidebar-nav">
            <div class="nav-section-title">Core Operations</div>
            <a class="nav-item" data-route="dashboard">
              <span class="nav-icon">📊</span>
              <span class="nav-label">Operations Dashboard</span>
              <span class="nav-badge" style="background: var(--accent-subtle); color: var(--accent-primary);">LIVE</span>
            </a>
            <a class="nav-item" data-route="workspaces">
              <span class="nav-icon">🌐</span>
              <span class="nav-label">Workspaces & Scope</span>
            </a>
            <a class="nav-item" data-route="assets">
              <span class="nav-icon">🖥️</span>
              <span class="nav-label">Asset Inventory</span>
            </a>

            <div class="nav-section-title">Offensive & Discovery</div>
            <a class="nav-item" data-route="reconnaissance">
              <span class="nav-icon">🛰️</span>
              <span class="nav-label">Reconnaissance</span>
            </a>
            <a class="nav-item" data-route="scans">
              <span class="nav-icon">🛡️</span>
              <span class="nav-label">Scans & Assessments</span>
            </a>
            <a class="nav-item" data-route="capabilities">
              <span class="nav-icon">⚡</span>
              <span class="nav-label">Tool Registry</span>
            </a>
            <a class="nav-item" data-route="workflows">
              <span class="nav-icon">🔄</span>
              <span class="nav-label">Workflow Pipelines</span>
            </a>

            <div class="nav-section-title">AI & Threat Intelligence</div>
            <a class="nav-item" data-route="ai-assistant">
              <span class="nav-icon">🧠</span>
              <span class="nav-label">AI Security Assistant</span>
            </a>
            <a class="nav-item" data-route="graph">
              <span class="nav-icon">🕸️</span>
              <span class="nav-label">Attack-Path Graph</span>
            </a>
            <a class="nav-item" data-route="ai-providers">
              <span class="nav-icon">🤖</span>
              <span class="nav-label">AI Providers</span>
            </a>

            <div class="nav-section-title">Findings & Evidence</div>
            <a class="nav-item" data-route="findings">
              <span class="nav-icon">🔍</span>
              <span class="nav-label">Vulnerabilities & Findings</span>
            </a>
            <a class="nav-item" data-route="evidence">
              <span class="nav-icon">🗄️</span>
              <span class="nav-label">Evidence Vault</span>
            </a>
            <a class="nav-item" data-route="reports">
              <span class="nav-icon">📁</span>
              <span class="nav-label">Security Reports</span>
            </a>

            <div class="nav-section-title">Execution & Governance</div>
            <a class="nav-item" data-route="terminal">
              <span class="nav-icon">💻</span>
              <span class="nav-label">Execution Terminal</span>
            </a>
            <a class="nav-item" data-route="activity">
              <span class="nav-icon">⏱️</span>
              <span class="nav-label">Operational Activity</span>
            </a>
            <a class="nav-item" data-route="audit">
              <span class="nav-icon">📋</span>
              <span class="nav-label">Audit Ledger</span>
            </a>
            <a class="nav-item" data-route="settings">
              <span class="nav-icon">⚙️</span>
              <span class="nav-label">Settings & Themes</span>
            </a>
          </nav>

          <div class="sidebar-footer">
            <div class="user-avatar">${userInitials}</div>
            <div class="brand-text" style="flex: 1; overflow: hidden;">
              <span style="font-weight: 600; font-size: 12px; color: var(--text-primary); text-overflow: ellipsis; white-space: nowrap; overflow: hidden;">
                ${userDisplayName}
              </span>
              <span style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono);">
                ${primaryRole}
              </span>
            </div>
            <button id="btn-quick-logout" class="btn btn-ghost btn-sm" style="padding: 4px;" title="Logout">⏻</button>
          </div>
        </aside>

        <!-- Main Wrapper -->
        <div class="main-wrapper">
          <!-- Topbar -->
          <header class="topbar">
            <div class="topbar-left">
              <!-- Workspace Dropdown -->
              <div style="position: relative;">
                <div class="workspace-badge" id="btn-workspace-menu">
                  <span>🏢</span>
                  <span id="topbar-workspace-name">${ws?.name || 'Apex Sovereign Workspace'}</span>
                  <span style="font-size: 9px; opacity: 0.7;">▼</span>
                </div>
                <div id="workspace-dropdown" class="card" style="display: none; position: absolute; top: calc(100% + 8px); left: 0; min-width: 240px; z-index: 500; padding: 6px; box-shadow: var(--shadow-xl);"></div>
              </div>

              <!-- Global Search Trigger -->
              <button id="btn-search-trigger" class="btn btn-secondary btn-sm" style="display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 6px 12px; border-radius: var(--radius-md);">
                <span>🔍</span>
                <span style="color: var(--text-secondary);">Command Palette...</span>
                <kbd style="font-size: 10px; padding: 2px 4px; background: var(--bg-surface-sunken); border-radius: 4px; border: 1px solid var(--border-medium);">Ctrl+K</kbd>
              </button>
            </div>

            <div class="topbar-right">
              <!-- Live Health Pulse Badge -->
              <div class="health-status-badge" id="health-indicator" title="Ingress Gateway Liveness">
                <div style="width: 7px; height: 7px; border-radius: 50%; background: #10b981; box-shadow: 0 0 8px #10b981;"></div>
                <span>Sovereign Ingress: UP</span>
              </div>

              <!-- Live SSE Telemetry Stream Badge -->
              <div class="health-status-badge" id="stream-indicator" title="Real-Time Server-Sent Events (SSE) Stream">
                <div id="stream-pulse-dot" style="width: 7px; height: 7px; border-radius: 50%; background: #06b6d4; box-shadow: 0 0 8px #06b6d4;"></div>
                <span id="stream-status-text">SSE: Connected</span>
              </div>

              <!-- Notifications Menu -->
              <div style="position: relative;">
                <button id="btn-notifications-menu" class="btn btn-ghost btn-sm" style="position: relative; padding: 6px 10px;" title="Notifications">
                  <span>🔔</span>
                  <span id="badge-notification-count" style="display: none; position: absolute; top: 2px; right: 2px; width: 8px; height: 8px; border-radius: 50%; background: var(--color-critical);"></span>
                </button>
                <div id="notifications-dropdown" class="card" style="display: none; position: absolute; top: calc(100% + 8px); right: 0; width: 320px; z-index: 500; padding: 0; box-shadow: var(--shadow-xl); overflow: hidden;">
                  <div style="padding: 10px 14px; border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 600; font-size: 12px; color: var(--text-primary);">System Alerts & Audits</span>
                    <button id="btn-clear-notifications" class="btn btn-ghost btn-sm" style="font-size: 11px; padding: 2px 6px;">Clear</button>
                  </div>
                  <div id="notifications-list" style="max-height: 280px; overflow-y: auto; padding: 8px;">
                    <div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 12px;">No unread security alerts</div>
                  </div>
                </div>
              </div>

              <!-- User Profile Menu -->
              <div style="position: relative;">
                <div class="user-profile-button" id="btn-user-menu">
                  <div class="user-avatar">${userInitials}</div>
                  <span style="font-size: 12px; font-weight: 600; color: var(--text-primary); max-width: 120px; text-overflow: ellipsis; white-space: nowrap; overflow: hidden;">
                    ${userDisplayName.split(' ')[0] || 'Operator'}
                  </span>
                  <span style="font-size: 8px; opacity: 0.7;">▼</span>
                </div>
                <div id="user-dropdown" class="card" style="display: none; position: absolute; top: calc(100% + 8px); right: 0; min-width: 200px; z-index: 500; padding: 6px; box-shadow: var(--shadow-xl);">
                  <div style="padding: 8px 10px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 4px;">
                    <div style="font-weight: 600; font-size: 12px; color: var(--text-primary);">${auth.user?.email || 'operator@shn.sovereign'}</div>
                    <div style="font-size: 10px; color: var(--accent-primary); font-family: var(--font-mono);">${auth.roles.join(', ') || 'ORG_ADMIN'}</div>
                  </div>
                  <a class="nav-item" data-route="settings" style="font-size: 12px; padding: 6px 10px;">
                    <span>⚙️</span> Personalization & Settings
                  </a>
                  <a class="nav-item" data-route="audit" style="font-size: 12px; padding: 6px 10px;">
                    <span>📋</span> Security Audit Trail
                  </a>
                  <div style="border-top: 1px solid var(--border-subtle); margin: 4px 0;"></div>
                  <button id="btn-menu-logout" class="btn btn-ghost btn-sm" style="width: 100%; justify-content: flex-start; color: var(--color-critical); font-size: 12px; padding: 6px 10px;">
                    <span>⏻</span> Sign Out
                  </button>
                </div>
              </div>
            </div>
          </header>

          <!-- Main View Mount -->
          <main class="content-viewport" id="view-viewport"></main>
        </div>
      </div>

      <!-- Command Palette Modal -->
      <div id="command-palette-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.65); backdrop-filter: blur(8px); z-index: 3000; align-items: flex-start; justify-content: center; padding-top: 12vh;">
        <div class="card" style="width: 100%; max-width: 580px; padding: 0; overflow: hidden; box-shadow: var(--shadow-xl); border: 1px solid var(--border-medium);">
          <div style="padding: 12px 16px; border-bottom: 1px solid var(--border-subtle); display: flex; align-items: center; gap: 10px; background: var(--bg-surface-elevated);">
            <span>🔍</span>
            <input
              id="command-palette-input"
              type="text"
              placeholder="Search views, assets, capabilities, or quick actions..."
              style="flex: 1; background: transparent; border: none; outline: none; color: var(--text-primary); font-size: 14px;"
            />
            <kbd style="font-size: 10px; padding: 2px 6px; background: var(--bg-surface-sunken); border-radius: 4px; border: 1px solid var(--border-subtle); color: var(--text-muted);">ESC</kbd>
          </div>
          <div id="command-palette-results" style="max-height: 320px; overflow-y: auto; padding: 6px;"></div>
        </div>
      </div>

      <!-- Toast Container -->
      <div id="toast-container"></div>
    `;

    this.bindShellEvents();
  }

  private bindShellEvents(): void {
    this.root.querySelector('#brand-home-link')?.addEventListener('click', () => {
      this.router.navigate('dashboard');
    });

    this.root.querySelector('#btn-toggle-sidebar')?.addEventListener('click', () => {
      this.isSidebarCollapsed = !this.isSidebarCollapsed;
      const sidebar = this.root.querySelector('#app-sidebar');
      const btn = this.root.querySelector('#btn-toggle-sidebar');
      if (sidebar && btn) {
        if (this.isSidebarCollapsed) {
          sidebar.classList.add('collapsed');
          btn.textContent = '▶';
        } else {
          sidebar.classList.remove('collapsed');
          btn.textContent = '◀';
        }
      }
    });

    this.root.querySelectorAll<HTMLAnchorElement>('.nav-item').forEach((item) => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const route = item.dataset.route as RouteId;
        if (route) {
          this.closeAllMenus();
          this.router.navigate(route);
        }
      });
    });

    this.root.querySelector('#btn-workspace-menu')?.addEventListener('click', (e) => {
      e.stopPropagation();
      this.isWorkspaceMenuOpen = !this.isWorkspaceMenuOpen;
      this.isNotificationsOpen = false;
      this.isUserMenuOpen = false;
      this.toggleMenu('workspace-dropdown', this.isWorkspaceMenuOpen);
    });

    this.root.querySelector('#btn-notifications-menu')?.addEventListener('click', (e) => {
      e.stopPropagation();
      this.isNotificationsOpen = !this.isNotificationsOpen;
      this.isWorkspaceMenuOpen = false;
      this.isUserMenuOpen = false;
      this.toggleMenu('notifications-dropdown', this.isNotificationsOpen);
    });

    this.root.querySelector('#btn-user-menu')?.addEventListener('click', (e) => {
      e.stopPropagation();
      this.isUserMenuOpen = !this.isUserMenuOpen;
      this.isWorkspaceMenuOpen = false;
      this.isNotificationsOpen = false;
      this.toggleMenu('user-dropdown', this.isUserMenuOpen);
    });

    document.addEventListener('click', () => {
      this.closeAllMenus();
    });

    const logoutHandler = () => {
      this.authStore.logout();
      this.router.navigate('login');
    };
    this.root.querySelector('#btn-quick-logout')?.addEventListener('click', logoutHandler);
    this.root.querySelector('#btn-menu-logout')?.addEventListener('click', logoutHandler);

    this.root.querySelector('#btn-search-trigger')?.addEventListener('click', () => {
      this.openCommandPalette();
    });

    this.root.querySelector('#command-palette-modal')?.addEventListener('click', (e) => {
      if ((e.target as HTMLElement).id === 'command-palette-modal') {
        this.closeCommandPalette();
      }
    });

    this.root.querySelector('#btn-clear-notifications')?.addEventListener('click', () => {
      const list = this.root.querySelector('#notifications-list');
      if (list) {
        list.innerHTML = `<div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 12px;">No unread security alerts</div>`;
      }
      const badge = this.root.querySelector<HTMLElement>('#badge-notification-count');
      if (badge) badge.style.display = 'none';
    });
  }

  private toggleMenu(id: string, isOpen: boolean): void {
    const el = this.root.querySelector<HTMLElement>(`#${id}`);
    if (el) {
      el.style.display = isOpen ? 'block' : 'none';
    }
  }

  private closeAllMenus(): void {
    this.isWorkspaceMenuOpen = false;
    this.isNotificationsOpen = false;
    this.isUserMenuOpen = false;
    this.toggleMenu('workspace-dropdown', false);
    this.toggleMenu('notifications-dropdown', false);
    this.toggleMenu('user-dropdown', false);
  }

  private renderWorkspaceMenu(): void {
    const dropdown = this.root.querySelector<HTMLElement>('#workspace-dropdown');
    if (!dropdown) return;

    const wsState = this.workspaceStore.getState();
    const active = wsState.activeWorkspace;

    dropdown.innerHTML = `
      <div style="padding: 6px 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.08em;">
        Switch Authorized Scope
      </div>
      ${wsState.workspaces.map((w) => `
        <div
          class="ws-switch-item"
          data-ws-id="${w.id}"
          style="cursor: pointer; padding: 8px 10px; border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: space-between; font-size: 12px; font-weight: ${w.id === active?.id ? '600' : '400'}; color: ${w.id === active?.id ? 'var(--accent-primary)' : 'var(--text-primary)'}; background: ${w.id === active?.id ? 'var(--accent-subtle)' : 'transparent'};"
        >
          <span>${w.name}</span>
          ${w.id === active?.id ? '<span style="font-size: 10px;">✓</span>' : ''}
        </div>
      `).join('')}
      <div style="border-top: 1px solid var(--border-subtle); margin: 6px 0;"></div>
      <div
        id="btn-nav-workspaces"
        style="cursor: pointer; padding: 8px 10px; border-radius: var(--radius-sm); font-size: 12px; color: var(--accent-primary); display: flex; align-items: center; gap: 6px;"
      >
        <span>+</span> Manage All Workspaces
      </div>
    `;

    dropdown.querySelectorAll<HTMLElement>('.ws-switch-item').forEach((item) => {
      item.addEventListener('click', () => {
        const id = item.dataset.wsId;
        if (id) {
          this.workspaceStore.setActiveWorkspace(id);
          this.closeAllMenus();
          const current = this.router.getCurrentRoute();
          this.mountView(current.route);
        }
      });
    });

    dropdown.querySelector('#btn-nav-workspaces')?.addEventListener('click', () => {
      this.closeAllMenus();
      this.router.navigate('workspaces');
    });
  }

  private updateActiveNav(activeRoute: RouteId): void {
    this.root.querySelectorAll<HTMLElement>('.nav-item').forEach((item) => {
      if (item.dataset.route === activeRoute) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
  }

  private mountView(route: RouteId): void {
    const mount = this.root.querySelector<HTMLElement>('#view-viewport');
    if (!mount) return;

    if (this.currentViewInstance) {
      this.currentViewInstance.unmount();
      this.currentViewInstance = null;
    }

    mount.innerHTML = '';

    const viewDeps = {
      api: this.apiClient,
      workspaceStore: this.workspaceStore,
      notify: this.notificationStore,
    };

    switch (route) {
      case 'dashboard':
        renderDashboardView(mount, viewDeps);
        break;
      case 'workspaces':
        renderWorkspacesView(mount, viewDeps);
        break;
      case 'assets':
        renderAssetsView(mount, viewDeps);
        break;
      case 'reconnaissance':
        this.reconView.mount(mount);
        this.currentViewInstance = this.reconView;
        break;
      case 'scans':
        this.scansView.mount(mount);
        this.currentViewInstance = this.scansView;
        break;
      case 'capabilities':
        renderCapabilitiesView(mount, viewDeps);
        break;
      case 'workflows':
        this.workflowsView.mount(mount);
        this.currentViewInstance = this.workflowsView;
        break;
      case 'ai-assistant':
        this.aiAssistantView.mount(mount);
        this.currentViewInstance = this.aiAssistantView;
        break;
      case 'graph':
        this.graphView.mount(mount);
        this.currentViewInstance = this.graphView;
        break;
      case 'findings':
        renderFindingsView(mount, viewDeps);
        break;
      case 'evidence':
        this.evidenceView.mount(mount);
        this.currentViewInstance = this.evidenceView;
        break;
      case 'reports':
        this.reportsView.mount(mount);
        this.currentViewInstance = this.reportsView;
        break;
      case 'executions':
        renderExecutionsView(mount, viewDeps);
        break;
      case 'terminal':
        this.terminalView.mount(mount);
        this.currentViewInstance = this.terminalView;
        break;
      case 'ai-providers':
        this.aiProvidersView.mount(mount);
        this.currentViewInstance = this.aiProvidersView;
        break;
      case 'activity':
        this.activityView.mount(mount);
        this.currentViewInstance = this.activityView;
        break;
      case 'audit':
        this.auditView.mount(mount);
        this.currentViewInstance = this.auditView;
        break;
      case 'settings':
        this.settingsView.mount(mount);
        this.currentViewInstance = this.settingsView;
        break;
      default:
        renderDashboardView(mount, viewDeps);
    }
  }

  private initKeyboardShortcuts(): void {
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (this.isCommandPaletteOpen) {
          this.closeCommandPalette();
        } else {
          this.openCommandPalette();
        }
      }
      if (e.key === 'Escape') {
        this.closeCommandPalette();
        this.closeAllMenus();
      }
    });
  }

  private openCommandPalette(): void {
    if (!this.authStore.getState().isAuthenticated) return;
    this.isCommandPaletteOpen = true;
    const modal = this.root.querySelector<HTMLElement>('#command-palette-modal');
    const input = this.root.querySelector<HTMLInputElement>('#command-palette-input');
    if (modal && input) {
      modal.style.display = 'flex';
      input.value = '';
      input.focus();
      this.renderCommandResults('');
      input.oninput = () => {
        this.renderCommandResults(input.value);
      };
    }
  }

  private closeCommandPalette(): void {
    this.isCommandPaletteOpen = false;
    const modal = this.root.querySelector<HTMLElement>('#command-palette-modal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  private renderCommandResults(query: string): void {
    const container = this.root.querySelector<HTMLElement>('#command-palette-results');
    if (!container) return;

    const commands: Array<{ title: string; subtitle: string; icon: string; action: () => void }> = [
      { title: 'Operations Dashboard', subtitle: 'View operational KPIs, world map, and telemetry', icon: '📊', action: () => this.router.navigate('dashboard') },
      { title: 'Workspaces & Scope', subtitle: 'Inspect authorization gates and CIDR boundaries', icon: '🌐', action: () => this.router.navigate('workspaces') },
      { title: 'Asset Inventory', subtitle: 'Manage targets, canonical addresses, and criticality', icon: '🖥️', action: () => this.router.navigate('assets') },
      { title: 'Reconnaissance', subtitle: 'DNS zone discovery, HTTP fingerprinting', icon: '🛰️', action: () => this.router.navigate('reconnaissance') },
      { title: 'Scans & Assessments', subtitle: 'Policy-governed vulnerability scans', icon: '🛡️', action: () => this.router.navigate('scans') },
      { title: 'Tool Registry', subtitle: 'Discovered offensive & defensive capabilities', icon: '⚡', action: () => this.router.navigate('capabilities') },
      { title: 'Workflow Pipelines', subtitle: 'Multi-stage assessment orchestration', icon: '🔄', action: () => this.router.navigate('workflows') },
      { title: 'AI Security Assistant', subtitle: 'Evidence-driven recommendations & chat', icon: '🧠', action: () => this.router.navigate('ai-assistant') },
      { title: 'Attack-Path Graph', subtitle: 'Obsidian-like interactive topological relationship graph', icon: '🕸️', action: () => this.router.navigate('graph') },
      { title: 'AI Providers', subtitle: 'Configure Ollama, OpenAI, Anthropic, or Heuristic', icon: '🤖', action: () => this.router.navigate('ai-providers') },
      { title: 'Vulnerabilities & Findings', subtitle: 'Triage CVSS scores, evidence hashes, and lifecycle', icon: '🔍', action: () => this.router.navigate('findings') },
      { title: 'Evidence Vault', subtitle: 'Cryptographic artifacts and SHA-256 chain of custody', icon: '🗄️', action: () => this.router.navigate('evidence') },
      { title: 'Security Reports', subtitle: 'Generate SHA-256 signed executive & technical reports', icon: '📁', action: () => this.router.navigate('reports') },
      { title: 'Execution Terminal', subtitle: 'Background tool supervision & live terminal logs', icon: '💻', action: () => this.router.navigate('terminal') },
      { title: 'Operational Activity', subtitle: 'Chronological timeline of system events and alerts', icon: '⏱️', action: () => this.router.navigate('activity') },
      { title: 'Audit Ledger', subtitle: 'Cryptographic immutable audit records', icon: '📋', action: () => this.router.navigate('audit') },
      { title: 'Settings & Themes', subtitle: 'Configure Day/Night/Ambient modes and accents', icon: '⚙️', action: () => this.router.navigate('settings') },
      { title: 'Theme: Cyber-Operations', subtitle: 'Switch to deep-space dark palette', icon: '🌌', action: () => this.settingsStore.setTheme('night') },
      { title: 'Theme: Ambient Mode', subtitle: 'Switch to translucent atmospheric glow', icon: '✨', action: () => this.settingsStore.setTheme('ambient') },
      { title: 'Theme: Light Mode', subtitle: 'Switch to clean high-readability daylight', icon: '☀️', action: () => this.settingsStore.setTheme('day') },
    ];

    const q = query.toLowerCase().trim();
    const filtered = commands.filter((c) => !q || c.title.toLowerCase().includes(q) || c.subtitle.toLowerCase().includes(q));

    if (filtered.length === 0) {
      container.innerHTML = `<div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 13px;">No commands match "${query}"</div>`;
      return;
    }

    container.innerHTML = filtered.map((c, i) => `
      <div
        class="cmd-item"
        data-cmd-index="${i}"
        style="cursor: pointer; padding: 10px 12px; border-radius: var(--radius-sm); display: flex; align-items: center; gap: 12px; transition: background 0.15s ease;"
      >
        <span style="font-size: 16px;">${c.icon}</span>
        <div style="flex: 1;">
          <div style="font-weight: 600; font-size: 13px; color: var(--text-primary);">${c.title}</div>
          <div style="font-size: 11px; color: var(--text-muted);">${c.subtitle}</div>
        </div>
        <kbd style="font-size: 10px; color: var(--text-muted);">↵</kbd>
      </div>
    `).join('');

    container.querySelectorAll<HTMLElement>('.cmd-item').forEach((item) => {
      item.addEventListener('mouseenter', () => {
        item.style.background = 'var(--accent-subtle)';
      });
      item.addEventListener('mouseleave', () => {
        item.style.background = 'transparent';
      });
      item.addEventListener('click', () => {
        const idx = parseInt(item.dataset.cmdIndex || '0', 10);
        this.closeCommandPalette();
        filtered[idx]?.action();
      });
    });
  }

  private renderToasts(toasts: ToastMessage[]): void {
    const container = this.root.querySelector<HTMLElement>('#toast-container');
    if (!container) return;

    container.innerHTML = toasts.map((t) => `
      <div class="toast toast-${t.type}" id="${t.id}">
        <div style="font-size: 16px;">
          ${t.type === 'success' ? '✓' : t.type === 'error' ? '⚠️' : t.type === 'warning' ? '⚡' : 'ℹ️'}
        </div>
        <div style="flex: 1;">
          ${t.title ? `<div style="font-weight: 600; font-size: 12px; color: var(--text-primary); margin-bottom: 2px;">${t.title}</div>` : ''}
          <div style="font-size: 12px; color: var(--text-secondary);">${t.message}</div>
        </div>
        <button class="btn btn-ghost btn-sm btn-dismiss-toast" data-toast-id="${t.id}" style="padding: 2px 4px; font-size: 12px; line-height: 1;">✕</button>
      </div>
    `).join('');

    container.querySelectorAll<HTMLButtonElement>('.btn-dismiss-toast').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.toastId;
        if (id) this.notificationStore.dismiss(id);
      });
    });

    const badge = this.root.querySelector<HTMLElement>('#badge-notification-count');
    if (badge && toasts.length > 0) {
      badge.style.display = 'block';
    }
  }

  private startHealthPolling(): void {
    const check = async () => {
      try {
        const live = await this.apiClient.getLiveness();
        this.isHealthy = live.status === 'UP';
      } catch {
        this.isHealthy = false;
      }

      const indicator = this.root.querySelector<HTMLElement>('#health-indicator');
      if (indicator) {
        if (this.isHealthy) {
          indicator.innerHTML = `
            <div style="width: 7px; height: 7px; border-radius: 50%; background: #10b981; box-shadow: 0 0 8px #10b981;"></div>
            <span>Sovereign Ingress: UP</span>
          `;
          indicator.style.color = '#10b981';
        } else {
          indicator.innerHTML = `
            <div style="width: 7px; height: 7px; border-radius: 50%; background: var(--color-critical); box-shadow: 0 0 8px var(--color-critical);"></div>
            <span>Sovereign Ingress: DEGRADED</span>
          `;
          indicator.style.color = 'var(--color-critical)';
        }
      }
    };

    check();
    this.healthInterval = window.setInterval(check, 15000);
  }

  destroy(): void {
    if (this.healthInterval) {
      clearInterval(this.healthInterval);
      this.healthInterval = null;
    }
    if (this.currentViewInstance) {
      this.currentViewInstance.unmount();
      this.currentViewInstance = null;
    }
  }
}
