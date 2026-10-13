/**
 * Shadow : Helix Nebula (SHN) — Sovereign Web Console Bootstrap & Public API
 *
 * Initializes the ambient cosmic canvas, typed API client, reactive state stores,
 * client-side routing, and the master application shell.
 */

export * from './contracts.js';
export { ApiClient, ApiError, type ApiClientConfig, type ProblemDetailsError } from './services/api-client.js';
export { AuthStore, type AuthState } from './state/auth-store.js';
export { SettingsStore } from './state/settings-store.js';
export { WorkspaceStore, type WorkspaceState } from './state/workspace-store.js';
export { NotificationStore, type ToastMessage } from './state/notification-store.js';
export { Router, type RouteId, type RouteMatch, type RouteHandler } from './router.js';
export { NebulaCanvas, type NebulaCanvasOptions } from './canvas/nebula-canvas.js';
export { AppShell } from './app.js';

// Visualizations
export { renderSeverityDonut, type SeveritySlice } from './visualization/severity-donut.js';
export { renderExecutionTimeline } from './visualization/timeline-chart.js';
export { renderTopologyGraph, type TopologyData } from './visualization/topology-graph.js';

// Views
export { renderLoginView } from './views/login-view.js';
export { renderDashboardView } from './views/dashboard-view.js';
export { renderWorkspacesView } from './views/workspaces-view.js';
export { renderAssetsView } from './views/assets-view.js';
export { renderCapabilitiesView } from './views/capabilities-view.js';
export { renderExecutionsView } from './views/executions-view.js';
export { renderFindingsView } from './views/findings-view.js';
export { AuditView } from './views/audit-view.js';
export { SettingsView } from './views/settings-view.js';

import { NebulaCanvas } from './canvas/nebula-canvas.js';
import { ApiClient } from './services/api-client.js';
import { AuthStore } from './state/auth-store.js';
import { SettingsStore } from './state/settings-store.js';
import { WorkspaceStore } from './state/workspace-store.js';
import { NotificationStore } from './state/notification-store.js';
import { Router } from './router.js';
import { AppShell } from './app.js';

export function bootstrapWebConsole(): AppShell | null {
  if (typeof document === 'undefined') return null;

  // 1. Initialize Nebula Canvas
  const canvasElement = document.querySelector<HTMLCanvasElement>('#nebula-bg-canvas');
  let nebulaCanvas: NebulaCanvas | null = null;
  if (canvasElement) {
    nebulaCanvas = new NebulaCanvas(canvasElement);
  }

  // 2. Initialize Core State Stores
  const settingsStore = new SettingsStore();
  const notificationStore = new NotificationStore();

  // 3. Sync Settings with Canvas
  if (nebulaCanvas) {
    const initialSettings = settingsStore.getSettings();
    nebulaCanvas.setReducedMotion(initialSettings.reducedMotion);
    settingsStore.subscribe((s) => {
      nebulaCanvas?.setReducedMotion(s.reducedMotion);
    });
  }

  // 4. Initialize HTTP API Client
  const apiClient = new ApiClient({
    baseUrl: '',
    onUnauthorized: () => {
      notificationStore.warning('Session expired or unauthorized. Please re-authenticate.', 'Authentication');
    },
  });

  // 5. Initialize Auth and Workspace Stores
  const authStore = new AuthStore(apiClient);
  const workspaceStore = new WorkspaceStore(apiClient, authStore);

  // 6. Initialize Router
  const router = new Router(authStore);

  // 7. Mount Application Shell
  const appRoot = document.querySelector<HTMLElement>('#app-root');
  if (!appRoot) {
    return null;
  }

  const appShell = new AppShell(
    appRoot,
    apiClient,
    authStore,
    workspaceStore,
    settingsStore,
    notificationStore,
    router
  );

  appShell.init();

  // 8. Global Error Handlers for Operator Observability
  window.addEventListener('unhandledrejection', (event) => {
    console.error('[SHN Gateway Client] Unhandled Rejection:', event.reason);
    notificationStore.error(
      event.reason instanceof Error ? event.reason.message : 'An unexpected asynchronous failure occurred.',
      'System Error'
    );
  });

  window.addEventListener('error', (event) => {
    console.error('[SHN Gateway Client] Uncaught Error:', event.error);
  });

  console.log(`
========================================================================
SHADOW : HELIX NEBULA (SHN) — SOVEREIGN CLIENT INITIALIZED
========================================================================
[+] Design Mode:      ${settingsStore.getSettings().theme.toUpperCase()}
[+] Accent Palette:   ${settingsStore.getSettings().accent.toUpperCase()}
[+] Auth Status:      ${authStore.getState().isAuthenticated ? 'AUTHENTICATED' : 'ANONYMOUS'}
========================================================================
`);

  return appShell;
}

// Auto-bootstrap in browser environment
if (typeof window !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => bootstrapWebConsole());
  } else {
    bootstrapWebConsole();
  }
}
