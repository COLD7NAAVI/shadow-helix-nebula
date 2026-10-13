/**
 * Shadow : Helix Nebula (SHN) — Client Router
 *
 * Hash-based SPA routing with route authentication guards,
 * deep linking, and navigation state propagation.
 */

import type { AuthStore } from './state/auth-store.js';

export type RouteId =
  | 'login'
  | 'dashboard'
  | 'workspaces'
  | 'assets'
  | 'capabilities'
  | 'executions'
  | 'findings'
  | 'audit'
  | 'settings';

export interface RouteMatch {
  route: RouteId;
  params: Record<string, string>;
}

export type RouteHandler = (match: RouteMatch) => void;

export class Router {
  private currentRoute: RouteId = 'dashboard';
  private currentParams: Record<string, string> = {};
  private readonly listeners = new Set<(match: RouteMatch) => void>();

  constructor(private readonly authStore: AuthStore) {
    window.addEventListener('hashchange', () => this.handleHashChange());
  }

  start(): void {
    this.handleHashChange();
  }

  getCurrentRoute(): RouteMatch {
    return {
      route: this.currentRoute,
      params: { ...this.currentParams },
    };
  }

  subscribe(listener: (match: RouteMatch) => void): () => void {
    this.listeners.add(listener);
    listener(this.getCurrentRoute());
    return () => this.listeners.delete(listener);
  }

  navigate(route: RouteId, params?: Record<string, string>): void {
    let hash = `#${route}`;
    if (params && Object.keys(params).length > 0) {
      const qs = new URLSearchParams(params).toString();
      hash += `?${qs}`;
    }
    window.location.hash = hash;
  }

  private handleHashChange(): void {
    const rawHash = window.location.hash.replace(/^#\/?/, '') || 'dashboard';
    const [pathPart, queryPart] = rawHash.split('?');

    const validRoutes: RouteId[] = [
      'login',
      'dashboard',
      'workspaces',
      'assets',
      'capabilities',
      'executions',
      'findings',
      'audit',
      'settings',
    ];

    let targetRoute = (validRoutes.includes(pathPart as RouteId) ? pathPart : 'dashboard') as RouteId;
    const params: Record<string, string> = {};

    if (queryPart) {
      const sp = new URLSearchParams(queryPart);
      for (const [k, v] of sp.entries()) {
        params[k] = v;
      }
    }

    // Authentication Guard
    const auth = this.authStore.getState();
    if (!auth.isAuthenticated) {
      if (targetRoute !== 'login') {
        window.location.hash = '#login';
        return;
      }
    } else {
      if (targetRoute === 'login') {
        window.location.hash = '#dashboard';
        return;
      }
    }

    this.currentRoute = targetRoute;
    this.currentParams = params;

    const match: RouteMatch = { route: this.currentRoute, params: this.currentParams };
    for (const listener of this.listeners) {
      listener(match);
    }
  }
}
