/**
 * Shadow : Helix Nebula (SHN) — Authentication State Store
 */

import type { User, LoginResponse } from '../contracts.js';
import type { ApiClient } from '../services/api-client.js';

export interface AuthState {
  isAuthenticated: boolean;
  token: string | null;
  user: User | null;
  workspaceId: string | null;
  roles: string[];
  permissionMask: number;
}

export class AuthStore {
  private state: AuthState;
  private readonly listeners = new Set<(state: AuthState) => void>();

  constructor(private readonly api: ApiClient) {
    const token = localStorage.getItem('shn_auth_token');
    const userJson = localStorage.getItem('shn_auth_user');
    const workspaceId = localStorage.getItem('shn_active_workspace_id');
    const rolesJson = localStorage.getItem('shn_auth_roles');

    this.state = {
      isAuthenticated: Boolean(token),
      token: token || null,
      user: userJson ? JSON.parse(userJson) : null,
      workspaceId: workspaceId || null,
      roles: rolesJson ? JSON.parse(rolesJson) : [],
      permissionMask: 0,
    };
  }

  getState(): AuthState {
    return { ...this.state };
  }

  subscribe(listener: (state: AuthState) => void): () => void {
    this.listeners.add(listener);
    listener(this.getState());
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    const s = this.getState();
    for (const listener of this.listeners) {
      listener(s);
    }
  }

  handleLoginSuccess(data: LoginResponse): void {
    localStorage.setItem('shn_auth_token', data.token);
    localStorage.setItem('shn_auth_user', JSON.stringify(data.user));
    localStorage.setItem('shn_active_workspace_id', data.workspaceId);
    localStorage.setItem('shn_auth_roles', JSON.stringify(data.roles));

    this.state = {
      isAuthenticated: true,
      token: data.token,
      user: data.user,
      workspaceId: data.workspaceId,
      roles: data.roles,
      permissionMask: data.permissionMask,
    };
    this.notify();
  }

  setActiveWorkspace(workspaceId: string): void {
    localStorage.setItem('shn_active_workspace_id', workspaceId);
    this.state.workspaceId = workspaceId;
    this.notify();
  }

  logout(): void {
    localStorage.removeItem('shn_auth_token');
    localStorage.removeItem('shn_auth_user');
    localStorage.removeItem('shn_active_workspace_id');
    localStorage.removeItem('shn_auth_roles');

    this.state = {
      isAuthenticated: false,
      token: null,
      user: null,
      workspaceId: null,
      roles: [],
      permissionMask: 0,
    };
    this.notify();
  }

  async verifySession(): Promise<boolean> {
    if (!this.state.token) {
      this.logout();
      return false;
    }
    try {
      const me = await this.api.getMe();
      if (me && me.actor) {
        if (!this.state.user) {
          this.state.user = {
            id: me.actor.id,
            email: me.actor.email || 'operator@shn.sovereign',
            displayName: me.actor.displayName || 'System Operator',
            organizationId: me.actor.organizationId,
          };
        }
        if (me.workspaceId && !this.state.workspaceId) {
          this.state.workspaceId = me.workspaceId;
        }
        this.notify();
        return true;
      }
      this.logout();
      return false;
    } catch {
      this.logout();
      return false;
    }
  }
}
