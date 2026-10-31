/**
 * Shadow : Helix Nebula (SHN) — Workspace Context Store
 */

import type { Workspace } from '../contracts.js';
import type { ApiClient } from '../services/api-client.js';
import type { AuthStore } from './auth-store.js';

export interface WorkspaceState {
  workspaces: Workspace[];
  activeWorkspace: Workspace | null;
  loading: boolean;
  error: string | null;
}

export class WorkspaceStore {
  private state: WorkspaceState = {
    workspaces: [],
    activeWorkspace: null,
    loading: false,
    error: null,
  };
  private readonly listeners = new Set<(state: WorkspaceState) => void>();

  constructor(
    private readonly api: ApiClient,
    private readonly authStore: AuthStore
  ) {}

  getState(): WorkspaceState {
    return { ...this.state };
  }

  getActiveWorkspace(): Workspace | null {
    return this.state.activeWorkspace;
  }

  subscribe(listener: (state: WorkspaceState) => void): () => void {
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

  async loadWorkspaces(): Promise<void> {
    this.state.loading = true;
    this.state.error = null;
    this.notify();

    try {
      const list = await this.api.listWorkspaces();
      this.state.workspaces = list;

      const currentWksId = this.authStore.getState().workspaceId;
      const found = list.find((w) => w.id === currentWksId) || list[0] || null;

      this.state.activeWorkspace = found;
      if (found && found.id !== currentWksId) {
        try {
          const switchRes = await this.api.switchWorkspace(found.id);
          this.authStore.updateWorkspaceSession(switchRes);
        } catch {
          this.authStore.setActiveWorkspace(found.id);
        }
      }
      this.state.loading = false;
      this.notify();
    } catch (err: any) {
      this.state.loading = false;
      this.state.error = err.message || 'Failed to load workspaces';
      this.notify();
    }
  }

  async setActiveWorkspace(workspaceId: string): Promise<boolean> {
    const found = this.state.workspaces.find((w) => w.id === workspaceId);
    if (!found) return false;

    try {
      const switchRes = await this.api.switchWorkspace(workspaceId);
      this.authStore.updateWorkspaceSession(switchRes);
    } catch {
      this.authStore.setActiveWorkspace(workspaceId);
    }

    this.state.activeWorkspace = found;
    this.notify();
    return true;
  }

  async createWorkspace(name: string): Promise<Workspace> {
    const created = await this.api.createWorkspace({ name });
    this.state.workspaces = [...this.state.workspaces, created];
    this.state.activeWorkspace = created;
    try {
      const switchRes = await this.api.switchWorkspace(created.id);
      this.authStore.updateWorkspaceSession(switchRes);
    } catch {
      this.authStore.setActiveWorkspace(created.id);
    }
    this.notify();
    return created;
  }
}
