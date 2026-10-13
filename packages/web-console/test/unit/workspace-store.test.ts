/**
 * Shadow : Helix Nebula (SHN) — WorkspaceStore Unit Tests
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { WorkspaceStore, AuthStore, ApiClient } from '../../dist/index.js';

describe('WorkspaceStore (Unit Tests)', () => {
  let mockApi: ApiClient;
  let mockAuth: AuthStore;
  let workspaceList: any[];

  beforeEach(() => {
    workspaceList = [
      { id: 'ws-1', name: 'Helix Sector Alpha', slug: 'sector-alpha' },
      { id: 'ws-2', name: 'Quantum Sandbox', slug: 'quantum-sandbox' },
    ];

    const mockStorage = {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    };
    (globalThis as any).localStorage = mockStorage;

    mockApi = new ApiClient();
    (mockApi as any).listWorkspaces = async () => [...workspaceList];
    (mockApi as any).createWorkspace = async ({ name }: { name: string }) => {
      const created = { id: 'ws-new-' + Date.now(), name, slug: name.toLowerCase().replace(/\s+/g, '-') };
      workspaceList.push(created);
      return created;
    };

    mockAuth = new AuthStore(mockApi);
  });

  it('initializes with empty workspaces and null active workspace', () => {
    const store = new WorkspaceStore(mockApi, mockAuth);
    const state = store.getState();

    assert.deepEqual(state.workspaces, []);
    assert.equal(state.activeWorkspace, null);
    assert.equal(state.loading, false);
  });

  it('loads workspaces and selects active workspace', async () => {
    const store = new WorkspaceStore(mockApi, mockAuth);
    await store.loadWorkspaces();

    const state = store.getState();
    assert.equal(state.workspaces.length, 2);
    assert.equal(state.activeWorkspace?.id, 'ws-1');
    assert.equal(store.getActiveWorkspace()?.name, 'Helix Sector Alpha');
  });

  it('switches active workspace and updates auth context', async () => {
    const store = new WorkspaceStore(mockApi, mockAuth);
    await store.loadWorkspaces();

    store.setActiveWorkspace('ws-2');

    assert.equal(store.getActiveWorkspace()?.id, 'ws-2');
    assert.equal(store.getActiveWorkspace()?.name, 'Quantum Sandbox');
  });

  it('creates a new workspace, adds it to the list, and sets it active', async () => {
    const store = new WorkspaceStore(mockApi, mockAuth);
    await store.loadWorkspaces();

    const created = await store.createWorkspace('Sovereign Fortress');

    assert.equal(created.name, 'Sovereign Fortress');
    assert.equal(store.getActiveWorkspace()?.id, created.id);
    assert.equal(store.getState().workspaces.length, 3);
  });
});
