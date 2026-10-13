/**
 * Shadow : Helix Nebula (SHN) — AuthStore Unit Tests
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { AuthStore, ApiClient } from '../../dist/index.js';

class MockStorage implements Storage {
  private store = new Map<string, string>();

  get length(): number {
    return this.store.size;
  }
  clear(): void {
    this.store.clear();
  }
  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }
  key(index: number): string | null {
    return Array.from(this.store.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.store.delete(key);
  }
  setItem(key: string, value: string): void {
    this.store.set(key, String(value));
  }
}

describe('AuthStore (Unit Tests)', () => {
  let mockStorage: MockStorage;
  let mockApi: ApiClient;

  beforeEach(() => {
    mockStorage = new MockStorage();
    (globalThis as any).localStorage = mockStorage;
    mockApi = new ApiClient();
  });

  it('starts in anonymous state when localStorage is empty', () => {
    const store = new AuthStore(mockApi);
    const state = store.getState();

    assert.equal(state.isAuthenticated, false);
    assert.equal(state.token, null);
    assert.equal(state.user, null);
    assert.equal(state.workspaceId, null);
    assert.deepEqual(state.roles, []);
  });

  it('hydrates state from existing localStorage credentials', () => {
    mockStorage.setItem('shn_auth_token', 'persisted-jwt-token');
    mockStorage.setItem('shn_auth_user', JSON.stringify({ id: 'u-1', email: 'op@shn.sovereign', displayName: 'Op' }));
    mockStorage.setItem('shn_active_workspace_id', 'ws-alpha');
    mockStorage.setItem('shn_auth_roles', JSON.stringify(['ORG_ADMIN', 'SECURITY_LEAD']));

    const store = new AuthStore(mockApi);
    const state = store.getState();

    assert.equal(state.isAuthenticated, true);
    assert.equal(state.token, 'persisted-jwt-token');
    assert.equal(state.user?.email, 'op@shn.sovereign');
    assert.equal(state.workspaceId, 'ws-alpha');
    assert.deepEqual(state.roles, ['ORG_ADMIN', 'SECURITY_LEAD']);
  });

  it('handles login success, stores tokens, and notifies subscribers', () => {
    const store = new AuthStore(mockApi);
    let notifiedState: any = null;

    const unsubscribe = store.subscribe((state) => {
      notifiedState = state;
    });

    store.handleLoginSuccess({
      token: 'jwt-access-token-123',
      user: { id: 'usr-9', email: 'analyst@shn.sovereign', displayName: 'Analyst', organizationId: 'org-1' },
      workspaceId: 'ws-analyst',
      roles: ['WORKSPACE_ANALYST'],
      permissionMask: 31,
      expiresAt: Date.now() + 3600000,
    });

    assert.equal(notifiedState?.isAuthenticated, true);
    assert.equal(notifiedState?.token, 'jwt-access-token-123');
    assert.equal(notifiedState?.user?.displayName, 'Analyst');
    assert.equal(mockStorage.getItem('shn_auth_token'), 'jwt-access-token-123');
    assert.equal(mockStorage.getItem('shn_active_workspace_id'), 'ws-analyst');

    unsubscribe();
  });

  it('switches active workspace safely and notifies listeners', () => {
    const store = new AuthStore(mockApi);
    store.handleLoginSuccess({
      token: 'tok-1',
      user: { id: 'u-1', email: 'op@shn.sovereign', displayName: 'Op', organizationId: 'org-1' },
      workspaceId: 'ws-initial',
      roles: ['ORG_ADMIN'],
      permissionMask: 1,
      expiresAt: Date.now() + 10000,
    });

    store.setActiveWorkspace('ws-switched');

    assert.equal(store.getState().workspaceId, 'ws-switched');
    assert.equal(mockStorage.getItem('shn_active_workspace_id'), 'ws-switched');
  });

  it('clears session on logout', () => {
    const store = new AuthStore(mockApi);
    store.handleLoginSuccess({
      token: 'tok-1',
      user: { id: 'u-1', email: 'op@shn.sovereign', displayName: 'Op', organizationId: 'org-1' },
      workspaceId: 'ws-initial',
      roles: ['ORG_ADMIN'],
      permissionMask: 1,
      expiresAt: Date.now() + 10000,
    });

    store.logout();
    const state = store.getState();

    assert.equal(state.isAuthenticated, false);
    assert.equal(state.token, null);
    assert.equal(state.user, null);
    assert.equal(mockStorage.getItem('shn_auth_token'), null);
    assert.equal(mockStorage.getItem('shn_active_workspace_id'), null);
  });
});
