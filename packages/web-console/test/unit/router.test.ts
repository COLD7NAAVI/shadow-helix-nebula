/**
 * Shadow : Helix Nebula (SHN) — Router Unit Tests
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { Router, AuthStore, ApiClient } from '../../dist/index.js';

describe('Router (Unit Tests)', () => {
  let mockWindow: {
    location: { hash: string };
    listeners: Record<string, ((e?: any) => void)[]>;
    addEventListener: (type: string, fn: (e?: any) => void) => void;
  };
  let mockAuth: AuthStore;

  beforeEach(() => {
    mockWindow = {
      location: { hash: '' },
      listeners: {},
      addEventListener(type: string, fn: (e?: any) => void) {
        if (!this.listeners[type]) this.listeners[type] = [];
        this.listeners[type]!.push(fn);
      },
    };
    (globalThis as any).window = mockWindow;

    const mockStorage = {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    };
    (globalThis as any).localStorage = mockStorage;

    mockAuth = new AuthStore(new ApiClient());
  });

  it('redirects unauthenticated operators to #login', () => {
    mockWindow.location.hash = '#dashboard';
    const router = new Router(mockAuth);

    router.start();

    assert.equal(mockWindow.location.hash, '#login');
  });

  it('permits #login when unauthenticated', () => {
    mockWindow.location.hash = '#login';
    const router = new Router(mockAuth);

    router.start();

    assert.equal(router.getCurrentRoute().route, 'login');
  });

  it('permits protected routes when authenticated', () => {
    mockAuth.handleLoginSuccess({
      token: 'valid-token',
      user: { id: 'u1', email: 'op@shn.sovereign', displayName: 'Op', organizationId: 'o1' },
      workspaceId: 'w1',
      roles: ['ORG_ADMIN'],
      permissionMask: 1,
      expiresAt: Date.now() + 10000,
    });

    mockWindow.location.hash = '#assets';
    const router = new Router(mockAuth);

    router.start();

    assert.equal(router.getCurrentRoute().route, 'assets');
  });

  it('redirects authenticated operators from #login to #dashboard', () => {
    mockAuth.handleLoginSuccess({
      token: 'valid-token',
      user: { id: 'u1', email: 'op@shn.sovereign', displayName: 'Op', organizationId: 'o1' },
      workspaceId: 'w1',
      roles: ['ORG_ADMIN'],
      permissionMask: 1,
      expiresAt: Date.now() + 10000,
    });

    mockWindow.location.hash = '#login';
    const router = new Router(mockAuth);

    router.start();

    assert.equal(mockWindow.location.hash, '#dashboard');
  });

  it('parses URL search parameters from hash query strings', () => {
    mockAuth.handleLoginSuccess({
      token: 'valid-token',
      user: { id: 'u1', email: 'op@shn.sovereign', displayName: 'Op', organizationId: 'o1' },
      workspaceId: 'w1',
      roles: ['ORG_ADMIN'],
      permissionMask: 1,
      expiresAt: Date.now() + 10000,
    });

    mockWindow.location.hash = '#findings?severity=CRITICAL&status=OPEN';
    const router = new Router(mockAuth);

    router.start();

    const current = router.getCurrentRoute();
    assert.equal(current.route, 'findings');
    assert.equal(current.params['severity'], 'CRITICAL');
    assert.equal(current.params['status'], 'OPEN');
  });

  it('notifies subscribers on programmatic navigate calls', () => {
    mockAuth.handleLoginSuccess({
      token: 'valid-token',
      user: { id: 'u1', email: 'op@shn.sovereign', displayName: 'Op', organizationId: 'o1' },
      workspaceId: 'w1',
      roles: ['ORG_ADMIN'],
      permissionMask: 1,
      expiresAt: Date.now() + 10000,
    });

    const router = new Router(mockAuth);
    router.start();

    let lastRoute = '';
    router.subscribe((match) => {
      lastRoute = match.route;
    });

    router.navigate('audit');

    // Simulate hashchange event in mock window
    mockWindow.listeners['hashchange']?.forEach((fn) => fn());

    assert.equal(lastRoute, 'audit');
  });
});
