/**
 * Shadow : Helix Nebula (SHN) — Login View Unit Tests
 *
 * Verifies form rendering, input retention, client-side validation,
 * and reliable authentication dispatch without DOM-wipe regression.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { renderLoginView } from '../../dist/views/login-view.js';
import { AuthStore, ApiClient } from '../../dist/index.js';
import { NotificationStore } from '../../dist/state/notification-store.js';

// Minimal DOM mock for isolated unit testing
class MockElement {
  public tagName: string;
  public id: string = '';
  public type: string = '';
  public value: string = '';
  public disabled: boolean = false;
  public textContent: string = '';
  public style: Record<string, string> = {};
  private _innerHTML: string = '';
  private listeners: Record<string, Array<(e: any) => void>> = {};
  public children: MockElement[] = [];

  constructor(tagName = 'div') {
    this.tagName = tagName;
  }

  get innerHTML(): string {
    return this._innerHTML;
  }

  set innerHTML(html: string) {
    this._innerHTML = html;
    this.children = [];
    this.parseSimpleElements(html);
  }

  addEventListener(type: string, listener: (e: any) => void): void {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(listener);
  }

  dispatchEvent(event: { type: string; defaultPrevented?: boolean; preventDefault?: () => void; target?: any }): boolean {
    event.target = event.target || this;
    const list = this.listeners[event.type] || [];
    for (const l of list) {
      l(event);
    }
    return true;
  }

  querySelector(selector: string): MockElement | null {
    if (selector.startsWith('#')) {
      const targetId = selector.slice(1);
      return this.findChildById(this, targetId);
    }
    return null;
  }

  private findChildById(parent: MockElement, id: string): MockElement | null {
    if (parent.id === id) return parent;
    for (const child of parent.children) {
      const found = this.findChildById(child, id);
      if (found) return found;
    }
    return null;
  }

  private parseSimpleElements(html: string): void {
    const idRegex = /<(input|button|form|div)\b([^>]*)\bid="([^"]+)"([^>]*)>/g;
    let match;
    while ((match = idRegex.exec(html)) !== null) {
      const tag = match[1];
      const attrs = match[2] + ' ' + match[4];
      const id = match[3];

      const el = new MockElement(tag);
      el.id = id;

      const typeMatch = attrs.match(/\btype="([^"]+)"/);
      if (typeMatch) el.type = typeMatch[1];

      const valMatch = attrs.match(/\bvalue="([^"]*)"/);
      if (valMatch) el.value = valMatch[1];

      if (attrs.includes('disabled')) el.disabled = true;

      this.children.push(el);
    }
  }
}

class MockStorage implements Storage {
  private store = new Map<string, string>();
  get length(): number { return this.store.size; }
  clear(): void { this.store.clear(); }
  getItem(key: string): string | null { return this.store.get(key) ?? null; }
  key(index: number): string | null { return Array.from(this.store.keys())[index] ?? null; }
  removeItem(key: string): void { this.store.delete(key); }
  setItem(key: string, value: string): void { this.store.set(key, String(value)); }
}

describe('LoginView (Unit Tests)', () => {
  let container: MockElement;
  let mockStorage: MockStorage;
  let authStore: AuthStore;
  let notificationStore: NotificationStore;
  let mockApi: any;
  let loginSuccessCalled: boolean;

  beforeEach(() => {
    mockStorage = new MockStorage();
    (globalThis as any).localStorage = mockStorage;
    container = new MockElement('div');
    loginSuccessCalled = false;

    mockApi = {
      login: async (creds: any) => {
        if (creds.email === 'operator@shn.sovereign' && creds.password === 'ValidPass123!') {
          return {
            token: 'mock-jwt-token-xyz',
            user: { id: 'usr-1', email: 'operator@shn.sovereign', displayName: 'Chief Security Officer' },
            workspaceId: 'wks-1',
            roles: ['ORG_ADMIN'],
            permissionMask: 0xffffffff,
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          };
        }
        const err: any = new Error('Invalid email or password.');
        err.problem = { status: 401, detail: 'Invalid email or password.' };
        throw err;
      },
      register: async () => {},
    };

    authStore = new AuthStore(mockApi as any);
    notificationStore = new NotificationStore();
  });

  it('renders login view structure with header, form, and inputs', () => {
    renderLoginView(container as any, {
      api: mockApi,
      authStore,
      notify: notificationStore,
      onLoginSuccess: () => { loginSuccessCalled = true; },
    });

    assert.ok(container.innerHTML.includes('SHADOW : HELIX NEBULA'));
    assert.ok(container.innerHTML.includes('Operator Email'));
    assert.ok(container.innerHTML.includes('Password'));

    const emailInput = container.querySelector('#login-email');
    const passInput = container.querySelector('#login-password');
    const form = container.querySelector('#auth-form');

    assert.ok(emailInput !== null);
    assert.ok(passInput !== null);
    assert.ok(form !== null);
  });

  it('validates empty inputs and prevents API call with appropriate error', async () => {
    let apiCalled = false;
    mockApi.login = async () => { apiCalled = true; };

    renderLoginView(container as any, {
      api: mockApi,
      authStore,
      notify: notificationStore,
      onLoginSuccess: () => { loginSuccessCalled = true; },
    });

    const form = container.querySelector('#auth-form');
    let defaultPrevented = false;
    form?.dispatchEvent({
      type: 'submit',
      preventDefault: () => { defaultPrevented = true; },
    });

    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.equal(defaultPrevented, true);
    assert.equal(apiCalled, false);
    assert.ok(container.innerHTML.includes('Email and password are required.'));
  });

  it('preserves populated credentials and submits correctly on login', async () => {
    renderLoginView(container as any, {
      api: mockApi,
      authStore,
      notify: notificationStore,
      onLoginSuccess: () => { loginSuccessCalled = true; },
    });

    const emailInput = container.querySelector('#login-email');
    const passInput = container.querySelector('#login-password');
    assert.ok(emailInput && passInput);

    emailInput.value = 'operator@shn.sovereign';
    passInput.value = 'ValidPass123!';

    const form = container.querySelector('#auth-form');
    form?.dispatchEvent({
      type: 'submit',
      preventDefault: () => {},
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.equal(loginSuccessCalled, true);
    assert.equal(authStore.getState().isAuthenticated, true);
    assert.equal(authStore.getState().user?.email, 'operator@shn.sovereign');
    assert.equal(authStore.getState().token, 'mock-jwt-token-xyz');
  });

  it('handles invalid authentication credentials with error message', async () => {
    renderLoginView(container as any, {
      api: mockApi,
      authStore,
      notify: notificationStore,
      onLoginSuccess: () => { loginSuccessCalled = true; },
    });

    const emailInput = container.querySelector('#login-email');
    const passInput = container.querySelector('#login-password');
    assert.ok(emailInput && passInput);

    emailInput.value = 'operator@shn.sovereign';
    passInput.value = 'WrongPassword!';

    const form = container.querySelector('#auth-form');
    form?.dispatchEvent({
      type: 'submit',
      preventDefault: () => {},
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.equal(loginSuccessCalled, false);
    assert.equal(authStore.getState().isAuthenticated, false);
    assert.ok(container.innerHTML.includes('Invalid email or password.'));
  });
});
