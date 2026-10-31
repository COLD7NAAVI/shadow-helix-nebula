/**
 * Shadow : Helix Nebula (SHN) — Terminal View Unit Tests
 *
 * Verifies canonical capability dropdown selection, target resolution,
 * client-side scope enforcement (SEC-INV-08 & port bounds), single-dispatch guard,
 * and reliable SUCCEEDED state and timestamp rendering without undefined regressions.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { TerminalView } from '../../dist/views/terminal-view.js';
import { ApiClient } from '../../dist/index.js';
import { WorkspaceStore, AuthStore } from '../../dist/index.js';
import { NotificationStore } from '../../dist/state/notification-store.js';

// Minimal mock DOM Element for isolated unit testing
class MockElement {
  public tagName: string;
  public id: string = '';
  public value: string = '';
  public disabled: boolean = false;
  public textContent: string = '';
  public style: Record<string, string> = {};
  public dataset: Record<string, string> = {};
  public classList = {
    classes: new Set<string>(),
    add: (c: string) => this.classList.classes.add(c),
    remove: (c: string) => this.classList.classes.delete(c),
    contains: (c: string) => this.classList.classes.has(c),
  };
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

  querySelector<T extends MockElement>(selector: string): T | null {
    if (selector.startsWith('#')) {
      const targetId = selector.slice(1);
      return this.findChildById(this, targetId) as T | null;
    }
    return null;
  }

  querySelectorAll<T extends MockElement>(selector: string): T[] {
    const results: T[] = [];
    this.collectMatching(this, selector, results);
    return results;
  }

  closest(selector: string): MockElement | null {
    return this;
  }

  private collectMatching<T extends MockElement>(node: MockElement, selector: string, results: T[]): void {
    if (selector.startsWith('.') && node.classList.contains(selector.slice(1))) {
      results.push(node as unknown as T);
    }
    for (const child of node.children) {
      this.collectMatching(child, selector, results);
    }
  }

  private findChildById(node: MockElement, id: string): MockElement | null {
    if (node.id === id) return node;
    for (const child of node.children) {
      const match = this.findChildById(child, id);
      if (match) return match;
    }
    return null;
  }

  private parseSimpleElements(html: string): void {
    // Parse tags with id
    const tagRegex = /<([a-zA-Z0-9]+)([^>]*)>/g;
    let match: RegExpExecArray | null;

    while ((match = tagRegex.exec(html)) !== null) {
      const tag = match[1]!.toLowerCase();
      const attrs = match[2] || '';
      const el = new MockElement(tag);

      const idMatch = /id=["']([^"']+)["']/.exec(attrs);
      if (idMatch) el.id = idMatch[1]!;

      const valueMatch = /value=["']([^"']*)["']/.exec(attrs);
      if (valueMatch) el.value = valueMatch[1]!;

      const classMatch = /class=["']([^"']*)["']/.exec(attrs);
      if (classMatch) {
        classMatch[1]!.split(/\s+/).filter(Boolean).forEach((c) => el.classList.add(c));
      }

      const disabledMatch = /\bdisabled\b/.exec(attrs);
      if (disabledMatch) el.disabled = true;

      // Extract options if select
      if (tag === 'select') {
        const optionRegex = /<option\s+value=["']([^"']*)["'](?:\s+selected)?\s*>([^<]*)<\/option>/g;
        let optMatch: RegExpExecArray | null;
        let firstVal: string | null = null;
        while ((optMatch = optionRegex.exec(html)) !== null) {
          if (firstVal === null) firstVal = optMatch[1]!;
          const opt = new MockElement('option');
          opt.value = optMatch[1]!;
          opt.textContent = optMatch[2]!;
          el.children.push(opt);
        }
        if (firstVal !== null) {
          el.value = firstVal;
        }
      }

      this.children.push(el);
    }
  }
}

describe('TerminalView (Unit Tests)', () => {
  let mockApi: any;
  let workspaceStore: WorkspaceStore;
  let authStore: AuthStore;
  let notify: NotificationStore;
  let container: MockElement;

  const mockCapabilities = [
    {
      id: 'shn://capabilities/web/http-baseline',
      name: 'http-baseline',
      displayName: 'HTTP Service Baseline & Header Audit',
      version: '1.0.0',
      category: 'DISCOVERY',
      description: 'HTTP header and server banner baseline',
      state: 'ACTIVE',
    },
    {
      id: 'shn://capabilities/network/port-scan',
      name: 'network-port-scan',
      displayName: 'Network Port Scanner',
      version: '1.0.0',
      category: 'RECONNAISSANCE',
      description: 'TCP SYN port scanner',
      state: 'ACTIVE',
    },
  ];

  const mockScopes = [
    {
      id: 'scope-juice',
      name: 'OWASP Juice Shop Local Perimeter',
      inclusions: [{ type: 'IPV4', value: '127.0.0.1' }],
      exclusions: [{ type: 'IPV4', value: '169.254.169.254' }],
      allowed_actions: ['RECON_PASSIVE', 'PROBING_ACTIVE', 'PORT_SCAN'],
      port_ranges: [{ start: 3000, end: 3000 }],
    },
  ];

  const mockAssets = [
    {
      id: 'asset-1',
      name: 'OWASP Juice Shop — Local Docker',
      canonicalValue: '127.0.0.1',
      type: 'IPV4',
      criticality: 'LOW',
      status: 'ACTIVE',
    },
  ];

  let dispatchedPayloads: any[] = [];

  beforeEach(() => {
    dispatchedPayloads = [];

    const mockStorage = {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    };
    (globalThis as any).localStorage = mockStorage;

    mockApi = {
      listCapabilities: async () => mockCapabilities,
      listExecutions: async () => [],
      listAssets: async () => mockAssets,
      listScopes: async () => mockScopes,
      listWorkspaces: async () => [
        { id: 'ws-juice', name: 'Juice Shop — Local Lab', slug: 'juice-shop-local-lab' },
      ],
      switchWorkspace: async (id: string) => ({
        token: 'token-juice',
        workspaceId: id,
      }),
      dispatchExecution: async (wsId: string, input: any) => {
        dispatchedPayloads.push({ wsId, ...input });
        return {
          id: '01a190ef-test-exec-1234567890ab',
          executionId: '01a190ef-test-exec-1234567890ab',
          workspaceId: wsId,
          target: input.target,
          capabilityUri: input.capabilityUri,
          action: 'http:probe',
          state: 'SUCCEEDED',
          stdoutSummary: 'HTTP/1.1 200 OK\r\nServer: Juice Shop\r\n',
          stderrSummary: null,
          rawOutputSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          createdAt: new Date().toISOString(),
        };
      },
    };

    authStore = new AuthStore(mockApi as any);
    workspaceStore = new WorkspaceStore(mockApi as any, authStore);
    notify = new NotificationStore();
    container = new MockElement('div');
  });

  it('populates capability dropdown with canonical IDs and never undefined', async () => {
    await workspaceStore.loadWorkspaces();
    const view = new TerminalView(mockApi as any, workspaceStore, notify);

    view.mount(container as unknown as HTMLElement);
    // Allow Promise.all in loadData to complete
    await new Promise((resolve) => setTimeout(resolve, 50));

    const select = container.querySelector<MockElement>('#select-capability');
    assert.ok(select, 'Capability select must exist');
    assert.notEqual(select.value, 'undefined', 'Capability value must never be literal "undefined"');
    assert.strictEqual(select.value, 'shn://capabilities/web/http-baseline');
  });

  it('dispatches valid capability with canonical identifier and authorized target', async () => {
    await workspaceStore.loadWorkspaces();
    const view = new TerminalView(mockApi as any, workspaceStore, notify);

    view.mount(container as unknown as HTMLElement);
    await new Promise((resolve) => setTimeout(resolve, 50));

    const selectCap = container.querySelector<MockElement>('#select-capability')!;
    const inputTarget = container.querySelector<MockElement>('#input-target-custom')!;
    const inputPort = container.querySelector<MockElement>('#input-target-port')!;
    const btnDispatch = container.querySelector<MockElement>('#btn-dispatch-capability')!;

    selectCap.value = 'shn://capabilities/web/http-baseline';
    inputTarget.value = 'http://127.0.0.1:3000';
    inputPort.value = '3000';

    btnDispatch.dispatchEvent({ type: 'click' });
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.strictEqual(dispatchedPayloads.length, 1, 'Exactly one dispatch must be sent');
    assert.strictEqual(dispatchedPayloads[0].capabilityUri, 'shn://capabilities/web/http-baseline');
    assert.strictEqual(dispatchedPayloads[0].target, 'http://127.0.0.1:3000');
    assert.strictEqual(dispatchedPayloads[0].port, 3000);
  });

  it('blocks dispatch when target violates SEC-INV-08 cloud metadata', async () => {
    await workspaceStore.loadWorkspaces();
    const view = new TerminalView(mockApi as any, workspaceStore, notify);

    view.mount(container as unknown as HTMLElement);
    await new Promise((resolve) => setTimeout(resolve, 50));

    const selectCap = container.querySelector<MockElement>('#select-capability')!;
    const inputTarget = container.querySelector<MockElement>('#input-target-custom')!;
    const btnDispatch = container.querySelector<MockElement>('#btn-dispatch-capability')!;

    selectCap.value = 'shn://capabilities/web/http-baseline';
    inputTarget.value = 'http://169.254.169.254/latest/meta-data';

    btnDispatch.dispatchEvent({ type: 'click' });
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.strictEqual(dispatchedPayloads.length, 0, 'Must block cloud metadata pre-dispatch');
    const toast = notify.getToasts().find((t) => t.type === 'error');
    assert.ok(toast, 'Error toast must be shown');
    assert.ok(toast.message.includes('SEC-INV-08'), 'Error must cite SEC-INV-08');
  });

  it('blocks dispatch when target port violates scope boundaries', async () => {
    await workspaceStore.loadWorkspaces();
    const view = new TerminalView(mockApi as any, workspaceStore, notify);

    view.mount(container as unknown as HTMLElement);
    await new Promise((resolve) => setTimeout(resolve, 50));

    const selectCap = container.querySelector<MockElement>('#select-capability')!;
    const inputTarget = container.querySelector<MockElement>('#input-target-custom')!;
    const inputPort = container.querySelector<MockElement>('#input-target-port')!;
    const btnDispatch = container.querySelector<MockElement>('#btn-dispatch-capability')!;

    selectCap.value = 'shn://capabilities/web/http-baseline';
    inputTarget.value = 'http://127.0.0.1:8080';
    inputPort.value = '8080';

    btnDispatch.dispatchEvent({ type: 'click' });
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.strictEqual(dispatchedPayloads.length, 0, 'Must block out-of-scope port 8080 pre-dispatch');
    const toast = notify.getToasts().find((t) => t.type === 'error');
    assert.ok(toast, 'Error toast must be shown');
    assert.ok(toast.message.includes('outside authorized port range'), 'Error must cite port range');
  });

  it('rejects missing or undefined capability without making dispatch call', async () => {
    await workspaceStore.loadWorkspaces();
    const view = new TerminalView(mockApi as any, workspaceStore, notify);

    view.mount(container as unknown as HTMLElement);
    await new Promise((resolve) => setTimeout(resolve, 50));

    const selectCap = container.querySelector<MockElement>('#select-capability')!;
    const btnDispatch = container.querySelector<MockElement>('#btn-dispatch-capability')!;

    selectCap.value = 'undefined';

    btnDispatch.dispatchEvent({ type: 'click' });
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.strictEqual(dispatchedPayloads.length, 0, 'Must not dispatch with literal "undefined" capability');
    const toast = notify.getToasts().find((t) => t.type === 'warning');
    assert.ok(toast, 'Warning toast must be shown');
  });

  it('renders execution output with SUCCEEDED state and valid timestamp', async () => {
    await workspaceStore.loadWorkspaces();
    const view = new TerminalView(mockApi as any, workspaceStore, notify);

    view.mount(container as unknown as HTMLElement);
    await new Promise((resolve) => setTimeout(resolve, 50));

    const btnDispatch = container.querySelector<MockElement>('#btn-dispatch-capability')!;
    btnDispatch.dispatchEvent({ type: 'click' });
    await new Promise((resolve) => setTimeout(resolve, 50));

    const viewport = container.querySelector<MockElement>('#terminal-viewport-container');
    assert.ok(viewport, 'Terminal viewport container must exist');
    assert.ok(viewport.innerHTML.includes('SUCCEEDED'), 'Must render SUCCEEDED state');
    assert.ok(!viewport.innerHTML.includes('Dispatched At: undefined'), 'Must never render "Dispatched At: undefined"');
    assert.ok(!viewport.innerHTML.includes('Target: undefined'), 'Must never render "Target: undefined"');
  });
});
