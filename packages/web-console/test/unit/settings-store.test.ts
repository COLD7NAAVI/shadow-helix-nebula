/**
 * Shadow : Helix Nebula (SHN) — SettingsStore Unit Tests
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { SettingsStore } from '../../dist/index.js';

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

describe('SettingsStore (Unit Tests)', () => {
  let mockStorage: MockStorage;

  beforeEach(() => {
    mockStorage = new MockStorage();
    (globalThis as any).localStorage = mockStorage;
  });

  it('initializes with default signature Helix Nebula settings', () => {
    const store = new SettingsStore();
    const settings = store.getSettings();

    assert.equal(settings.theme, 'night');
    assert.equal(settings.accent, 'cyan');
    assert.equal(settings.font, 'sans');
    assert.equal(settings.density, 'comfortable');
    assert.equal(settings.reducedMotion, false);
    assert.equal(settings.backgroundOpacity, 0.85);
    assert.equal(settings.backgroundStyle, 'nebula');
  });

  it('updates theme mode and notifies subscribers', () => {
    const store = new SettingsStore();
    let updatedTheme = '';

    store.subscribe((s) => {
      updatedTheme = s.theme;
    });

    store.setTheme('ambient');
    assert.equal(updatedTheme, 'ambient');
    assert.equal(store.getSettings().theme, 'ambient');

    store.setTheme('day');
    assert.equal(updatedTheme, 'day');
    assert.equal(store.getSettings().theme, 'day');
  });

  it('updates accent colors and persists to localStorage', () => {
    const store = new SettingsStore();
    store.setAccent('violet');

    assert.equal(store.getSettings().accent, 'violet');

    const stored = JSON.parse(mockStorage.getItem('shn_personalization_v1') || '{}');
    assert.equal(stored.accent, 'violet');
  });

  it('toggles reduced motion, typography, and display density', () => {
    const store = new SettingsStore();

    store.setReducedMotion(true);
    assert.equal(store.getSettings().reducedMotion, true);

    store.setFont('mono');
    assert.equal(store.getSettings().font, 'mono');

    store.setDensity('compact');
    assert.equal(store.getSettings().density, 'compact');
  });

  it('restores settings from persisted storage', () => {
    mockStorage.setItem(
      'shn_personalization_v1',
      JSON.stringify({
        theme: 'day',
        accent: 'emerald',
        font: 'mono',
        density: 'compact',
        reducedMotion: true,
      })
    );

    const store = new SettingsStore();
    const s = store.getSettings();

    assert.equal(s.theme, 'day');
    assert.equal(s.accent, 'emerald');
    assert.equal(s.font, 'mono');
    assert.equal(s.density, 'compact');
    assert.equal(s.reducedMotion, true);
  });
});
