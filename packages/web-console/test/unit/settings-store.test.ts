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
    assert.equal(settings.wallpaperPreset, 'nebula-core');
    assert.equal(settings.wallpaperOpacity, 0.5);
    assert.equal(settings.wallpaperBlur, 6);
    assert.equal(settings.overlayIntensity, 0.65);
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

  it('updates ambient wallpaper presets and persists to storage', () => {
    const store = new SettingsStore();

    store.setWallpaperPreset('cyber-matrix');
    assert.equal(store.getSettings().wallpaperPreset, 'cyber-matrix');

    const stored = JSON.parse(mockStorage.getItem('shn_personalization_v1') || '{}');
    assert.equal(stored.wallpaperPreset, 'cyber-matrix');

    store.setWallpaperPreset('solar-corona');
    assert.equal(store.getSettings().wallpaperPreset, 'solar-corona');
  });

  it('configures custom local image wallpaper and restores properly', () => {
    const store = new SettingsStore();
    const mockDataUrl = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

    store.setCustomWallpaper(mockDataUrl);
    assert.equal(store.getSettings().wallpaperPreset, 'custom');
    assert.equal(store.getSettings().customWallpaperDataUrl, mockDataUrl);

    const stored = JSON.parse(mockStorage.getItem('shn_personalization_v1') || '{}');
    assert.equal(stored.wallpaperPreset, 'custom');
    assert.equal(stored.customWallpaperDataUrl, mockDataUrl);

    store.clearCustomWallpaper();
    assert.equal(store.getSettings().wallpaperPreset, 'nebula-core');
    assert.equal(store.getSettings().customWallpaperDataUrl, undefined);
  });

  it('configures wallpaper opacity, blur, and overlay intensity', () => {
    const store = new SettingsStore();

    store.setWallpaperOpacity(0.8);
    assert.equal(store.getSettings().wallpaperOpacity, 0.8);

    store.setWallpaperBlur(12);
    assert.equal(store.getSettings().wallpaperBlur, 12);

    store.setOverlayIntensity(0.75);
    assert.equal(store.getSettings().overlayIntensity, 0.75);

    const stored = JSON.parse(mockStorage.getItem('shn_personalization_v1') || '{}');
    assert.equal(stored.wallpaperOpacity, 0.8);
    assert.equal(stored.wallpaperBlur, 12);
    assert.equal(stored.overlayIntensity, 0.75);
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
        wallpaperPreset: 'tactical-carbon',
        wallpaperOpacity: 0.7,
        wallpaperBlur: 10,
        overlayIntensity: 0.8,
      })
    );

    const store = new SettingsStore();
    const s = store.getSettings();

    assert.equal(s.theme, 'day');
    assert.equal(s.accent, 'emerald');
    assert.equal(s.font, 'mono');
    assert.equal(s.density, 'compact');
    assert.equal(s.reducedMotion, true);
    assert.equal(s.wallpaperPreset, 'tactical-carbon');
    assert.equal(s.wallpaperOpacity, 0.7);
    assert.equal(s.wallpaperBlur, 10);
    assert.equal(s.overlayIntensity, 0.8);
  });
});
