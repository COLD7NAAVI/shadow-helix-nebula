/**
 * Shadow : Helix Nebula (SHN) — Personalization & UI Settings Store
 */

import type { PersonalizationSettings, ThemeMode, AccentColor, FontPreference, DensityPreference, BackgroundStyle } from '../contracts.js';

const STORAGE_KEY = 'shn_personalization_v1';

const DEFAULT_SETTINGS: PersonalizationSettings = {
  theme: 'night',
  accent: 'cyan',
  font: 'sans',
  density: 'comfortable',
  reducedMotion: false,
  backgroundOpacity: 0.85,
  backgroundStyle: 'nebula',
  refreshIntervalSeconds: 30,
};

export class SettingsStore {
  private settings: PersonalizationSettings;
  private readonly listeners = new Set<(settings: PersonalizationSettings) => void>();

  constructor() {
    this.settings = this.loadSettings();
    this.applyToDom();
  }

  private loadSettings(): PersonalizationSettings {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        return { ...DEFAULT_SETTINGS, ...JSON.parse(stored) };
      }
    } catch {
      // Fallback to default
    }
    return { ...DEFAULT_SETTINGS };
  }

  getSettings(): PersonalizationSettings {
    return { ...this.settings };
  }

  subscribe(listener: (settings: PersonalizationSettings) => void): () => void {
    this.listeners.add(listener);
    listener(this.getSettings());
    return () => this.listeners.delete(listener);
  }

  updateSettings(updates: Partial<PersonalizationSettings>): void {
    this.settings = { ...this.settings, ...updates };
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.settings));
    } catch {
      // Storage unavailable
    }
    this.applyToDom();
    for (const listener of this.listeners) {
      listener(this.getSettings());
    }
  }

  setTheme(theme: ThemeMode): void {
    this.updateSettings({ theme });
  }

  setAccent(accent: AccentColor): void {
    this.updateSettings({ accent });
  }

  setFont(font: FontPreference): void {
    this.updateSettings({ font });
  }

  setDensity(density: DensityPreference): void {
    this.updateSettings({ density });
  }

  setReducedMotion(reducedMotion: boolean): void {
    this.updateSettings({ reducedMotion });
  }

  setBackgroundOpacity(backgroundOpacity: number): void {
    this.updateSettings({ backgroundOpacity });
  }

  setBackgroundStyle(backgroundStyle: BackgroundStyle): void {
    this.updateSettings({ backgroundStyle });
  }

  private applyToDom(): void {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;

    root.setAttribute('data-theme', this.settings.theme);
    root.setAttribute('data-accent', this.settings.accent);
    root.setAttribute('data-font', this.settings.font);
    root.setAttribute('data-density', this.settings.density);
    root.setAttribute('data-reduced-motion', String(this.settings.reducedMotion));
    root.setAttribute('data-bg-style', this.settings.backgroundStyle);

    root.style.setProperty('--bg-nebula-opacity', String(this.settings.backgroundOpacity));
  }
}
