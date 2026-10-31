/**
 * Shadow : Helix Nebula (SHN) — Personalization & UI Settings Store
 */

import type {
  PersonalizationSettings,
  ThemeMode,
  AccentColor,
  FontPreference,
  DensityPreference,
  BackgroundStyle,
  BundledWallpaper,
  AmbientSettings,
} from '../contracts.js';
import type { ApiClient } from '../services/api-client.js';

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
  wallpaperPreset: 'nebula-core',
  wallpaperOpacity: 0.5,
  wallpaperBlur: 6,
  overlayIntensity: 0.65,
};

export class SettingsStore {
  private settings: PersonalizationSettings;
  private readonly listeners = new Set<(settings: PersonalizationSettings) => void>();
  private apiClient: ApiClient | null = null;

  constructor(apiClient?: ApiClient) {
    this.apiClient = apiClient || null;
    this.settings = this.loadSettings();
    this.applyToDom();
  }

  setApiClient(api: ApiClient): void {
    this.apiClient = api;
    this.syncFromBackend();
  }

  async syncFromBackend(): Promise<void> {
    if (!this.apiClient) return;
    try {
      const prefs = await this.apiClient.getUserPreferences();
      if (prefs) {
        let theme: ThemeMode = 'night';
        if (prefs.theme === 'light') theme = 'day';
        else if (prefs.theme === 'ambient') theme = 'ambient';

        let accent: AccentColor = 'cyan';
        if (prefs.accentColor === 'emerald') accent = 'emerald';
        else if (prefs.accentColor === 'violet') accent = 'violet';
        else if (prefs.accentColor === 'amber') accent = 'amber';
        else if (prefs.accentColor === 'rose') accent = 'magenta';

        const layout = (prefs.dashboardLayout || {}) as Record<string, any>;
        const ambient = (layout.ambientSettings || {}) as Partial<AmbientSettings>;

        const updates: Partial<PersonalizationSettings> = {
          theme,
          accent,
          density: prefs.density === 'compact' ? 'compact' : 'comfortable',
          reducedMotion: Boolean(prefs.reducedMotion),
        };

        if (ambient.wallpaperPreset) updates.wallpaperPreset = ambient.wallpaperPreset;
        if (ambient.customWallpaperDataUrl) updates.customWallpaperDataUrl = ambient.customWallpaperDataUrl;
        if (typeof ambient.wallpaperOpacity === 'number') updates.wallpaperOpacity = ambient.wallpaperOpacity;
        if (typeof ambient.wallpaperBlur === 'number') updates.wallpaperBlur = ambient.wallpaperBlur;
        if (typeof ambient.overlayIntensity === 'number') updates.overlayIntensity = ambient.overlayIntensity;

        this.updateSettings(updates, false);
      }
    } catch {
      // Offline / unauthenticated fallback to local storage
    }
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

  updateSettings(updates: Partial<PersonalizationSettings>, persistToBackend = true): void {
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

    if (persistToBackend && this.apiClient) {
      const theme = this.settings.theme === 'day' ? 'light' : this.settings.theme === 'ambient' ? 'ambient' : 'cyber-operations';
      const accent = this.settings.accent === 'magenta' ? 'rose' : this.settings.accent;
      this.apiClient.saveUserPreferences({
        theme,
        accentColor: accent as any,
        density: this.settings.density,
        reducedMotion: this.settings.reducedMotion,
        dashboardLayout: {
          ambientSettings: {
            wallpaperPreset: this.settings.wallpaperPreset,
            customWallpaperDataUrl: this.settings.customWallpaperDataUrl,
            wallpaperOpacity: this.settings.wallpaperOpacity,
            wallpaperBlur: this.settings.wallpaperBlur,
            overlayIntensity: this.settings.overlayIntensity,
          },
        },
      }).catch(() => {
        // Backend sync failure silent fallback
      });
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

  setWallpaperPreset(wallpaperPreset: BundledWallpaper): void {
    this.updateSettings({ wallpaperPreset });
  }

  setCustomWallpaper(customWallpaperDataUrl: string): void {
    this.updateSettings({
      wallpaperPreset: 'custom',
      customWallpaperDataUrl,
    });
  }

  clearCustomWallpaper(): void {
    this.updateSettings({
      wallpaperPreset: 'nebula-core',
      customWallpaperDataUrl: undefined,
    });
  }

  setWallpaperOpacity(wallpaperOpacity: number): void {
    this.updateSettings({ wallpaperOpacity });
  }

  setWallpaperBlur(wallpaperBlur: number): void {
    this.updateSettings({ wallpaperBlur });
  }

  setOverlayIntensity(overlayIntensity: number): void {
    this.updateSettings({ overlayIntensity });
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
    root.setAttribute('data-wallpaper', this.settings.wallpaperPreset);

    root.style.setProperty('--bg-nebula-opacity', String(this.settings.backgroundOpacity));
    root.style.setProperty('--wallpaper-opacity', String(this.settings.wallpaperOpacity));
    root.style.setProperty('--wallpaper-blur', `${this.settings.wallpaperBlur}px`);
    root.style.setProperty('--overlay-center', String(Math.max(0, this.settings.overlayIntensity - 0.25)));
    root.style.setProperty('--overlay-edge', String(this.settings.overlayIntensity));

    const wallpaperEl = document.querySelector<HTMLElement>('#ambient-wallpaper-image');
    if (wallpaperEl) {
      if (this.settings.wallpaperPreset === 'custom' && this.settings.customWallpaperDataUrl) {
        wallpaperEl.style.backgroundImage = `url("${this.settings.customWallpaperDataUrl}")`;
      } else {
        wallpaperEl.style.backgroundImage = '';
      }
    }
  }
}
