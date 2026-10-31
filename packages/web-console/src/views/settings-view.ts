/**
 * Shadow : Helix Nebula (SHN) — Settings & Personalization View
 *
 * Implements Day/Night/Ambient themes, cosmic accent palettes,
 * typography selection, density toggles, accessibility settings,
 * and SecurityContext token inspection.
 */

import type { SettingsStore } from '../state/settings-store.js';
import type { AuthStore } from '../state/auth-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type {
  ThemeMode,
  AccentColor,
  FontPreference,
  DensityPreference,
  BackgroundStyle,
  BundledWallpaper,
} from '../contracts.js';

export class SettingsView {
  private container: HTMLElement | null = null;
  private unsubscribeSettings: (() => void) | null = null;
  private unsubscribeAuth: (() => void) | null = null;

  constructor(
    private readonly settingsStore: SettingsStore,
    private readonly authStore: AuthStore,
    private readonly notificationStore: NotificationStore
  ) {}

  mount(target: HTMLElement): void {
    this.container = target;
    this.render();
    this.unsubscribeSettings = this.settingsStore.subscribe(() => {
      this.render();
    });
    this.unsubscribeAuth = this.authStore.subscribe(() => {
      this.render();
    });
  }

  unmount(): void {
    if (this.unsubscribeSettings) {
      this.unsubscribeSettings();
      this.unsubscribeSettings = null;
    }
    if (this.unsubscribeAuth) {
      this.unsubscribeAuth();
      this.unsubscribeAuth = null;
    }
    this.container = null;
  }

  private render(): void {
    if (!this.container) return;
    const settings = this.settingsStore.getSettings();
    const authState = this.authStore.getState();

    const themes: Array<{ id: ThemeMode; label: string; desc: string; icon: string }> = [
      { id: 'night', label: 'Night (Deep Space)', desc: 'Signature deep cosmic dark palette with glassmorphism', icon: '🌌' },
      { id: 'ambient', label: 'Ambient (Atmospheric)', desc: 'Translucent high-contrast nebula glow and soft surfaces', icon: '✨' },
      { id: 'day', label: 'Day (Professional)', desc: 'Clean, bright, crisp high-readability daylight interface', icon: '☀️' },
    ];

    const accents: Array<{ id: AccentColor; label: string; color: string }> = [
      { id: 'cyan', label: 'Sovereign Cyan', color: '#06b6d4' },
      { id: 'violet', label: 'Nebula Violet', color: '#8b5cf6' },
      { id: 'magenta', label: 'Pulsar Magenta', color: '#ec4899' },
      { id: 'emerald', label: 'Defensive Emerald', color: '#10b981' },
      { id: 'amber', label: 'Solar Amber', color: '#f59e0b' },
    ];

    const wallpapers: Array<{ id: BundledWallpaper; label: string; desc: string; icon: string; preview: string }> = [
      { id: 'nebula-core', label: 'Nebula Core', desc: 'Signature deep violet & cyan filaments', icon: '🌌', preview: 'radial-gradient(circle at 30% 30%, #8b5cf6, #06b6d4 60%, #050814)' },
      { id: 'cyber-matrix', label: 'Cyber Matrix', desc: 'Neon isometric defense grid', icon: '⚡', preview: 'linear-gradient(45deg, #00f0ff 10%, #020712 90%)' },
      { id: 'quantum-aurora', label: 'Quantum Aurora', desc: 'Polar emerald & violet wave', icon: '🌠', preview: 'radial-gradient(circle at 70% 30%, #10b981, #8b5cf6 60%, #04090c)' },
      { id: 'solar-corona', label: 'Solar Corona', desc: 'Radiant amber coronal flares', icon: '☀️', preview: 'radial-gradient(circle at 80% 20%, #f59e0b, #ef4444 60%, #0d0604)' },
      { id: 'tactical-carbon', label: 'Tactical Carbon', desc: 'Stealth carbon fiber weave', icon: '🛡️', preview: 'linear-gradient(135deg, #27272a 0%, #090a0f 100%)' },
      { id: 'obsidian-void', label: 'Obsidian Void', desc: 'Deep space void with soft horizon', icon: '🌑', preview: 'linear-gradient(180deg, #1e293b 0%, #020617 100%)' },
    ];

    this.container.innerHTML = `
      <div class="view-header" style="margin-bottom: 1.5rem;">
        <div style="font-size: 0.8125rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--color-accent); margin-bottom: 0.25rem;">
          Platform Configuration & Aesthetics
        </div>
        <h1 style="margin: 0; font-size: 1.75rem; font-weight: 700; color: var(--color-text-primary);">
          Settings & Personalization
        </h1>
        <p style="margin: 0.25rem 0 0 0; font-size: 0.875rem; color: var(--color-text-secondary);">
          Customize the Helix Nebula signature design system, typography, display density, ambient mode wallpapers, and inspect your sovereign identity.
        </p>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem;">
        <!-- Theme & Visual Appearance -->
        <div class="card" style="padding: 1.5rem;">
          <h2 style="margin: 0 0 1rem 0; font-size: 1.125rem; font-weight: 600; color: var(--color-text-primary); display: flex; align-items: center; gap: 0.5rem;">
            <span>🎨</span> Theme & Visual Palette
          </h2>

          <!-- Theme Selector -->
          <div style="margin-bottom: 1.5rem;">
            <label style="display: block; font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); margin-bottom: 0.5rem; text-transform: uppercase;">
              Interface Theme Mode
            </label>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem;">
              ${themes.map(t => `
                <button
                  class="btn-theme-select card"
                  data-theme-id="${t.id}"
                  style="cursor: pointer; padding: 1rem 0.75rem; text-align: center; border: 2px solid ${settings.theme === t.id ? 'var(--color-accent)' : 'var(--color-border)'}; background: ${settings.theme === t.id ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'}; transition: all 0.2s ease;"
                >
                  <div style="font-size: 1.5rem; margin-bottom: 0.25rem;">${t.icon}</div>
                  <div style="font-weight: 600; font-size: 0.8125rem; color: var(--color-text-primary);">${t.label.split(' ')[0]}</div>
                  <div style="font-size: 0.6875rem; color: var(--color-text-muted); margin-top: 0.25rem;">${t.id.toUpperCase()}</div>
                </button>
              `).join('')}
            </div>
          </div>

          <!-- Accent Color Selector -->
          <div style="margin-bottom: 1.5rem;">
            <label style="display: block; font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); margin-bottom: 0.5rem; text-transform: uppercase;">
              Accent Color
            </label>
            <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
              ${accents.map(a => `
                <button
                  class="btn-accent-select"
                  data-accent-id="${a.id}"
                  style="cursor: pointer; display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.875rem; border-radius: var(--radius-md); border: 1.5px solid ${settings.accent === a.id ? a.color : 'var(--color-border)'}; background: ${settings.accent === a.id ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'}; transition: all 0.2s ease;"
                >
                  <div style="width: 14px; height: 14px; border-radius: 50%; background: ${a.color}; box-shadow: 0 0 6px ${a.color};"></div>
                  <span style="font-size: 0.8125rem; font-weight: 500; color: var(--color-text-primary);">${a.label.split(' ')[1] || a.label}</span>
                </button>
              `).join('')}
            </div>
          </div>

          <!-- Cosmic Background Particle Style -->
          <div style="margin-bottom: 1.5rem;">
            <label style="display: block; font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); margin-bottom: 0.5rem; text-transform: uppercase;">
              Canvas Particle Atmosphere
            </label>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem;">
              ${(['nebula', 'starfield', 'void'] as BackgroundStyle[]).map(s => `
                <button
                  class="btn-bg-style"
                  data-bg-style="${s}"
                  style="cursor: pointer; padding: 0.625rem; text-align: center; border-radius: var(--radius-md); border: 1.5px solid ${settings.backgroundStyle === s ? 'var(--color-accent)' : 'var(--color-border)'}; background: ${settings.backgroundStyle === s ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'};"
                >
                  <span style="font-size: 0.8125rem; font-weight: 600; text-transform: capitalize; color: var(--color-text-primary);">${s}</span>
                </button>
              `).join('')}
            </div>
          </div>

          <!-- Particle Canvas Opacity Slider -->
          <div style="margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
              <label style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); text-transform: uppercase;">
                Particle Scintillation Opacity
              </label>
              <span id="opacity-val" style="font-family: var(--font-mono); font-size: 0.8125rem; color: var(--color-accent);">
                ${Math.round(settings.backgroundOpacity * 100)}%
              </span>
            </div>
            <input
              type="range"
              id="input-bg-opacity"
              min="10"
              max="100"
              value="${Math.round(settings.backgroundOpacity * 100)}"
              style="width: 100%; accent-color: var(--color-accent);"
            />
          </div>
        </div>

        <!-- Ambient Mode Wallpapers & Background Atmosphere -->
        <div class="card" style="padding: 1.5rem;">
          <h2 style="margin: 0 0 1rem 0; font-size: 1.125rem; font-weight: 600; color: var(--color-text-primary); display: flex; align-items: center; gap: 0.5rem;">
            <span>🖼️</span> Ambient Wallpapers & Atmosphere
          </h2>

          <!-- Wallpaper Presets Grid -->
          <div style="margin-bottom: 1.25rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
              <label style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); text-transform: uppercase;">
                Wallpaper Presets (${wallpapers.length} Bundled)
              </label>
              ${settings.wallpaperPreset === 'custom' ? `
                <span class="badge" style="background: var(--accent-subtle); color: var(--accent-primary); font-size: 10px;">
                  CUSTOM IMAGE ACTIVE
                </span>
              ` : ''}
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 0.75rem;">
              ${wallpapers.map(w => `
                <button
                  class="btn-wallpaper-select card"
                  data-wallpaper-id="${w.id}"
                  style="cursor: pointer; padding: 0.625rem; text-align: center; border: 2px solid ${settings.wallpaperPreset === w.id ? 'var(--color-accent)' : 'var(--color-border)'}; background: ${settings.wallpaperPreset === w.id ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'}; border-radius: var(--radius-md); transition: all 0.2s ease;"
                  title="${w.desc}"
                >
                  <div style="width: 100%; height: 36px; border-radius: var(--radius-xs); background: ${w.preview}; margin-bottom: 0.375rem; border: 1px solid rgba(255,255,255,0.15);"></div>
                  <div style="font-weight: 600; font-size: 0.75rem; color: var(--color-text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    ${w.label}
                  </div>
                </button>
              `).join('')}
            </div>
          </div>

          <!-- Local Image Upload Section -->
          <div style="margin-bottom: 1.25rem; padding: 1rem; background: var(--color-surface-sunken); border-radius: var(--radius-md); border: 1px solid var(--color-border);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
              <span style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-primary);">
                📁 Custom Local Wallpaper
              </span>
              <input type="file" id="input-custom-wallpaper" accept="image/*" style="display: none;" />
              <div style="display: flex; gap: 8px;">
                <button id="btn-trigger-upload" class="btn btn-secondary btn-sm" style="font-size: 11px;">
                  Upload Image...
                </button>
                ${settings.customWallpaperDataUrl ? `
                  <button id="btn-clear-wallpaper" class="btn btn-ghost btn-sm" style="font-size: 11px; color: var(--color-critical);">
                    Clear
                  </button>
                ` : ''}
              </div>
            </div>
            <div style="font-size: 0.75rem; color: var(--color-text-muted);">
              ${settings.customWallpaperDataUrl
                ? 'Custom image loaded and persisted in browser local storage & workspace profile.'
                : 'Select any PNG, JPG, or SVG image from your local system. Stored securely.'}
            </div>
          </div>

          <!-- Wallpaper Opacity Slider -->
          <div style="margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.375rem;">
              <label style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); text-transform: uppercase;">
                Wallpaper Opacity
              </label>
              <span id="wallpaper-opacity-val" style="font-family: var(--font-mono); font-size: 0.8125rem; color: var(--color-accent);">
                ${Math.round(settings.wallpaperOpacity * 100)}%
              </span>
            </div>
            <input
              type="range"
              id="input-wallpaper-opacity"
              min="10"
              max="100"
              value="${Math.round(settings.wallpaperOpacity * 100)}"
              style="width: 100%; accent-color: var(--color-accent);"
            />
          </div>

          <!-- Wallpaper Blur Slider -->
          <div style="margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.375rem;">
              <label style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); text-transform: uppercase;">
                Wallpaper Backdrop Blur
              </label>
              <span id="wallpaper-blur-val" style="font-family: var(--font-mono); font-size: 0.8125rem; color: var(--color-accent);">
                ${settings.wallpaperBlur}px
              </span>
            </div>
            <input
              type="range"
              id="input-wallpaper-blur"
              min="0"
              max="24"
              value="${settings.wallpaperBlur}"
              style="width: 100%; accent-color: var(--color-accent);"
            />
          </div>

          <!-- Contrast Overlay Intensity Slider -->
          <div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.375rem;">
              <label style="font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); text-transform: uppercase;">
                Dark Contrast Vignette Overlay
              </label>
              <span id="overlay-intensity-val" style="font-family: var(--font-mono); font-size: 0.8125rem; color: var(--color-accent);">
                ${Math.round(settings.overlayIntensity * 100)}%
              </span>
            </div>
            <input
              type="range"
              id="input-overlay-intensity"
              min="0"
              max="90"
              value="${Math.round(settings.overlayIntensity * 100)}"
              style="width: 100%; accent-color: var(--color-accent);"
            />
          </div>
        </div>

        <!-- Typography & Layout Controls -->
        <div class="card" style="padding: 1.5rem;">
          <h2 style="margin: 0 0 1rem 0; font-size: 1.125rem; font-weight: 600; color: var(--color-text-primary); display: flex; align-items: center; gap: 0.5rem;">
            <span>📐</span> Layout & Accessibility
          </h2>

          <!-- Font Preference -->
          <div style="margin-bottom: 1.5rem;">
            <label style="display: block; font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); margin-bottom: 0.5rem; text-transform: uppercase;">
              Interface Typography
            </label>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
              <button
                class="btn-font-select"
                data-font="sans"
                style="cursor: pointer; padding: 0.75rem; text-align: left; border-radius: var(--radius-md); border: 1.5px solid ${settings.font === 'sans' ? 'var(--color-accent)' : 'var(--color-border)'}; background: ${settings.font === 'sans' ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'};"
              >
                <div style="font-weight: 600; font-size: 0.875rem; color: var(--color-text-primary); font-family: 'Inter', sans-serif;">Inter / Outfit</div>
                <div style="font-size: 0.6875rem; color: var(--color-text-muted); margin-top: 0.25rem;">Modern Variable Sans</div>
              </button>

              <button
                class="btn-font-select"
                data-font="mono"
                style="cursor: pointer; padding: 0.75rem; text-align: left; border-radius: var(--radius-md); border: 1.5px solid ${settings.font === 'mono' ? 'var(--color-accent)' : 'var(--color-border)'}; background: ${settings.font === 'mono' ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'};"
              >
                <div style="font-weight: 600; font-size: 0.875rem; color: var(--color-text-primary); font-family: 'JetBrains Mono', monospace;">JetBrains Mono</div>
                <div style="font-size: 0.6875rem; color: var(--color-text-muted); margin-top: 0.25rem;">Technical Monospace</div>
              </button>
            </div>
          </div>

          <!-- Density Preference -->
          <div style="margin-bottom: 1.5rem;">
            <label style="display: block; font-size: 0.8125rem; font-weight: 600; color: var(--color-text-secondary); margin-bottom: 0.5rem; text-transform: uppercase;">
              Display Density
            </label>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
              <button
                class="btn-density-select"
                data-density="comfortable"
                style="cursor: pointer; padding: 0.75rem; text-align: left; border-radius: var(--radius-md); border: 1.5px solid ${settings.density === 'comfortable' ? 'var(--color-accent)' : 'var(--color-border)'}; background: ${settings.density === 'comfortable' ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'};"
              >
                <div style="font-weight: 600; font-size: 0.875rem; color: var(--color-text-primary);">Comfortable</div>
                <div style="font-size: 0.6875rem; color: var(--color-text-muted); margin-top: 0.25rem;">Standard padding & row spacing</div>
              </button>

              <button
                class="btn-density-select"
                data-density="compact"
                style="cursor: pointer; padding: 0.75rem; text-align: left; border-radius: var(--radius-md); border: 1.5px solid ${settings.density === 'compact' ? 'var(--color-accent)' : 'var(--color-border)'}; background: ${settings.density === 'compact' ? 'var(--color-surface-elevated)' : 'var(--color-surface-sunken)'};"
              >
                <div style="font-weight: 600; font-size: 0.875rem; color: var(--color-text-primary);">Compact</div>
                <div style="font-size: 0.6875rem; color: var(--color-text-muted); margin-top: 0.25rem;">Dense high-information layout</div>
              </button>
            </div>
          </div>

          <!-- Accessibility: Reduced Motion -->
          <div style="margin-bottom: 1.5rem; padding: 1rem; background: var(--color-surface-sunken); border-radius: var(--radius-md); border: 1px solid var(--color-border); display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-weight: 600; font-size: 0.875rem; color: var(--color-text-primary);">Reduced Motion</div>
              <div style="font-size: 0.75rem; color: var(--color-text-muted);">Freezes nebula canvas particles and minimizes CSS transitions.</div>
            </div>
            <label style="cursor: pointer; display: flex; align-items: center;">
              <input
                type="checkbox"
                id="checkbox-reduced-motion"
                ${settings.reducedMotion ? 'checked' : ''}
                style="width: 18px; height: 18px; accent-color: var(--color-accent);"
              />
            </label>
          </div>

          <!-- Reset Defaults -->
          <div style="display: flex; justify-content: flex-end;">
            <button id="btn-reset-settings" class="btn btn-secondary btn-sm">
              Restore Default Settings
            </button>
          </div>
        </div>

        <!-- Operator Identity & Security Context -->
        <div class="card" style="padding: 1.5rem; grid-column: 1 / -1;">
          <h2 style="margin: 0 0 1rem 0; font-size: 1.125rem; font-weight: 600; color: var(--color-text-primary); display: flex; align-items: center; gap: 0.5rem;">
            <span>🛡️</span> Sovereign Operator Identity & SecurityContext
          </h2>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
            <div style="background: var(--color-surface-sunken); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
              <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Operator Email</div>
              <div style="font-weight: 600; font-size: 0.875rem; color: var(--color-text-primary); margin-top: 0.25rem;">
                ${authState.user?.email || 'operator@shn.sovereign'}
              </div>
            </div>

            <div style="background: var(--color-surface-sunken); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
              <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Display Name</div>
              <div style="font-weight: 600; font-size: 0.875rem; color: var(--color-text-primary); margin-top: 0.25rem;">
                ${authState.user?.displayName || 'Helix Sovereign Operator'}
              </div>
            </div>

            <div style="background: var(--color-surface-sunken); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
              <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Assigned Roles</div>
              <div style="display: flex; gap: 0.25rem; flex-wrap: wrap; margin-top: 0.25rem;">
                ${(authState.roles.length > 0 ? authState.roles : ['ORG_ADMIN']).map(r => `
                  <span class="badge badge-accent" style="font-size: 0.6875rem;">${r}</span>
                `).join('')}
              </div>
            </div>

            <div style="background: var(--color-surface-sunken); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
              <div style="font-size: 0.6875rem; text-transform: uppercase; color: var(--color-text-muted); font-weight: 600;">Session State</div>
              <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.25rem;">
                <div style="width: 8px; height: 8px; border-radius: 50%; background: var(--color-emerald-500);"></div>
                <span style="font-size: 0.875rem; font-weight: 500; color: var(--color-text-primary);">Authenticated</span>
              </div>
            </div>
          </div>

          <!-- Bearer Token Inspection -->
          <div style="background: var(--color-surface-sunken); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--color-border);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
              <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--color-text-secondary);">
                Active SecurityContextToken (Bearer)
              </div>
              <button id="btn-copy-token" class="btn btn-secondary btn-sm" style="font-size: 0.75rem;">
                Copy Token
              </button>
            </div>
            <pre style="margin: 0; padding: 0.75rem; background: var(--color-surface-elevated); border: 1px solid var(--color-border); border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-text-secondary); word-break: break-all; white-space: pre-wrap; max-height: 80px; overflow-y: auto;">${authState.token || 'Bearer token not initialized'}</pre>
          </div>

          <!-- Session Sign-out -->
          <div style="margin-top: 1.5rem; display: flex; justify-content: flex-end;">
            <button id="btn-sign-out" class="btn btn-danger btn-sm">
              Sign Out & Terminate Session
            </button>
          </div>
        </div>
      </div>
    `;

    this.bindEvents();
  }

  private bindEvents(): void {
    if (!this.container) return;

    // Theme selection
    this.container.querySelectorAll<HTMLButtonElement>('.btn-theme-select').forEach(btn => {
      btn.addEventListener('click', () => {
        const t = btn.dataset.themeId as ThemeMode;
        if (t) {
          this.settingsStore.setTheme(t);
          this.notificationStore.notify({
            type: 'info',
            title: 'Theme Applied',
            message: `Switched theme to ${t.toUpperCase()}.`,
          });
        }
      });
    });

    // Accent selection
    this.container.querySelectorAll<HTMLButtonElement>('.btn-accent-select').forEach(btn => {
      btn.addEventListener('click', () => {
        const a = btn.dataset.accentId as AccentColor;
        if (a) {
          this.settingsStore.setAccent(a);
        }
      });
    });

    // Background style
    this.container.querySelectorAll<HTMLButtonElement>('.btn-bg-style').forEach(btn => {
      btn.addEventListener('click', () => {
        const s = btn.dataset.bgStyle as BackgroundStyle;
        if (s) {
          this.settingsStore.setBackgroundStyle(s);
        }
      });
    });

    // Opacity slider
    const opacityInput = this.container.querySelector<HTMLInputElement>('#input-bg-opacity');
    opacityInput?.addEventListener('input', (e) => {
      const val = parseInt((e.target as HTMLInputElement).value, 10);
      const span = this.container?.querySelector('#opacity-val');
      if (span) span.textContent = `${val}%`;
      this.settingsStore.setBackgroundOpacity(val / 100);
    });

    // Wallpaper Preset selection
    this.container.querySelectorAll<HTMLButtonElement>('.btn-wallpaper-select').forEach(btn => {
      btn.addEventListener('click', () => {
        const wid = btn.dataset.wallpaperId as BundledWallpaper;
        if (wid) {
          this.settingsStore.setWallpaperPreset(wid);
          this.notificationStore.notify({
            type: 'info',
            title: 'Wallpaper Updated',
            message: `Active wallpaper switched to ${wid}.`,
          });
        }
      });
    });

    // Custom Wallpaper Upload
    const uploadInput = this.container.querySelector<HTMLInputElement>('#input-custom-wallpaper');
    this.container.querySelector('#btn-trigger-upload')?.addEventListener('click', () => {
      uploadInput?.click();
    });

    uploadInput?.addEventListener('change', (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      if (!file.type.startsWith('image/')) {
        this.notificationStore.notify({
          type: 'error',
          title: 'Invalid File',
          message: 'Please select a valid image file (PNG, JPG, SVG, WEBP).',
        });
        return;
      }

      const reader = new FileReader();
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          this.settingsStore.setCustomWallpaper(reader.result);
          this.notificationStore.notify({
            type: 'success',
            title: 'Custom Wallpaper Active',
            message: `Loaded custom image (${Math.round(file.size / 1024)} KB) and persisted to profile.`,
          });
        }
      };
      reader.onerror = () => {
        this.notificationStore.notify({
          type: 'error',
          title: 'Read Failed',
          message: 'Failed to read selected local image file.',
        });
      };
      reader.readAsDataURL(file);
    });

    // Clear Custom Wallpaper
    this.container.querySelector('#btn-clear-wallpaper')?.addEventListener('click', () => {
      this.settingsStore.clearCustomWallpaper();
      this.notificationStore.notify({
        type: 'info',
        title: 'Custom Wallpaper Cleared',
        message: 'Reverted to default bundled wallpaper.',
      });
    });

    // Wallpaper Opacity Slider
    const wallOpacityInput = this.container.querySelector<HTMLInputElement>('#input-wallpaper-opacity');
    wallOpacityInput?.addEventListener('input', (e) => {
      const val = parseInt((e.target as HTMLInputElement).value, 10);
      const span = this.container?.querySelector('#wallpaper-opacity-val');
      if (span) span.textContent = `${val}%`;
      this.settingsStore.setWallpaperOpacity(val / 100);
    });

    // Wallpaper Blur Slider
    const wallBlurInput = this.container.querySelector<HTMLInputElement>('#input-wallpaper-blur');
    wallBlurInput?.addEventListener('input', (e) => {
      const val = parseInt((e.target as HTMLInputElement).value, 10);
      const span = this.container?.querySelector('#wallpaper-blur-val');
      if (span) span.textContent = `${val}px`;
      this.settingsStore.setWallpaperBlur(val);
    });

    // Overlay Intensity Slider
    const overlayInput = this.container.querySelector<HTMLInputElement>('#input-overlay-intensity');
    overlayInput?.addEventListener('input', (e) => {
      const val = parseInt((e.target as HTMLInputElement).value, 10);
      const span = this.container?.querySelector('#overlay-intensity-val');
      if (span) span.textContent = `${val}%`;
      this.settingsStore.setOverlayIntensity(val / 100);
    });

    // Font selection
    this.container.querySelectorAll<HTMLButtonElement>('.btn-font-select').forEach(btn => {
      btn.addEventListener('click', () => {
        const f = btn.dataset.font as FontPreference;
        if (f) {
          this.settingsStore.setFont(f);
        }
      });
    });

    // Density selection
    this.container.querySelectorAll<HTMLButtonElement>('.btn-density-select').forEach(btn => {
      btn.addEventListener('click', () => {
        const d = btn.dataset.density as DensityPreference;
        if (d) {
          this.settingsStore.setDensity(d);
        }
      });
    });

    // Reduced motion checkbox
    const motionCheckbox = this.container.querySelector<HTMLInputElement>('#checkbox-reduced-motion');
    motionCheckbox?.addEventListener('change', (e) => {
      const checked = (e.target as HTMLInputElement).checked;
      this.settingsStore.setReducedMotion(checked);
    });

    // Reset settings
    this.container.querySelector('#btn-reset-settings')?.addEventListener('click', () => {
      this.settingsStore.updateSettings({
        theme: 'night',
        accent: 'cyan',
        font: 'sans',
        density: 'comfortable',
        reducedMotion: false,
        backgroundOpacity: 0.85,
        backgroundStyle: 'nebula',
        wallpaperPreset: 'nebula-core',
        customWallpaperDataUrl: undefined,
        wallpaperOpacity: 0.5,
        wallpaperBlur: 6,
        overlayIntensity: 0.65,
      });
      this.notificationStore.notify({
        type: 'info',
        title: 'Defaults Restored',
        message: 'Personalization settings restored to default baseline.',
      });
    });

    // Copy token
    this.container.querySelector('#btn-copy-token')?.addEventListener('click', () => {
      const token = this.authStore.getState().token;
      if (token) {
        navigator.clipboard.writeText(token);
        this.notificationStore.notify({
          type: 'success',
          title: 'Token Copied',
          message: 'SecurityContextToken copied to clipboard.',
        });
      }
    });

    // Sign out
    this.container.querySelector('#btn-sign-out')?.addEventListener('click', () => {
      this.authStore.logout();
      window.location.hash = '#login';
    });
  }
}
