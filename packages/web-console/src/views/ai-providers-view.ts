/**
 * Shadow : Helix Nebula (SHN) — Configurable AI Providers View
 *
 * Implements Section 10:
 * - Multi-provider configuration: OpenAI-Compatible, Ollama Local, Anthropic, Sovereign Local Heuristic
 * - Encrypted credential persistence via Secrets Vault
 * - Real-time connectivity probing & diagnostic feedback
 * - Privacy and data-sharing disclosure notices
 */

import type { ApiClient } from '../services/api-client.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { AiProvider } from '../contracts.js';

export class AiProvidersView {
  private container: HTMLElement | null = null;
  private providers: AiProvider[] = [];
  private isTesting = false;
  private testResult: { success: boolean; message?: string; latencyMs?: number; modelsAvailable?: string[] } | null = null;

  constructor(
    private readonly api: ApiClient,
    private readonly notify: NotificationStore
  ) {}

  mount(target: HTMLElement): void {
    this.container = target;
    this.loadData();
  }

  unmount(): void {
    this.container = null;
  }

  private async loadData(): Promise<void> {
    try {
      this.providers = await this.api.listAiProviders().catch(() => []);
      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load AI providers');
    }
  }

  private async testConnection(providerType: string, baseUrl: string, modelName: string, apiKey: string): Promise<void> {
    this.isTesting = true;
    this.testResult = null;
    this.render();
    this.bindEvents();

    try {
      const res = await this.api.testAiConnection({
        providerType,
        baseUrl: baseUrl || undefined,
        modelName,
        apiKey: apiKey || undefined,
      });
      this.testResult = res;
      if (res.success) {
        this.notify.success(res.message || 'Connection verified successfully');
      } else {
        this.notify.warning(res.message || 'Connection test returned a warning');
      }
    } catch (err: any) {
      this.testResult = { success: false, message: err.message || 'Test connection failed' };
      this.notify.error(err.message || 'Connection failed');
    } finally {
      this.isTesting = false;
      this.render();
      this.bindEvents();
    }
  }

  private async createProvider(data: Record<string, unknown>): Promise<void> {
    try {
      this.notify.info('Encrypting API credentials and storing provider...');
      const created = await this.api.createAiProvider(data);
      this.notify.success(`AI Provider "${created.displayName}" registered successfully`);
      this.testResult = null;
      await this.loadData();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to register AI provider');
    }
  }

  private render(): void {
    if (!this.container) return;

    this.container.innerHTML = `
      <div class="content-viewport" style="display:flex;flex-direction:column;gap:20px;">
        <!-- Header -->
        <div class="page-header" style="margin-bottom:0;">
          <div class="page-title-group">
            <div style="display:flex;align-items:center;gap:12px;">
              <h2>Configurable AI Provider Ecosystem</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                MULTI-VENDOR & LOCAL
              </span>
            </div>
            <div class="page-subtitle">
              Configure sovereign local inference (Ollama, Heuristic) or remote LLM endpoints (OpenAI, Anthropic).
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <a href="#ai-assistant" class="btn btn-secondary">
              <span>←</span> AI Assistant
            </a>
          </div>
        </div>

        <!-- 2-Column: Configured Providers List & Registration Form -->
        <div style="display:grid;grid-template-columns:1fr 480px;gap:20px;align-items:start;">
          <!-- Left: Provider Cards List -->
          <div style="display:flex;flex-direction:column;gap:16px;">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>🤖</span> Active Provider Registrations (${this.providers.length})
            </div>

            ${this.providers.length > 0 ? this.providers.map((p) => `
              <div class="card" style="display:flex;flex-direction:column;gap:12px;border:1px solid var(--border-medium);">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                  <div style="display:flex;align-items:center;gap:10px;">
                    <span style="font-size:20px;">${p.providerType === 'OLLAMA' ? '🦙' : p.providerType === 'LOCAL_HEURISTIC' ? '⚡' : '🧠'}</span>
                    <div>
                      <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
                        ${p.displayName}
                        ${p.isDefault ? '<span class="badge" style="background:#10b981;color:#fff;font-size:9px;">DEFAULT</span>' : ''}
                      </div>
                      <div style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">
                        ${p.providerType} · Model: <span style="color:#00f0ff;">${p.modelName}</span>
                      </div>
                    </div>
                  </div>
                  <span class="badge" style="font-size:10px;background:${p.healthStatus === 'HEALTHY' ? '#10b981' : p.healthStatus === 'DEGRADED' ? '#f59e0b' : '#64748b'};color:#fff;">
                    ${p.healthStatus}
                  </span>
                </div>

                <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:10px;padding:10px;background:var(--bg-surface-sunken);border-radius:var(--radius-sm);font-size:11px;font-family:var(--font-mono);">
                  <div>
                    <span style="color:var(--text-muted);display:block;">Endpoint:</span>
                    <span style="color:var(--text-primary);">${p.baseUrl || 'Local Process'}</span>
                  </div>
                  <div>
                    <span style="color:var(--text-muted);display:block;">Max Tokens:</span>
                    <span style="color:var(--text-primary);">${p.maxTokens}</span>
                  </div>
                  <div>
                    <span style="color:var(--text-muted);display:block;">Secret Storage:</span>
                    <span style="color:#10b981;">Vault Encrypted</span>
                  </div>
                </div>
              </div>
            `).join('') : `
              <div class="card empty-state" style="padding:48px 24px;">
                <div class="empty-state-icon">⚙️</div>
                <div class="empty-state-title">No AI Providers Registered</div>
                <div class="empty-state-desc">Register a local Ollama instance, an OpenAI-compatible endpoint, or the sovereign local deterministic engine using the form.</div>
              </div>
            `}
          </div>

          <!-- Right: Registration Form -->
          <div class="card" style="display:flex;flex-direction:column;gap:14px;border:1px solid var(--border-medium);">
            <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
              <span>+</span> Register New AI Provider
            </div>

            <!-- Provider Type -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Provider Architecture</label>
              <select id="input-provider-type" style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;">
                <option value="LOCAL_HEURISTIC">Sovereign Local Heuristic (Zero Cloud Data Leakage)</option>
                <option value="OLLAMA">Ollama (Local Private Self-Hosted Endpoint)</option>
                <option value="OPENAI_COMPATIBLE">OpenAI API Compatible Endpoint</option>
                <option value="ANTHROPIC">Anthropic API</option>
              </select>
            </div>

            <!-- Display Name -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Display Name</label>
              <input
                id="input-display-name"
                type="text"
                value="Sovereign Heuristic Engine"
                placeholder="e.g. Local Llama 3 or Production GPT-4o"
                style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;"
              />
            </div>

            <!-- Base URL -->
            <div id="row-base-url">
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Base URL (Optional for Local)</label>
              <input
                id="input-base-url"
                type="text"
                placeholder="e.g. http://localhost:11434 or https://api.openai.com/v1"
                style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--font-mono);"
              />
            </div>

            <!-- Model Name -->
            <div>
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">Model Name / Identifier</label>
              <input
                id="input-model-name"
                type="text"
                value="shn-sovereign-heuristic-v1"
                placeholder="e.g. llama3:8b, gpt-4o-mini, claude-3-5-sonnet-20241022"
                style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--font-mono);"
              />
            </div>

            <!-- API Key -->
            <div id="row-api-key">
              <label style="display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;">API Key (Encrypted in Secrets Vault)</label>
              <input
                id="input-api-key"
                type="password"
                placeholder="Enter API Key (will not be logged or exposed in bundles)"
                style="width:100%;padding:8px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;"
              />
            </div>

            <!-- Privacy Notice Checkbox -->
            <div style="padding:10px;background:rgba(0,240,255,0.06);border:1px solid rgba(0,240,255,0.2);border-radius:var(--radius-sm);font-size:11px;color:var(--text-secondary);line-height:1.4;">
              <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer;">
                <input type="checkbox" id="chk-privacy" checked style="margin-top:2px;" />
                <span>
                  <strong>Data Privacy Disclosure:</strong> I acknowledge that target endpoints and finding metadata may be processed by the selected provider. Local Heuristic and Ollama execute strictly on-premise without cloud transmission.
                </span>
              </label>
            </div>

            <!-- Test Connection Result Box -->
            ${this.testResult ? `
              <div style="padding:10px;border-radius:var(--radius-sm);background:${this.testResult.success ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)'};border:1px solid ${this.testResult.success ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'};font-size:11px;color:${this.testResult.success ? '#10b981' : '#ef4444'};">
                <div style="font-weight:700;">${this.testResult.success ? '✓ Connection Verified' : '✕ Connection Diagnostic Failed'}</div>
                <div style="margin-top:2px;">${this.testResult.message}</div>
                ${this.testResult.latencyMs ? `<div style="font-family:var(--font-mono);font-size:10px;margin-top:2px;">Latency: ${this.testResult.latencyMs}ms</div>` : ''}
              </div>
            ` : ''}

            <!-- Buttons: Test Connection & Save -->
            <div style="display:flex;gap:10px;margin-top:6px;">
              <button id="btn-test-connection" class="btn btn-secondary" ${this.isTesting ? 'disabled' : ''} style="flex:1;">
                <span>${this.isTesting ? '⏳' : '⚡'}</span>
                <span>${this.isTesting ? 'Testing...' : 'Test Connection'}</span>
              </button>
              <button id="btn-save-provider" class="btn btn-primary" style="flex:1;">
                <span>💾</span> Save Provider
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.container) return;

    const selectType = this.container.querySelector<HTMLSelectElement>('#input-provider-type');
    const inputName = this.container.querySelector<HTMLInputElement>('#input-display-name');
    const inputModel = this.container.querySelector<HTMLInputElement>('#input-model-name');
    const inputUrl = this.container.querySelector<HTMLInputElement>('#input-base-url');
    const inputKey = this.container.querySelector<HTMLInputElement>('#input-api-key');
    const rowUrl = this.container.querySelector<HTMLElement>('#row-base-url');
    const rowKey = this.container.querySelector<HTMLElement>('#row-api-key');

    selectType?.addEventListener('change', () => {
      const val = selectType.value;
      if (val === 'LOCAL_HEURISTIC') {
        if (inputName) inputName.value = 'Sovereign Local Heuristic';
        if (inputModel) inputModel.value = 'shn-sovereign-heuristic-v1';
        if (rowUrl) rowUrl.style.display = 'none';
        if (rowKey) rowKey.style.display = 'none';
      } else if (val === 'OLLAMA') {
        if (inputName) inputName.value = 'Ollama Local Daemon';
        if (inputModel) inputModel.value = 'llama3:8b';
        if (inputUrl) inputUrl.value = 'http://localhost:11434';
        if (rowUrl) rowUrl.style.display = 'block';
        if (rowKey) rowKey.style.display = 'none';
      } else if (val === 'OPENAI_COMPATIBLE') {
        if (inputName) inputName.value = 'OpenAI Compatible';
        if (inputModel) inputModel.value = 'gpt-4o-mini';
        if (inputUrl) inputUrl.value = 'https://api.openai.com/v1';
        if (rowUrl) rowUrl.style.display = 'block';
        if (rowKey) rowKey.style.display = 'block';
      } else if (val === 'ANTHROPIC') {
        if (inputName) inputName.value = 'Anthropic Claude';
        if (inputModel) inputModel.value = 'claude-3-5-sonnet-20241022';
        if (inputUrl) inputUrl.value = 'https://api.anthropic.com/v1';
        if (rowUrl) rowUrl.style.display = 'block';
        if (rowKey) rowKey.style.display = 'block';
      }
    });

    this.container.querySelector('#btn-test-connection')?.addEventListener('click', () => {
      const type = selectType?.value || 'LOCAL_HEURISTIC';
      const url = inputUrl?.value?.trim() || '';
      const model = inputModel?.value?.trim() || 'shn-sovereign-heuristic-v1';
      const key = inputKey?.value?.trim() || '';

      this.testConnection(type, url, model, key);
    });

    this.container.querySelector('#btn-save-provider')?.addEventListener('click', () => {
      const type = selectType?.value || 'LOCAL_HEURISTIC';
      const name = inputName?.value?.trim() || 'Custom Provider';
      const url = inputUrl?.value?.trim() || undefined;
      const model = inputModel?.value?.trim() || 'shn-sovereign-heuristic-v1';
      const key = inputKey?.value?.trim() || undefined;

      this.createProvider({
        providerType: type,
        displayName: name,
        baseUrl: url,
        modelName: model,
        apiKey: key,
        isDefault: this.providers.length === 0,
      });
    });
  }
}
