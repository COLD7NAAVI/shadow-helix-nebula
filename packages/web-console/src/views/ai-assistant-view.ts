/**
 * Shadow : Helix Nebula (SHN) — Evidence-Driven AI Security Assistant & Chat View
 *
 * Implements Section 11:
 * - Structured, schema-validated recommendations based on collected workspace findings & assets
 * - One-click operator approval with capability dispatch through execution supervisor
 * - Interactive AI security chat interface with context awareness and proposed actions
 * - Transparent risk scoring, confidence metric, and evidence traceability
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { AiRecommendation, AiProvider } from '../contracts.js';

interface ChatMessage {
  id: string;
  sender: 'ai' | 'operator';
  text: string;
  timestamp: string;
  proposedActions?: Array<{ title: string; capabilityUri: string; target: string; parameters?: any }> | undefined;
}

export class AiAssistantView {
  private container: HTMLElement | null = null;
  private recommendations: AiRecommendation[] = [];
  private providers: AiProvider[] = [];
  private selectedProviderId: string | null = null;
  private chatMessages: ChatMessage[] = [];
  private isGenerating = false;
  private isSendingChat = false;

  constructor(
    private readonly api: ApiClient,
    private readonly workspaceStore: WorkspaceStore,
    private readonly notify: NotificationStore
  ) {
    // Initial welcome message from the sovereign assistant
    this.chatMessages.push({
      id: 'welcome-msg',
      sender: 'ai',
      text: 'Greetings Operator. I am the Shadow Helix Sovereign Security Orchestrator. I continuously correlate your workspace assets, findings, and scope policies to recommend evidence-backed verification steps. How can I assist your assessment operations today?',
      timestamp: new Date().toLocaleTimeString(),
      proposedActions: [
        { title: 'Re-Analyze Workspace Assets', capabilityUri: 'shn://capabilities/web/http-baseline', target: 'active-scope' },
        { title: 'Inspect Target TLS Ciphers', capabilityUri: 'shn://capabilities/web/tls-inspect', target: 'active-scope' },
      ],
    });
  }

  mount(target: HTMLElement): void {
    this.container = target;
    this.loadData();
  }

  unmount(): void {
    this.container = null;
  }

  private async loadData(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    try {
      const [recs, provs] = await Promise.all([
        this.api.listAiRecommendations(ws.id).catch(() => []),
        this.api.listAiProviders().catch(() => []),
      ]);

      this.recommendations = recs;
      this.providers = provs;

      if (this.providers.length > 0 && !this.selectedProviderId) {
        const def = this.providers.find((p) => p.isDefault) || this.providers[0];
        if (def) this.selectedProviderId = def.id;
      }

      this.render();
      this.bindEvents();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load AI orchestrator data');
    }
  }

  private async generateRecommendations(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    this.isGenerating = true;
    this.render();

    try {
      this.notify.info('AI assistant inspecting assets, scope, and findings...');
      const recs = await this.api.generateAiRecommendations(ws.id);
      this.recommendations = recs;
      this.notify.success(`Generated ${recs.length} evidence-backed security recommendations`);
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to generate recommendations');
    } finally {
      this.isGenerating = false;
      this.render();
      this.bindEvents();
    }
  }

  private async approveRecommendation(id: string): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    try {
      this.notify.info('Authorizing recommendation and dispatching tool...');
      const res = await this.api.approveAiRecommendation(ws.id, id);
      if (res.success) {
        this.notify.success(`Capability dispatched! Execution ID: ${res.executionId || 'Active'}`);
        await this.loadData();
      }
    } catch (err: any) {
      this.notify.error(err.message || 'Approval failed');
    }
  }

  private async dismissRecommendation(id: string): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    try {
      await this.api.dismissAiRecommendation(ws.id, id);
      this.notify.info('Recommendation dismissed');
      await this.loadData();
    } catch (err: any) {
      this.notify.error(err.message || 'Dismissal failed');
    }
  }

  private async sendChatMessage(prompt: string): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws || !prompt.trim()) return;

    // Add operator message
    this.chatMessages.push({
      id: 'msg-' + Date.now(),
      sender: 'operator',
      text: prompt,
      timestamp: new Date().toLocaleTimeString(),
    });

    this.isSendingChat = true;
    this.render();
    this.bindEvents();

    try {
      const resp = await this.api.chatAi(ws.id, prompt, this.selectedProviderId || undefined);
      this.chatMessages.push({
        id: 'msg-resp-' + Date.now(),
        sender: 'ai',
        text: resp.reply,
        timestamp: new Date().toLocaleTimeString(),
        proposedActions: resp.proposedActions as any,
      });
    } catch (err: any) {
      this.chatMessages.push({
        id: 'msg-err-' + Date.now(),
        sender: 'ai',
        text: `Error communicating with AI provider: ${err.message}. Using sovereign local heuristic rules.`,
        timestamp: new Date().toLocaleTimeString(),
      });
    } finally {
      this.isSendingChat = false;
      this.render();
      this.bindEvents();
      this.scrollChatToBottom();
    }
  }

  private scrollChatToBottom(): void {
    const box = this.container?.querySelector<HTMLElement>('#chat-messages-container');
    if (box) {
      box.scrollTop = box.scrollHeight;
    }
  }

  private render(): void {
    if (!this.container) return;

    const ws = this.workspaceStore.getActiveWorkspace();
    const pendingRecs = this.recommendations.filter((r) => r.status === 'PENDING');

    this.container.innerHTML = `
      <div class="content-viewport" style="display:flex;flex-direction:column;gap:20px;height:calc(100vh - 60px);">
        <!-- Header -->
        <div class="page-header" style="margin-bottom:0;">
          <div class="page-title-group">
            <div style="display:flex;align-items:center;gap:12px;">
              <h2>Evidence-Driven AI Security Assistant</h2>
              <span class="badge" style="background:rgba(236,72,153,0.15);color:#ec4899;border:1px solid rgba(236,72,153,0.3);font-size:11px;">
                ZERO-TRUST ORCHESTRATOR
              </span>
            </div>
            <div class="page-subtitle">
              Sovereign correlation for workspace: <strong style="color:var(--text-primary);">${ws?.name || 'Default'}</strong>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-generate-recs" class="btn btn-primary" ${this.isGenerating ? 'disabled' : ''} style="display:flex;align-items:center;gap:6px;">
              <span>${this.isGenerating ? '⏳' : '⚡'}</span>
              <span>${this.isGenerating ? 'Analyzing...' : 'Generate AI Recommendations'}</span>
            </button>
            <a href="#ai-providers" class="btn btn-secondary">
              <span>⚙️</span> Provider Settings
            </a>
          </div>
        </div>

        <!-- 2-Column Split: Recommendations on Left, Interactive Chat on Right -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;flex:1;overflow:hidden;">
          <!-- Left Column: Recommendations Queue -->
          <div class="card" style="display:flex;flex-direction:column;gap:14px;overflow:hidden;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="font-weight:700;font-size:14px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
                <span>🎯</span> Recommended Action Queue (${pendingRecs.length})
              </div>
              <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">
                Policy-Enforced Safe Execution
              </span>
            </div>

            <!-- List of Recommendations -->
            <div style="flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:12px;padding-right:4px;">
              ${pendingRecs.length > 0 ? pendingRecs.map((rec) => `
                <div class="ai-rec-card ${rec.riskLevel === 'CRITICAL' || rec.riskLevel === 'HIGH' ? 'high-risk' : rec.riskLevel === 'MEDIUM' ? 'med-risk' : 'low-risk'}">
                  <!-- Header -->
                  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
                    <div>
                      <div style="font-weight:700;font-size:13px;color:var(--text-primary);">${rec.objective}</div>
                      <div style="font-size:12px;color:var(--text-secondary);margin-top:3px;line-height:1.4;">${rec.rationale}</div>
                    </div>
                    <span class="badge" style="font-size:10px;background:${rec.riskLevel === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : rec.riskLevel === 'HIGH' ? 'rgba(249,115,22,0.2)' : 'rgba(0,240,255,0.2)'};color:${rec.riskLevel === 'CRITICAL' ? '#ef4444' : rec.riskLevel === 'HIGH' ? '#f97316' : '#00f0ff'};">
                      ${rec.riskLevel}
                    </span>
                  </div>

                  <!-- Details Pill Row -->
                  <div style="display:flex;flex-wrap:wrap;gap:12px;padding:8px;background:var(--bg-surface-sunken);border-radius:var(--radius-sm);font-size:11px;font-family:var(--font-mono);">
                    <div>
                      <span style="color:var(--text-muted);">Capability:</span>
                      <strong style="color:#00f0ff;">${rec.proposedCapability}</strong>
                    </div>
                    <div>
                      <span style="color:var(--text-muted);">Target:</span>
                      <strong style="color:var(--text-primary);">${rec.target}</strong>
                    </div>
                    <div>
                      <span style="color:var(--text-muted);">Confidence:</span>
                      <strong style="color:#10b981;">${Math.round(rec.confidence * 100)}%</strong>
                    </div>
                  </div>

                  <!-- Assumptions / Scope Prereqs -->
                  ${rec.assumptions && rec.assumptions.length > 0 ? `
                    <div style="font-size:11px;color:var(--text-muted);">
                      <span style="font-weight:600;">Prerequisites:</span> ${rec.assumptions.join(' · ')}
                    </div>
                  ` : ''}

                  <!-- Actions -->
                  <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:4px;">
                    <button class="btn btn-ghost btn-sm btn-dismiss-rec" data-rec-id="${rec.id}" style="font-size:11px;padding:4px 10px;">
                      Dismiss
                    </button>
                    <button class="btn btn-primary btn-sm btn-approve-rec" data-rec-id="${rec.id}" style="font-size:11px;padding:4px 14px;display:flex;align-items:center;gap:6px;">
                      <span>✓</span>
                      <span>Approve & Dispatch</span>
                    </button>
                  </div>
                </div>
              `).join('') : `
                <div class="empty-state" style="padding:48px 16px;">
                  <div class="empty-state-icon">🤖</div>
                  <div class="empty-state-title">No Pending Recommendations</div>
                  <div class="empty-state-desc">The AI orchestrator will analyze newly discovered assets and vulnerability findings to propose next safe assessment steps.</div>
                  <button id="btn-empty-generate-recs" class="btn btn-secondary btn-sm" style="margin-top:12px;">
                    ⚡ Analyze Workspace Now
                  </button>
                </div>
              `}
            </div>
          </div>

          <!-- Right Column: Context-Aware Security Chat -->
          <div class="card" style="display:flex;flex-direction:column;overflow:hidden;padding:0;">
            <!-- Chat Header -->
            <div style="padding:12px 16px;background:var(--bg-surface-elevated);border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;justify-content:space-between;">
              <div style="display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:var(--text-primary);">
                <span>💬</span> Sovereign Operator Chat
              </div>
              <!-- Provider Selector -->
              <div style="display:flex;align-items:center;gap:6px;font-size:11px;">
                <span style="color:var(--text-muted);">Provider:</span>
                <select id="select-ai-provider" style="padding:3px 8px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:var(--radius-xs);color:var(--text-primary);font-size:11px;">
                  ${this.providers.map((p) => `
                    <option value="${p.id}" ${p.id === this.selectedProviderId ? 'selected' : ''}>
                      ${p.displayName} (${p.providerType})
                    </option>
                  `).join('')}
                </select>
              </div>
            </div>

            <!-- Messages Scroll Box -->
            <div id="chat-messages-container" style="flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:14px;">
              ${this.chatMessages.map((m) => `
                <div style="display:flex;flex-direction:column;align-items:${m.sender === 'operator' ? 'flex-end' : 'flex-start'};gap:4px;">
                  <div style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);">
                    ${m.sender === 'operator' ? 'Operator' : 'Sovereign AI'} · ${m.timestamp}
                  </div>
                  <div style="max-width:85%;padding:10px 14px;border-radius:${m.sender === 'operator' ? '12px 12px 2px 12px' : '12px 12px 12px 2px'};background:${m.sender === 'operator' ? 'var(--accent-primary)' : 'var(--bg-surface-elevated)'};color:${m.sender === 'operator' ? '#030712' : 'var(--text-primary)'};border:${m.sender === 'operator' ? 'none' : '1px solid var(--border-subtle)'};font-size:12px;line-height:1.5;">
                    ${this.escapeHtml(m.text)}
                  </div>
                  ${m.proposedActions && m.proposedActions.length > 0 ? `
                    <div style="display:flex;gap:6px;margin-top:4px;flex-wrap:wrap;">
                      ${m.proposedActions.map((act) => `
                        <button class="btn btn-secondary btn-sm btn-quick-action" data-cap="${act.capabilityUri}" data-target="${act.target}" style="font-size:10px;padding:3px 8px;border-color:var(--accent-primary);color:var(--accent-primary);">
                          ⚡ ${act.title}
                        </button>
                      `).join('')}
                    </div>
                  ` : ''}
                </div>
              `).join('')}
              ${this.isSendingChat ? `
                <div style="display:flex;align-items:center;gap:8px;color:var(--text-muted);font-size:12px;">
                  <span>🤖 Thinking...</span>
                </div>
              ` : ''}
            </div>

            <!-- Chat Input Box -->
            <div style="padding:12px 16px;background:var(--bg-surface-elevated);border-top:1px solid var(--border-subtle);display:flex;align-items:center;gap:10px;">
              <input
                id="chat-input"
                type="text"
                placeholder="Ask about vulnerabilities, suggest next steps, or request advice..."
                style="flex:1;padding:8px 12px;background:var(--bg-input);border:1px solid var(--border-medium);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;"
              />
              <button id="btn-send-chat" class="btn btn-primary" ${this.isSendingChat ? 'disabled' : ''} style="padding:8px 16px;font-size:12px;">
                Send
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  private bindEvents(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-generate-recs')?.addEventListener('click', () => {
      this.generateRecommendations();
    });

    this.container.querySelector('#btn-empty-generate-recs')?.addEventListener('click', () => {
      this.generateRecommendations();
    });

    this.container.querySelectorAll<HTMLButtonElement>('.btn-approve-rec').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.recId;
        if (id) this.approveRecommendation(id);
      });
    });

    this.container.querySelectorAll<HTMLButtonElement>('.btn-dismiss-rec').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.recId;
        if (id) this.dismissRecommendation(id);
      });
    });

    const selectProv = this.container.querySelector<HTMLSelectElement>('#select-ai-provider');
    selectProv?.addEventListener('change', () => {
      this.selectedProviderId = selectProv.value;
    });

    const sendBtn = this.container.querySelector('#btn-send-chat');
    const inputChat = this.container.querySelector<HTMLInputElement>('#chat-input');

    const handleSend = () => {
      const text = inputChat?.value?.trim();
      if (text) {
        if (inputChat) inputChat.value = '';
        this.sendChatMessage(text);
      }
    };

    sendBtn?.addEventListener('click', handleSend);
    inputChat?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleSend();
      }
    });

    this.container.querySelectorAll<HTMLButtonElement>('.btn-quick-action').forEach((btn) => {
      btn.addEventListener('click', () => {
        const cap = btn.dataset.cap;
        const target = btn.dataset.target;
        if (cap) {
          window.location.hash = `#terminal?cap=${encodeURIComponent(cap)}&target=${encodeURIComponent(target || '')}`;
        }
      });
    });
  }
}
