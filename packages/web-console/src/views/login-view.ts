/**
 * Shadow : Helix Nebula (SHN) — Authentication View
 *
 * Professional sovereign cybersecurity login & organization registration screen.
 * Implements robust controlled form state, client-side validation, and secure session handoff.
 */

import type { ApiClient } from '../services/api-client.js';
import type { AuthStore } from '../state/auth-store.js';
import type { NotificationStore } from '../state/notification-store.js';

function escapeHtml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderLoginView(
  container: HTMLElement,
  deps: { api: ApiClient; authStore: AuthStore; notify: NotificationStore; onLoginSuccess: () => void }
): void {
  let activeTab: 'login' | 'register' = 'login';
  let isLoading = false;
  let errorMessage: string | null = null;

  // Form input state preservation across renders
  let loginEmail = '';
  let loginPassword = '';
  let regOrgName = '';
  let regAdminName = '';
  let regEmail = '';
  let regPassword = '';

  function render() {
    container.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;width:100vw;padding:20px;position:relative;z-index:10;">
        <div class="card" style="width:100%;max-width:440px;padding:32px;background:var(--bg-surface-glass-heavy);border:1px solid var(--border-glass);box-shadow:var(--shadow-lg);">
          <!-- Brand Header -->
          <div style="text-align:center;margin-bottom:28px;">
            <div style="width:48px;height:48px;margin:0 auto 14px;border-radius:var(--radius-lg);background:linear-gradient(135deg, var(--accent-primary) 0%, var(--shn-brand-violet) 100%);display:flex;align-items:center;justify-content:center;box-shadow:0 0 25px var(--accent-glow);">
              <span style="font-weight:900;font-size:20px;color:#030408;">SHN</span>
            </div>
            <h1 style="font-size:22px;font-weight:700;letter-spacing:-0.02em;">SHADOW : HELIX NEBULA</h1>
            <p style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.08em;margin-top:4px;">Sovereign Cybersecurity Architecture</p>
          </div>

          <!-- Tab Switcher -->
          <div style="display:flex;background:var(--bg-input);padding:4px;border-radius:var(--radius-md);margin-bottom:24px;border:1px solid var(--border-medium);">
            <button id="tab-login" type="button" class="btn ${activeTab === 'login' ? 'btn-primary' : 'btn-ghost'}" style="flex:1;font-size:12px;padding:6px;" ${isLoading ? 'disabled' : ''}>Sign In</button>
            <button id="tab-register" type="button" class="btn ${activeTab === 'register' ? 'btn-primary' : 'btn-ghost'}" style="flex:1;font-size:12px;padding:6px;" ${isLoading ? 'disabled' : ''}>New Organization</button>
          </div>

          ${errorMessage ? `
            <div id="auth-error-banner" style="padding:12px 14px;border-radius:var(--radius-md);background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.35);color:#ef4444;font-size:12px;margin-bottom:20px;display:flex;align-items:center;gap:8px;">
              <span>⚠</span>
              <span>${escapeHtml(errorMessage)}</span>
            </div>
          ` : ''}

          <!-- Form Area -->
          <form id="auth-form" style="display:flex;flex-direction:column;gap:16px;">
            ${activeTab === 'login' ? `
              <div class="form-group" style="margin:0;">
                <label class="form-label" for="login-email">Operator Email</label>
                <input class="form-input" id="login-email" type="email" placeholder="operator@shn.sovereign" required autocomplete="email" value="${escapeHtml(loginEmail)}" ${isLoading ? 'disabled' : ''} />
              </div>

              <div class="form-group" style="margin:0;">
                <label class="form-label" for="login-password">Password</label>
                <input class="form-input" id="login-password" type="password" placeholder="••••••••" required autocomplete="current-password" value="${escapeHtml(loginPassword)}" ${isLoading ? 'disabled' : ''} />
              </div>

              <button type="submit" id="btn-submit-login" class="btn btn-primary btn-lg" style="margin-top:8px;" ${isLoading ? 'disabled' : ''}>
                ${isLoading ? 'Authenticating...' : 'Authorize Operator Session'}
              </button>

              <div style="margin-top:16px;padding:12px;border-radius:var(--radius-md);background:rgba(255,255,255,0.03);border:1px solid var(--border-subtle);font-size:11px;color:var(--text-muted);line-height:1.6;">
                <strong style="color:var(--text-secondary);">Sovereign Operator Access:</strong><br />
                Default Email: <code style="color:var(--accent-primary);">operator@shn.sovereign</code><br />
                <span style="font-size:10px;color:var(--text-muted);">Use the credentials provisioned during setup or specified via <code style="color:var(--text-secondary);">SHN_INITIAL_ADMIN_PASSWORD</code>.</span>
              </div>
            ` : `
              <div class="form-group" style="margin:0;">
                <label class="form-label" for="reg-org-name">Organization Name</label>
                <input class="form-input" id="reg-org-name" type="text" placeholder="Apex Cyber Command" required value="${escapeHtml(regOrgName)}" ${isLoading ? 'disabled' : ''} />
              </div>

              <div class="form-group" style="margin:0;">
                <label class="form-label" for="reg-admin-name">Administrator Name</label>
                <input class="form-input" id="reg-admin-name" type="text" placeholder="Chief Security Officer" required value="${escapeHtml(regAdminName)}" ${isLoading ? 'disabled' : ''} />
              </div>

              <div class="form-group" style="margin:0;">
                <label class="form-label" for="reg-email">Admin Email</label>
                <input class="form-input" id="reg-email" type="email" placeholder="admin@domain.sovereign" required autocomplete="email" value="${escapeHtml(regEmail)}" ${isLoading ? 'disabled' : ''} />
              </div>

              <div class="form-group" style="margin:0;">
                <label class="form-label" for="reg-password">Master Password (min 8 chars)</label>
                <input class="form-input" id="reg-password" type="password" placeholder="••••••••" required minlength="8" autocomplete="new-password" value="${escapeHtml(regPassword)}" ${isLoading ? 'disabled' : ''} />
              </div>

              <button type="submit" id="btn-submit-register" class="btn btn-primary btn-lg" style="margin-top:8px;" ${isLoading ? 'disabled' : ''}>
                ${isLoading ? 'Initializing...' : 'Provision Sovereign Tenant'}
              </button>
            `}
          </form>

          <!-- Footer Security Notice -->
          <div style="margin-top:24px;text-align:center;font-size:11px;color:var(--text-muted);display:flex;align-items:center;justify-content:center;gap:6px;">
            <span class="pulse-dot"></span>
            <span>Zero-Trust Security Perimeter Active</span>
          </div>
        </div>
      </div>
    `;

    // Bind Input Listeners to preserve state as user types
    if (activeTab === 'login') {
      const emailInput = container.querySelector('#login-email') as HTMLInputElement | null;
      const passInput = container.querySelector('#login-password') as HTMLInputElement | null;

      emailInput?.addEventListener('input', (e) => {
        loginEmail = (e.target as HTMLInputElement).value;
      });
      passInput?.addEventListener('input', (e) => {
        loginPassword = (e.target as HTMLInputElement).value;
      });
    } else {
      container.querySelector('#reg-org-name')?.addEventListener('input', (e) => {
        regOrgName = (e.target as HTMLInputElement).value;
      });
      container.querySelector('#reg-admin-name')?.addEventListener('input', (e) => {
        regAdminName = (e.target as HTMLInputElement).value;
      });
      container.querySelector('#reg-email')?.addEventListener('input', (e) => {
        regEmail = (e.target as HTMLInputElement).value;
      });
      container.querySelector('#reg-password')?.addEventListener('input', (e) => {
        regPassword = (e.target as HTMLInputElement).value;
      });
    }

    // Bind Tab Switching
    container.querySelector('#tab-login')?.addEventListener('click', () => {
      if (isLoading) return;
      activeTab = 'login';
      errorMessage = null;
      render();
    });

    container.querySelector('#tab-register')?.addEventListener('click', () => {
      if (isLoading) return;
      activeTab = 'register';
      errorMessage = null;
      render();
    });

    // Bind Form Submit
    container.querySelector('#auth-form')?.addEventListener('submit', async (e) => {
      if (typeof e.preventDefault === 'function') e.preventDefault();

      const form = (e.target || e.currentTarget || container.querySelector('#auth-form')) as HTMLFormElement;

      if (activeTab === 'login') {
        const emailEl = ((form && typeof form.querySelector === 'function' ? form.querySelector('#login-email') : null)
          || container.querySelector('#login-email')) as HTMLInputElement | null;
        const passEl = ((form && typeof form.querySelector === 'function' ? form.querySelector('#login-password') : null)
          || container.querySelector('#login-password')) as HTMLInputElement | null;

        // Retrieve directly from the live DOM elements before changing loading state
        const email = (emailEl ? emailEl.value : loginEmail).trim();
        const password = passEl ? passEl.value : loginPassword;

        // Store back in state
        loginEmail = email;
        loginPassword = password;

        if (!email || !password) {
          errorMessage = 'Email and password are required.';
          render();
          return;
        }

        isLoading = true;
        errorMessage = null;
        render();

        try {
          const loginRes = await deps.api.login({
            email,
            password,
          });

          deps.authStore.handleLoginSuccess(loginRes);
          deps.notify.success(`Welcome, ${loginRes.user.displayName}`, 'Authenticated');
          deps.onLoginSuccess();
        } catch (err: any) {
          isLoading = false;
          errorMessage = err.problem?.detail || err.message || 'Authentication failed. Please verify credentials.';
          render();
        }
      } else {
        const orgEl = ((form && typeof form.querySelector === 'function' ? form.querySelector('#reg-org-name') : null)
          || container.querySelector('#reg-org-name')) as HTMLInputElement | null;
        const nameEl = ((form && typeof form.querySelector === 'function' ? form.querySelector('#reg-admin-name') : null)
          || container.querySelector('#reg-admin-name')) as HTMLInputElement | null;
        const emailEl = ((form && typeof form.querySelector === 'function' ? form.querySelector('#reg-email') : null)
          || container.querySelector('#reg-email')) as HTMLInputElement | null;
        const passEl = ((form && typeof form.querySelector === 'function' ? form.querySelector('#reg-password') : null)
          || container.querySelector('#reg-password')) as HTMLInputElement | null;

        const organizationName = (orgEl ? orgEl.value : regOrgName).trim();
        const adminName = (nameEl ? nameEl.value : regAdminName).trim();
        const adminEmail = (emailEl ? emailEl.value : regEmail).trim();
        const adminPassword = passEl ? passEl.value : regPassword;

        regOrgName = organizationName;
        regAdminName = adminName;
        regEmail = adminEmail;
        regPassword = adminPassword;

        if (!organizationName || !adminEmail || !adminPassword) {
          errorMessage = 'All registration fields are required.';
          render();
          return;
        }

        if (adminPassword.length < 8) {
          errorMessage = 'Master password must be at least 8 characters long.';
          render();
          return;
        }

        isLoading = true;
        errorMessage = null;
        render();

        try {
          await deps.api.register({
            organizationName,
            adminName: adminName || 'System Administrator',
            adminEmail,
            adminPassword,
          });

          deps.notify.success('Organization provisioned. Please sign in.', 'Success');
          activeTab = 'login';
          loginEmail = adminEmail;
          loginPassword = '';
          regPassword = '';
          isLoading = false;
          errorMessage = null;
          render();
        } catch (err: any) {
          isLoading = false;
          errorMessage = err.problem?.detail || err.message || 'Organization registration failed.';
          render();
        }
      }
    });
  }

  render();
}
