/**
 * Shadow : Helix Nebula (SHN) — Sovereign Command Line Interface (CLI)
 *
 * Authoritative Spec: Phase 0.1 Section 4, Phase 0.14 Section 2 (INV-02, API-FST-002).
 * Public interface parity across all platform operations with predictable exit codes.
 */

import type { CliCommandResult } from '../contracts.js';

export interface CliContext {
  readonly argv: readonly string[];
  readonly env?: Record<string, string | undefined> | undefined;
}

export class CliRunner {
  async run(context: CliContext): Promise<CliCommandResult> {
    const args = [...context.argv];
    if (args.length === 0 || args.includes('--help') || args.includes('-h') || args[0] === 'help') {
      return {
        exitCode: 0,
        output: this.getHelpText(),
      };
    }

    if (args.includes('--version') || args.includes('-v')) {
      return {
        exitCode: 0,
        output: 'shn 0.1.0 (Shadow : Helix Nebula Sovereign Security Platform)',
      };
    }

    const isJson = args.includes('--json');
    const filteredArgs = args.filter((a) => a !== '--json');

    const domain = filteredArgs[0];
    const positionalArgs: string[] = [];
    const flagArgs: string[] = [];

    for (let i = 1; i < filteredArgs.length; i++) {
      const item = filteredArgs[i]!;
      if (item.startsWith('-')) {
        flagArgs.push(item);
        if (i + 1 < filteredArgs.length && !filteredArgs[i + 1]!.startsWith('-')) {
          flagArgs.push(filteredArgs[i + 1]!);
          i++;
        }
      } else {
        positionalArgs.push(item);
      }
    }

    const action = positionalArgs[0];
    const flags = this.parseFlags(flagArgs);

    const defaultUrl = context.env?.SHN_GATEWAY_URL || 'http://localhost:8080';
    const gatewayUrl = flags['url'] || defaultUrl;
    const token = flags['token'] || context.env?.SHN_AUTH_TOKEN;

    try {
      switch (domain) {
        case 'health': {
          return await this.handleHealth(gatewayUrl, isJson);
        }

        case 'auth': {
          if (action === 'register') {
            return await this.handleAuthRegister(gatewayUrl, flags, isJson);
          }
          if (action === 'login') {
            return await this.handleAuthLogin(gatewayUrl, flags, isJson);
          }
          if (action === 'me') {
            return await this.handleAuthMe(gatewayUrl, token, isJson);
          }
          return {
            exitCode: 1,
            output: 'Usage: shn auth [register|login|me] ...',
            error: `Unknown auth action "${action}".`,
          };
        }

        case 'workspace': {
          if (action === 'list') {
            return await this.handleWorkspaceList(gatewayUrl, token, isJson);
          }
          if (action === 'create') {
            return await this.handleWorkspaceCreate(gatewayUrl, token, flags, isJson);
          }
          return {
            exitCode: 1,
            output: 'Usage: shn workspace [list|create] ...',
            error: `Unknown workspace action "${action}".`,
          };
        }

        case 'asset': {
          if (action === 'list') {
            return await this.handleAssetList(gatewayUrl, token, flags, isJson);
          }
          if (action === 'register') {
            return await this.handleAssetRegister(gatewayUrl, token, flags, isJson);
          }
          return {
            exitCode: 1,
            output: 'Usage: shn asset [list|register] ...',
            error: `Unknown asset action "${action}".`,
          };
        }

        case 'finding': {
          if (action === 'list') {
            return await this.handleFindingList(gatewayUrl, token, flags, isJson);
          }
          if (action === 'transition') {
            return await this.handleFindingTransition(gatewayUrl, token, flags, isJson);
          }
          return {
            exitCode: 1,
            output: 'Usage: shn finding [list|transition] ...',
            error: `Unknown finding action "${action}".`,
          };
        }

        case 'capability': {
          if (action === 'list' || !action) {
            return await this.handleCapabilityList(gatewayUrl, token, flags, isJson);
          }
          return {
            exitCode: 1,
            output: 'Usage: shn capability [list] ...',
            error: `Unknown capability action "${action}".`,
          };
        }

        case 'execute': {
          return await this.handleExecute(gatewayUrl, token, flags, isJson);
        }

        default:
          return {
            exitCode: 1,
            output: this.getHelpText(),
            error: `Unknown command "${domain}". Run "shn --help" for available commands.`,
          };
      }
    } catch (err: any) {
      return {
        exitCode: 3,
        output: '',
        error: `Network / Gateway Error: ${err?.message || 'Connection failed'}`,
      };
    }
  }

  private parseFlags(args: string[]): Record<string, string> {
    const flags: Record<string, string> = {};
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg && arg.startsWith('--')) {
        const key = arg.slice(2);
        const next = args[i + 1];
        if (next && !next.startsWith('--')) {
          flags[key] = next;
          i++;
        } else {
          flags[key] = 'true';
        }
      }
    }
    return flags;
  }

  private async fetchJson(url: string, options?: RequestInit): Promise<{ status: number; data: any }> {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        ...(options?.headers || {}),
      },
    });

    let data: any;
    try {
      data = await res.json();
    } catch {
      data = await res.text();
    }
    return { status: res.status, data };
  }

  private async handleHealth(url: string, isJson: boolean): Promise<CliCommandResult> {
    const res = await this.fetchJson(`${url}/health/ready`);
    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `[+] Gateway Status: UP (Checks: ${JSON.stringify(res.data.checks)})`,
      };
    }
    return {
      exitCode: 3,
      output: isJson ? JSON.stringify(res.data, null, 2) : `[-] Gateway Status: DOWN (HTTP ${res.status})`,
      error: 'Health check failed',
    };
  }

  private async handleAuthRegister(url: string, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    const org = flags['org'];
    const email = flags['email'];
    const password = flags['password'];
    const name = flags['name'];

    if (!org || !email || !password) {
      return {
        exitCode: 1,
        output: 'Usage: shn auth register --org <name> --email <email> --password <pwd> [--name <name>]',
        error: 'Missing required registration parameters',
      };
    }

    const res = await this.fetchJson(`${url}/api/v1/auth/register`, {
      method: 'POST',
      body: JSON.stringify({ organizationName: org, adminEmail: email, adminPassword: password, adminName: name }),
    });

    if (res.status === 201) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `[+] Organization Registered: ${res.data.organization.name} (ID: ${res.data.organization.id})\n[+] Workspace ID: ${res.data.workspace.id}\n[+] Admin User: ${res.data.user.email}`,
      };
    }
    return {
      exitCode: 1,
      output: isJson ? JSON.stringify(res.data, null, 2) : `[-] Registration Failed (HTTP ${res.status}): ${res.data.detail || JSON.stringify(res.data)}`,
      error: res.data.detail || 'Registration failed',
    };
  }

  private async handleAuthLogin(url: string, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    const email = flags['email'];
    const password = flags['password'];
    const workspaceId = flags['workspace'];

    if (!email || !password) {
      return {
        exitCode: 1,
        output: 'Usage: shn auth login --email <email> --password <pwd> [--workspace <wksId>]',
        error: 'Missing email or password',
      };
    }

    const res = await this.fetchJson(`${url}/api/v1/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ email, password, workspaceId }),
    });

    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson
          ? JSON.stringify(res.data, null, 2)
          : `[+] Logged in successfully.\n[+] Token: ${res.data.token}\n[+] Workspace: ${res.data.workspaceId}\n[+] Roles: ${res.data.roles.join(', ')}`,
      };
    }
    return {
      exitCode: 2,
      output: isJson ? JSON.stringify(res.data, null, 2) : `[-] Login Failed: ${res.data.detail || 'Invalid credentials'}`,
      error: res.data.detail || 'Login failed',
    };
  }

  private async handleAuthMe(url: string, token: string | undefined, isJson: boolean): Promise<CliCommandResult> {
    if (!token) {
      return { exitCode: 2, output: '', error: 'Token required. Pass --token or set SHN_AUTH_TOKEN.' };
    }
    const res = await this.fetchJson(`${url}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `[+] Principal ID: ${res.data.actor.id}\n[+] Roles: ${res.data.actor.roles.join(', ')}\n[+] Workspace: ${res.data.workspaceId}`,
      };
    }
    return { exitCode: 2, output: '', error: res.data.detail || 'Authentication check failed' };
  }

  private async handleWorkspaceList(url: string, token: string | undefined, isJson: boolean): Promise<CliCommandResult> {
    if (!token) return { exitCode: 2, output: '', error: 'Token required (--token or SHN_AUTH_TOKEN)' };
    const res = await this.fetchJson(`${url}/api/v1/workspaces`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `Workspaces (${res.data.length}):\n` + res.data.map((w: any) => `  - ${w.name} [ID: ${w.id}]`).join('\n'),
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Failed to list workspaces' };
  }

  private async handleWorkspaceCreate(url: string, token: string | undefined, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    if (!token) return { exitCode: 2, output: '', error: 'Token required (--token)' };
    const name = flags['name'];
    if (!name) return { exitCode: 1, output: '', error: 'Workspace name is required (--name)' };

    const res = await this.fetchJson(`${url}/api/v1/workspaces`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({ name }),
    });
    if (res.status === 201) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `[+] Workspace created: ${res.data.name} (ID: ${res.data.id})`,
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Failed to create workspace' };
  }

  private async handleAssetList(url: string, token: string | undefined, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    if (!token) return { exitCode: 2, output: '', error: 'Token required' };
    const workspaceId = flags['workspace'];
    if (!workspaceId) return { exitCode: 1, output: '', error: 'Workspace ID required (--workspace)' };

    const res = await this.fetchJson(`${url}/api/v1/workspaces/${workspaceId}/assets`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `Assets (${res.data.length}):\n` + res.data.map((a: any) => `  - [${a.type}] ${a.canonicalValue} (Criticality: ${a.criticality}, ID: ${a.id})`).join('\n'),
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Failed to list assets' };
  }

  private async handleAssetRegister(url: string, token: string | undefined, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    if (!token) return { exitCode: 2, output: '', error: 'Token required' };
    const workspaceId = flags['workspace'];
    const target = flags['target'];
    if (!workspaceId || !target) return { exitCode: 1, output: '', error: 'Workspace and target required (--workspace, --target)' };

    const res = await this.fetchJson(`${url}/api/v1/workspaces/${workspaceId}/assets`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        rawTarget: target,
        type: flags['type'],
        name: flags['name'],
        criticality: flags['criticality'] || 'MEDIUM',
      }),
    });
    if (res.status === 201) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `[+] Asset Registered: [${res.data.type}] ${res.data.canonicalValue} (ID: ${res.data.id})`,
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Failed to register asset' };
  }

  private async handleFindingList(url: string, token: string | undefined, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    if (!token) return { exitCode: 2, output: '', error: 'Token required' };
    const workspaceId = flags['workspace'];
    if (!workspaceId) return { exitCode: 1, output: '', error: 'Workspace ID required (--workspace)' };

    const res = await this.fetchJson(`${url}/api/v1/workspaces/${workspaceId}/findings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `Findings (${res.data.length}):\n` + res.data.map((f: any) => `  - [${f.severity}] ${f.title} (Status: ${f.status}, ID: ${f.id})`).join('\n'),
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Failed to list findings' };
  }

  private async handleFindingTransition(url: string, token: string | undefined, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    if (!token) return { exitCode: 2, output: '', error: 'Token required' };
    const workspaceId = flags['workspace'];
    const findingId = flags['finding'];
    const toStatus = flags['status'];
    const reason = flags['reason'];
    if (!workspaceId || !findingId || !toStatus) {
      return { exitCode: 1, output: '', error: 'Workspace, finding, and status required (--workspace, --finding, --status)' };
    }

    const res = await this.fetchJson(`${url}/api/v1/workspaces/${workspaceId}/findings/${findingId}/transitions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({ toStatus, reason }),
    });
    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `[+] Finding status transitioned to: ${res.data.status}`,
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Status transition failed' };
  }

  private async handleCapabilityList(url: string, token: string | undefined, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const endpoint = flags['workspace']
      ? `${url}/api/v1/workspaces/${flags['workspace']}/capabilities`
      : `${url}/api/v1/capabilities`;

    const res = await this.fetchJson(endpoint, { headers });
    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson ? JSON.stringify(res.data, null, 2) : `Capabilities (${res.data.length}):\n` + res.data.map((c: any) => `  - ${c.name} (ID: ${c.id}, Risk: ${c.riskLevel})`).join('\n'),
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Failed to list capabilities' };
  }

  private async handleExecute(url: string, token: string | undefined, flags: Record<string, string>, isJson: boolean): Promise<CliCommandResult> {
    if (!token) return { exitCode: 2, output: '', error: 'Token required (--token)' };
    const workspaceId = flags['workspace'];
    const capabilityId = flags['capability'];
    const target = flags['target'];
    if (!workspaceId || !capabilityId || !target) {
      return { exitCode: 1, output: '', error: 'Workspace, capability, and target required (--workspace, --capability, --target)' };
    }

    let parameters = {};
    if (flags['params']) {
      try {
        parameters = JSON.parse(flags['params']);
      } catch {
        return { exitCode: 1, output: '', error: 'Parameters must be valid JSON string' };
      }
    }

    const res = await this.fetchJson(`${url}/api/v1/workspaces/${workspaceId}/executions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        capabilityId,
        target,
        parameters,
        port: flags['port'] ? Number(flags['port']) : undefined,
      }),
    });

    if (res.status === 200) {
      return {
        exitCode: 0,
        output: isJson
          ? JSON.stringify(res.data, null, 2)
          : `[+] Capability Dispatched Successfully!\n[+] Execution ID: ${res.data.executionId}\n[+] Exit Code: ${res.data.exitCode}\n[+] Evidence SHA-256: ${res.data.rawOutputSha256}\n[+] Output:\n${res.data.rawOutput}`,
      };
    }
    return { exitCode: 1, output: '', error: res.data.detail || 'Execution failed' };
  }

  private getHelpText(): string {
    return `
SHN — Sovereign Cybersecurity Architecture & Platform CLI

USAGE:
  shn <command> [subcommand] [flags]

COMMANDS:
  health                               Check platform gateway readiness
  auth register                        Register organization & admin user
  auth login                           Login and obtain session token
  auth me                              Verify active authentication session
  workspace list                       List accessible workspaces
  workspace create                     Create a new workspace
  asset list                           List assets in workspace
  asset register                       Register and canonicalize a target asset
  finding list                         List vulnerability findings in workspace
  finding transition                   Transition finding lifecycle status
  capability list                      List registered security capabilities
  execute                              Dispatch capability against target

GLOBAL FLAGS:
  --url <url>                          Gateway base URL (default: http://localhost:8080 or SHN_GATEWAY_URL)
  --token <token>                      Bearer authentication token (or SHN_AUTH_TOKEN)
  --json                               Output response as formatted JSON
  --help, -h                           Show this help message
  --version, -v                        Show version information

EXIT CODES:
  0                                    Success
  1                                    Invalid input or validation error
  2                                    Authentication / Authorization denied
  3                                    Network partition or gateway connection error
`.trim();
  }
}
