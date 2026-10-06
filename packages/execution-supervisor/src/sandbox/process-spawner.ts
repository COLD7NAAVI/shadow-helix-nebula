/**
 * Shadow : Helix Nebula (SHN) — Sandboxed Subprocess Spawner
 *
 * Implements SEC-INV-01, INV-14, Phase 0.9 Section 8:
 * - Direct execve(argv[]) invocation with ZERO shell interpretation (shell: false)
 * - Strict environment allowlisting (zero secret / credential inheritance)
 * - Ephemeral scratch directory isolation
 * - Stdio pipe encapsulation
 * - Input argument sanity and null-byte defenses
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, type ChildProcess } from 'node:child_process';
import { ok, err, type Result } from '@shn/shared-kernel';

export interface SpawnWorkerOptions {
  readonly executable: string;
  readonly args: readonly string[];
  readonly customEnv?: Record<string, string> | undefined;
  readonly baseScratchDir?: string | undefined;
  readonly executionId: string;
  readonly workerId: string;
}

export interface SpawnedWorker {
  readonly process: ChildProcess;
  readonly pid: number;
  readonly scratchDir: string;
  cleanup: () => Promise<void>;
}

// Allowlist of safe system environment variables permitted into worker processes
const SAFE_SYSTEM_ENV_KEYS = new Set([
  'PATH',
  'Path',
  'PATHEXT',
  'SystemRoot',
  'SYSTEMROOT',
  'windir',
  'TEMP',
  'TMP',
  'TMPDIR',
  'HOME',
  'USERPROFILE',
  'NODE_PATH',
  'LANG',
  'LC_ALL',
  'TZ',
  'COMSPEC',
]);

// Blacklist of forbidden substrings in environment variable keys to prevent credential leakage
const SENSITIVE_KEY_PATTERNS = [
  'PASS',
  'SECRET',
  'KEY',
  'TOKEN',
  'CRED',
  'AUTH',
  'DATABASE',
  'POSTGRES',
  'PG',
  'VAULT',
  'PRIVATE',
  'SHN_MASTER',
  'SHN_KEK',
  'SHN_SCOPE_SIGNING',
  'SHN_AUTH_SIGNING',
  'NODE_OPTIONS',
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'DYLD_INSERT_LIBRARIES',
];

export function buildSanitizedEnvironment(
  customEnv: Record<string, string> = {},
  executionId: string,
  workerId: string
): Record<string, string> {
  const sanitized: Record<string, string> = {};

  // 1. Copy allowlisted host environment variables
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;

    // Check allowlist
    if (!SAFE_SYSTEM_ENV_KEYS.has(key)) continue;

    // Check if key matches sensitive patterns
    const upperKey = key.toUpperCase();
    const isSensitive = SENSITIVE_KEY_PATTERNS.some((pattern) =>
      upperKey.includes(pattern)
    );
    if (isSensitive) continue;

    sanitized[key] = value;
  }

  // 2. Add custom execution environment variables (with strict sensitivity filtering)
  for (const [key, value] of Object.entries(customEnv)) {
    if (typeof value !== 'string') continue;

    const upperKey = key.toUpperCase();
    const isSensitive = SENSITIVE_KEY_PATTERNS.some((pattern) =>
      upperKey.includes(pattern)
    );
    if (isSensitive) continue; // Deny sensitive keys fail-closed

    sanitized[key] = value;
  }

  // 3. Inject execution identity identifiers
  sanitized['SHN_EXECUTION_ID'] = executionId;
  sanitized['SHN_WORKER_ID'] = workerId;
  sanitized['SHN_SANDBOX'] = '1';

  return sanitized;
}

export function validateCommandArguments(
  executable: string,
  args: readonly string[]
): Result<void, string> {
  const trimmedExec = executable.trim();
  if (!trimmedExec) {
    return err('Executable path cannot be empty');
  }

  // Null-byte injection check
  if (trimmedExec.includes('\0')) {
    return err('Executable path contains forbidden null-byte character');
  }

  // Reject batch files (.bat, .cmd) as they invoke cmd.exe and bypass shell: false argument separation
  const ext = path.extname(trimmedExec).toLowerCase();
  if (ext === '.bat' || ext === '.cmd') {
    return err('Execution of batch scripts (.bat, .cmd) is forbidden due to shell interpretation risks');
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (typeof arg !== 'string') {
      return err(`Argument at index ${i} is not a string`);
    }
    if (arg.includes('\0')) {
      return err(`Argument at index ${i} contains forbidden null-byte character`);
    }
    if (arg.length > 64 * 1024) {
      return err(`Argument at index ${i} exceeds maximum length of 64KB`);
    }
  }

  return ok(undefined);
}

export async function spawnSandboxedWorker(
  options: SpawnWorkerOptions
): Promise<Result<SpawnedWorker, string>> {
  const { executable, args, customEnv, baseScratchDir, executionId, workerId } = options;

  // 1. Validate command and arguments
  const valRes = validateCommandArguments(executable, args);
  if (valRes.isErr) {
    return err(valRes.error);
  }

  // 2. Create isolated ephemeral scratch directory
  const rootScratch = baseScratchDir || path.join(os.tmpdir(), 'shn-scratch');
  if (!fs.existsSync(rootScratch)) {
    try {
      fs.mkdirSync(rootScratch, { recursive: true });
    } catch (e) {
      return err(`Failed to create root scratch directory: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  let scratchDir: string;
  try {
    scratchDir = fs.mkdtempSync(path.join(rootScratch, `exec-${executionId}-`));
  } catch (e) {
    return err(`Failed to create ephemeral execution scratch dir: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 3. Build sanitized environment
  const env = buildSanitizedEnvironment(customEnv, executionId, workerId);
  env['TMP'] = scratchDir;
  env['TEMP'] = scratchDir;
  env['TMPDIR'] = scratchDir;

  // 4. Spawn subprocess with shell: false
  let child: ChildProcess;
  try {
    child = spawn(executable, [...args], {
      cwd: scratchDir,
      env,
      shell: false, // MANDATORY: Zero shell string interpolation
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
  } catch (e) {
    // Clean up scratch dir on spawn failure
    try {
      fs.rmSync(scratchDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
    return err(`Failed to spawn worker subprocess: ${e instanceof Error ? e.message : String(e)}`);
  }

  if (!child.pid) {
    try {
      fs.rmSync(scratchDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
    return err('Failed to acquire valid PID for worker subprocess');
  }

  const pid = child.pid;
  let cleanedUp = false;

  const cleanup = async (): Promise<void> => {
    if (cleanedUp) return;
    cleanedUp = true;
    try {
      if (fs.existsSync(scratchDir)) {
        await fs.promises.rm(scratchDir, { recursive: true, force: true });
      }
    } catch {
      // Suppress cleanup failure to prevent uncaught exceptions
    }
  };

  return ok({
    process: child,
    pid,
    scratchDir,
    cleanup,
  });
}
