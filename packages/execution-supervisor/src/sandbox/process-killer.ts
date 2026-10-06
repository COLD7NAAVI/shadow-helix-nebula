/**
 * Shadow : Helix Nebula (SHN) — Process Tree Terminator
 *
 * Robust, cross-platform, idempotent process tree termination.
 * Defeats orphan/zombie child processes across Windows, Linux, and macOS.
 */

import { execFile, type ChildProcess } from 'node:child_process';

export async function killProcessTree(
  pid: number,
  childProcess?: ChildProcess,
  signal: NodeJS.Signals | 'SIGKILL' = 'SIGKILL'
): Promise<void> {
  if (!pid || pid <= 0) return;

  // 1. Windows: taskkill /F /T /PID
  if (process.platform === 'win32') {
    await new Promise<void>((resolve) => {
      execFile('taskkill', ['/F', '/T', '/PID', String(pid)], () => {
        // Code 128 or 'not found' is expected if process already terminated
        resolve();
      });
    });

    if (childProcess && !childProcess.killed) {
      try {
        childProcess.kill('SIGKILL');
      } catch {
        // ignore
      }
    }
    return;
  }

  // 2. POSIX: process group kill
  try {
    process.kill(-pid, signal);
  } catch (e: any) {
    if (e?.code !== 'ESRCH') {
      try {
        process.kill(pid, signal);
      } catch {
        // ignore
      }
    }
  }

  if (childProcess && !childProcess.killed) {
    try {
      childProcess.kill(signal);
    } catch {
      // ignore
    }
  }
}
