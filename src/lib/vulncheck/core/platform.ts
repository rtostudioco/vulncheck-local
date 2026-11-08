import { runCommand, toExecLog, type CmdResult } from './runner';
import type { ExecLogEntry } from './types';

export type VcPlatform = 'linux' | 'windows' | 'unsupported';

/**
 * Detect the operating system and activate the corresponding auditing
 * modules automatically (spec §3). Windows support requires deployment on a
 * Windows host (PowerShell read-only collectors); this build reports honest
 * NOT_ASSESSED states when running elsewhere.
 */
export function detectPlatform(): VcPlatform {
  switch (process.platform) {
    case 'linux':
      return 'linux';
    case 'win32':
      return 'windows';
    default:
      return 'unsupported';
  }
}

/** Small structured logger with a module prefix — kept lightweight on purpose. */
export function createLogger(scope: string) {
  const prefix = `[vulncheck:${scope}]`;
  return {
    info: (...args: unknown[]) => console.log(prefix, ...args),
    warn: (...args: unknown[]) => console.warn(prefix, ...args),
    error: (...args: unknown[]) => console.error(prefix, ...args),
  };
}

/**
 * Shared helper: run an allowlisted command and record it in the exec log.
 * Never throws — returns a CmdResult so collectors can degrade gracefully.
 */
export async function loggedRun(
  id: Parameters<typeof runCommand>[0],
  args: string[],
  execLog: ExecLogEntry[],
): Promise<CmdResult> {
  const res = await runCommand(id, args);
  execLog.push(toExecLog(res));
  return res;
}

/**
 * Read a file safely (read-only). Returns null when unreadable/missing so
 * collectors can mark the affected rule NOT_ASSESSED instead of guessing.
 */
export async function readFileSafe(filePath: string, maxBytes = 2_000_000): Promise<string | null> {
  try {
    const fs = await import('fs/promises');
    const stat = await fs.stat(filePath);
    if (!stat.isFile() || stat.size > maxBytes) return null;
    return await fs.readFile(filePath, 'utf8');
  } catch {
    return null;
  }
}
