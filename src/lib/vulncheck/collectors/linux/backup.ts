/**
 * VulnCheck Local — Module H: Backup & Recovery Auditor collector (Linux)
 * -------------------------------------------------------------------------
 * Read-only. Sources: allowlisted `which` probes for backup tools,
 * /etc/crontab, /etc/cron.d/*, /etc/cron.{daily,weekly,monthly},
 * snapshot/backup directories (/timeshift, /snapshots, /.snapshots, /var/backups).
 * A backup is NEVER claimed valid: lastBackupDate is a filesystem timestamp only.
 */

import fsSync from 'fs';
import fs from 'fs/promises';
import { loggedRun, readFileSafe } from '../../core/platform';
import type { Dirent } from 'fs';
import type { BackupEvidence, BackupJobInfo, ExecLogEntry } from '../../core/types';

const BACKUP_TOOLS = [
  'timeshift',
  'rsnapshot',
  'restic',
  'borg',
  'borgmatic',
  'duplicity',
  'deja-dup',
  'bacula',
  'kopia',
];

const BACKUP_JOB_RE = /backup|rsync|tar |duplicity|borg|restic|timeshift|rsnapshot|dump|snapshot|syncthing/i;
const MAX_JOBS = 30;
const SNAPSHOT_DIRS = ['/timeshift', '/snapshots', '/.snapshots', '/var/backups'];

export function unavailableBackup(notes: string[]): BackupEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    toolsDetected: [],
    scheduledJobs: [],
    snapshotDirs: [],
    lastBackupDate: null,
  };
}

/// Probe one binary via the allowlisted WHICH command and record it in execLog.
async function probeBinary(binary: string, execLog: ExecLogEntry[]): Promise<string | null> {
  const res = await loggedRun('WHICH', [binary], execLog);
  if (!res.ok) return null;
  const p = res.stdout.trim().split('\n')[0]?.trim();
  return p && p.startsWith('/') ? p : null;
}

async function parseCronFile(
  filePath: string,
  jobs: BackupJobInfo[],
  scanned: { n: number },
): Promise<void> {
  const text = await readFileSafe(filePath);
  if (text === null) return;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (/^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(trimmed)) continue; // variable assignment
    const fields = trimmed.split(/\s+/);
    // /etc/crontab and cron.d lines: min hour dom mon dow user command...
    if (fields.length < 7) continue;
    scanned.n += 1;
    const schedule = fields.slice(0, 5).join(' ');
    const command = fields.slice(6).join(' ');
    if (BACKUP_JOB_RE.test(command)) {
      jobs.push({ file: filePath, schedule, command });
    }
  }
}

async function scanPeriodicDirs(
  jobs: BackupJobInfo[],
  scanned: { n: number },
): Promise<void> {
  const periodic: [string, string][] = [
    ['/etc/cron.daily', 'daily'],
    ['/etc/cron.weekly', 'weekly'],
    ['/etc/cron.monthly', 'monthly'],
  ];
  for (const [dir, schedule] of periodic) {
    try {
      const entries = await fs.readdir(dir);
      for (const entry of entries) {
        scanned.n += 1;
        if (BACKUP_JOB_RE.test(entry)) {
          jobs.push({ file: dir, schedule, command: entry });
        }
      }
    } catch {
      /* directory absent — fine */
    }
  }
}

/// Shallow recursive newest-file mtime scan (read-only, bounded).
async function newestFileMtime(
  dir: string,
  depth: number,
  budget: { n: number },
): Promise<Date | null> {
  let newest: Date | null = null;
  if (depth < 0 || budget.n <= 0) return newest;
  let entries: Dirent[] = [];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return newest;
  }
  for (const entry of entries) {
    if (budget.n <= 0) break;
    budget.n -= 1;
    const full = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      const sub = await newestFileMtime(full, depth - 1, budget);
      if (sub && (!newest || sub > newest)) newest = sub;
    } else if (entry.isFile()) {
      try {
        const st = await fs.stat(full);
        if (!newest || st.mtime > newest) newest = st.mtime;
      } catch {
        /* unreadable file — skip */
      }
    }
  }
  return newest;
}

/** Module H collector. Never throws; a backup is never claimed valid. */
export async function collectBackup(execLog: ExecLogEntry[]): Promise<BackupEvidence> {
  const notes: string[] = [];
  try {
    const toolsDetected: string[] = [];
    for (const tool of BACKUP_TOOLS) {
      const path = await probeBinary(tool, execLog);
      if (path) toolsDetected.push(tool);
    }
    if (toolsDetected.length > 0) {
      notes.push(`Backup tools detected: ${toolsDetected.join(', ')}`);
    }

    // Scheduled jobs from cron configuration
    const jobs: BackupJobInfo[] = [];
    const scanned = { n: 0 };
    await parseCronFile('/etc/crontab', jobs, scanned);
    try {
      const cronD = await fs.readdir('/etc/cron.d');
      for (const name of cronD.sort()) {
        await parseCronFile(`/etc/cron.d/${name}`, jobs, scanned);
      }
    } catch {
      /* /etc/cron.d absent */
    }
    await scanPeriodicDirs(jobs, scanned);
    const totalScanned = scanned.n;
    const scheduledJobs = jobs.slice(0, MAX_JOBS);
    if (jobs.length > MAX_JOBS) {
      notes.push(`scheduled job list truncated to ${MAX_JOBS} of ${jobs.length} matching jobs`);
    }
    notes.push(
      `scanned ${totalScanned} scheduled job entries across /etc/crontab, /etc/cron.d and periodic cron directories`,
    );

    // Snapshot / backup directories
    const snapshotDirs = SNAPSHOT_DIRS.filter((d) => {
      try {
        return fsSync.existsSync(d);
      } catch {
        return false;
      }
    });
    if (snapshotDirs.length === 0) {
      notes.push('no snapshot/backup directories found (/timeshift, /snapshots, /.snapshots, /var/backups)');
    }

    // Recency indicator — newest file mtime. NOT proof of a valid backup.
    let lastBackupDate: string | null = null;
    let sourceDir: string | null = null;
    const budget = { n: 500 };
    for (const dir of ['/timeshift', '/snapshots', '/.snapshots']) {
      if (!snapshotDirs.includes(dir)) continue;
      const d = await newestFileMtime(dir, 3, budget);
      if (d) {
        lastBackupDate = d.toISOString();
        sourceDir = dir;
      }
    }
    if (!lastBackupDate && snapshotDirs.includes('/var/backups')) {
      const d = await newestFileMtime('/var/backups', 2, budget);
      if (d) {
        lastBackupDate = d.toISOString();
        sourceDir = '/var/backups';
      }
    }
    if (lastBackupDate && sourceDir) {
      notes.push(
        sourceDir === '/var/backups'
          ? 'newest file in /var/backups — NOT proof of a valid backup'
          : `newest file in ${sourceDir} — NOT proof of a valid backup`,
      );
    }

    return {
      available: true,
      source: 'which probe + /etc/cron* + snapshot directories',
      notes,
      toolsDetected,
      scheduledJobs,
      snapshotDirs,
      lastBackupDate,
    };
  } catch (err) {
    return unavailableBackup([`Collection error: ${err instanceof Error ? err.message : String(err)}`, ...notes]);
  }
}
