/**
 * VulnCheck Local — Module H: Backup & Recovery Auditor collector (Windows)
 * ---------------------------------------------------------------------------
 * Read-only. Sources: allowlisted PowerShell query PS_BACKUP_VERSIONS —
 * `wbadmin get versions -quiet` output plus System Restore points via
 * Get-CimInstance root\\default SystemRestore.
 * A backup is NEVER claimed valid: lastBackupDate is a catalog/restore-point
 * timestamp only.
 */

import { asDateIso, asJsonArray, asNumber, asString, failureNote, parseJsonObject, runPs } from './ps';
import type { BackupEvidence, BackupJobInfo, ExecLogEntry } from '../../core/types';

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

interface WbadminVersion {
  identifier: string | null;
  backupTime: string | null; // ISO or null when unparseable
}

function parseWbadminOutput(text: string): { versions: WbadminVersion[]; catalogPresent: boolean } {
  const versions: WbadminVersion[] = [];
  const lines = text.split('\n');
  let current: WbadminVersion | null = null;
  let catalogPresent = false;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    const idM = /^Version identifier:\s*(.+)$/i.exec(line);
    if (idM) {
      catalogPresent = true;
      if (current) versions.push(current);
      current = { identifier: idM[1].trim(), backupTime: null };
      continue;
    }
    const timeM = /^Backup time:\s*(.+)$/i.exec(line);
    if (timeM && current) {
      const raw = timeM[1].trim();
      // wbadmin prints locale-formatted dates — parse best effort, flag unparseable.
      const parsed = Date.parse(raw);
      current.backupTime = Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
    }
  }
  if (current) versions.push(current);
  return { versions, catalogPresent };
}

/** Module H collector (Windows). Never throws; a backup is never claimed valid. */
export async function collectBackup(execLog: ExecLogEntry[]): Promise<BackupEvidence> {
  const notes: string[] = [];
  try {
    const res = await runPs('PS_BACKUP_VERSIONS', execLog);
    if (!res.ok) {
      return {
        ...unavailableBackup([
          failureNote(res, 'backup version/restore-point query') +
            ' — backup evidence could not be collected (wbadmin catalog and System Restore unavailable)',
        ]),
        source: 'wbadmin get versions + root\\default SystemRestore',
      };
    }

    const payload = parseJsonObject(res.stdout);
    if (!payload) {
      return {
        ...unavailableBackup([
          'backup query returned unparseable output — backup evidence unavailable',
        ]),
        source: 'wbadmin get versions + root\\default SystemRestore',
      };
    }

    const toolsDetected: string[] = [];
    const wbadminOutput = asString(payload.wbadminOutput);
    const wbadminError = asString(payload.wbadminError);
    const restorePoints = asJsonArray(payload.restorePoints);

    // ------------------------------------------------------------- wbadmin
    let lastBackupDate: string | null = null;
    let lastSource: 'wbadmin' | 'system-restore' | null = null;
    if (wbadminError !== null) {
      notes.push(`wbadmin get versions failed: ${wbadminError.slice(0, 200)}`);
    } else if (wbadminOutput !== null) {
      const { versions, catalogPresent } = parseWbadminOutput(wbadminOutput);
      toolsDetected.push('wbadmin (Windows Server Backup)');
      if (!catalogPresent) {
        notes.push('wbadmin responded but no backup versions/catalog entries were found');
      }
      const unparsed = versions.filter((v) => v.backupTime === null).length;
      if (unparsed > 0) {
        notes.push(`${unparsed} wbadmin version timestamp(s) could not be parsed (locale-specific format)`);
      }
      const newest = versions
        .map((v) => v.backupTime)
        .filter((t): t is string => t !== null)
        .sort()
        .pop();
      if (newest) {
        lastBackupDate = newest;
        lastSource = 'wbadmin';
      }
    } else {
      notes.push('wbadmin produced no output — Windows Server Backup state unknown');
    }

    // -------------------------------------------------------- restore points
    if (restorePoints.length > 0) {
      toolsDetected.push('System Restore');
      const times = restorePoints
        .map((r) => asDateIso(r.CreationTime))
        .filter((t): t is string => t !== null)
        .sort();
      if (times.length > 0) {
        const newestRestore = times[times.length - 1];
        if (!lastBackupDate || newestRestore > lastBackupDate) {
          // Only prefer a restore point when no wbadmin catalog exists.
          if (!lastSource) {
            lastBackupDate = newestRestore;
            lastSource = 'system-restore';
          }
        }
        notes.push(`${restorePoints.length} System Restore point(s) found; newest ${times[times.length - 1]}`);
      } else {
        notes.push('System Restore points exist but their creation times could not be parsed');
      }
    } else {
      notes.push('no System Restore points found (System Restore may be disabled or the query requires elevation)');
    }

    const rpCount = restorePoints
      .map((r) => asNumber(r.SequenceNumber))
      .filter((n): n is number => n !== null).length;

    notes.push('scheduled Task Scheduler jobs are not enumerated by the read-only Windows allowlist');
    notes.push(
      `lastBackupDate is a ${lastSource === 'wbadmin' ? 'wbadmin catalog' : lastSource === 'system-restore' ? `System Restore (${rpCount} point(s))` : 'timestamp'} indicator only — NOT proof of a valid backup`,
    );

    return {
      available: true,
      source: 'wbadmin get versions + root\\default SystemRestore',
      notes,
      toolsDetected,
      scheduledJobs: [] as BackupJobInfo[],
      snapshotDirs: [], // snapshot-directory concept is not applicable on Windows
      lastBackupDate,
    };
  } catch (err) {
    return unavailableBackup([`Collection error: ${err instanceof Error ? err.message : String(err)}`]);
  }
}
