/**
 * VulnCheck Local — Module E: System Update Auditor collector (Windows)
 * ----------------------------------------------------------------------
 * Read-only. Sources: allowlisted PowerShell queries — the read-only
 * Microsoft.Update.Session COM search (PS_UPDATES_PENDING, 30s cap) and
 * registry-based pending-reboot markers plus the NoAutoUpdate policy
 * (PS_PENDING_REBOOT).
 * Missing information is reported as null — never inferred to be healthy.
 * If the update search fails the module degrades to PARTIAL with a note.
 */

import { asBool, asNumber, asString, failureNote, parseJsonArray, parseJsonObject, runPs } from './ps';
import type { ExecLogEntry, UpdatesEvidence } from '../../core/types';

const MAX_PENDING_NAMES = 50;

export function unavailableUpdates(notes: string[]): UpdatesEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    pendingUpdates: null,
    pendingSecurityUpdates: null,
    pendingPackageNames: [],
    rebootRequired: null,
    autoUpdatesEnabled: null,
    lastUpdateCheck: null,
  };
}

interface PendingUpdateRow {
  title: string;
  severity: string | null;
  isDownloaded: boolean | null;
}

function parsePendingUpdates(stdout: string): { rows: PendingUpdateRow[]; searchError: string | null } {
  const obj = parseJsonObject(stdout);
  // A failed search produces {"searchError": "..."} (a bare object, not an array)
  if (obj && typeof obj.searchError === 'string') {
    return { rows: [], searchError: obj.searchError };
  }
  const rows = parseJsonArray(stdout)
    .map((r) => ({
      title: asString(r.Title) ?? 'unknown update',
      severity: asString(r.Severity),
      isDownloaded: asBool(r.IsDownloaded),
    }))
    .filter((r) => r.title !== 'unknown update' || r.severity !== null);
  return { rows, searchError: null };
}

/** Module E collector (Windows). Never throws; never downloads/installs anything. */
export async function collectUpdates(execLog: ExecLogEntry[]): Promise<UpdatesEvidence> {
  const notes: string[] = [];
  try {
    // --------------------------------------------- pending updates (COM search)
    let pendingUpdates: number | null = null;
    let pendingSecurityUpdates: number | null = null;
    let pendingPackageNames: string[] = [];
    let searchOk = false;

    const updRes = await runPs('PS_UPDATES_PENDING', execLog);
    if (updRes.ok) {
      const { rows, searchError } = parsePendingUpdates(updRes.stdout);
      if (searchError !== null) {
        notes.push(
          `Windows Update online search failed: ${searchError.slice(0, 200)} — pending update counts unknown`,
        );
      } else {
        searchOk = true;
        pendingUpdates = rows.length;
        pendingSecurityUpdates = rows.filter((r) => r.severity !== null).length;
        pendingPackageNames = rows.slice(0, MAX_PENDING_NAMES).map((r) => r.title);
        if (rows.length > MAX_PENDING_NAMES) {
          notes.push(`pending update title list truncated to ${MAX_PENDING_NAMES} of ${rows.length}`);
        }
        const downloaded = rows.filter((r) => r.isDownloaded === true).length;
        if (downloaded > 0) notes.push(`${downloaded} of ${rows.length} pending update(s) already downloaded`);
      }
    } else {
      notes.push(failureNote(updRes, 'Windows Update search') + ' — pending update counts unknown');
    }

    // ------------------------------------------- reboot required + AU policy
    let rebootRequired: boolean | null = null;
    let autoUpdatesEnabled: boolean | null = null;
    let rebootOk = false;

    const rebootRes = await runPs('PS_PENDING_REBOOT', execLog);
    const reb = rebootRes.ok ? parseJsonObject(rebootRes.stdout) : null;
    if (reb) {
      rebootOk = true;
      const wu = asBool(reb.wuRebootPending) === true;
      const cbs = asBool(reb.cbsRebootPending) === true;
      const pfr = asBool(reb.pendingFileRename) === true;
      rebootRequired = wu || cbs || pfr;
      if (rebootRequired) {
        const why = [wu && 'Windows Update', cbs && 'Component Based Servicing', pfr && 'pending file renames']
          .filter((s): s is string => typeof s === 'string')
          .join(', ');
        notes.push(`reboot required to complete pending operations (${why})`);
      }
      const noAuto = asNumber(reb.noAutoUpdate);
      if (noAuto === 1) {
        autoUpdatesEnabled = false;
        notes.push('NoAutoUpdate policy = 1 — automatic updates disabled by policy');
      } else if (noAuto === 0) {
        autoUpdatesEnabled = true;
      } else {
        notes.push('no NoAutoUpdate policy value found — Windows default update behavior applies but was not verified');
      }
    } else {
      notes.push(failureNote(rebootRes, 'pending-reboot registry query'));
    }

    notes.push('last update check time is not exposed by the read-only Windows allowlist');

    return {
      available: searchOk || rebootOk,
      source: 'Microsoft.Update.Session COM search + reboot/policy registry markers',
      notes,
      pendingUpdates,
      pendingSecurityUpdates,
      pendingPackageNames,
      rebootRequired,
      autoUpdatesEnabled,
      lastUpdateCheck: null,
    };
  } catch (err) {
    return unavailableUpdates([`Collection error: ${err instanceof Error ? err.message : String(err)}`, ...notes]);
  }
}
