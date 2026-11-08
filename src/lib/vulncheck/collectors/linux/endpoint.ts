/**
 * VulnCheck Local — Module F: Antivirus & Protection collector (Linux)
 * ----------------------------------------------------------------------
 * Read-only. Sources: allowlisted `which` probes (clamscan/clamdscan/freshclam),
 * `systemctl is-active clamav-daemon`, /var/lib/clamav signature database.
 * Protection is NEVER claimed active unless it could actually be verified.
 * Windows Defender probing is out of scope on Linux (Windows rules handle it).
 */

import fs from 'fs/promises';
import { loggedRun } from '../../core/platform';
import type { EndpointEvidence, ExecLogEntry } from '../../core/types';

export function unavailableEndpoint(notes: string[]): EndpointEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    productName: null,
    binaryPresent: false,
    daemonRunning: null,
    signatureDb: { present: false, path: null, lastUpdated: null },
    verifiedActive: false,
  };
}

/// Probe one binary via the allowlisted WHICH command and record it in execLog.
async function probeBinary(binary: string, execLog: ExecLogEntry[]): Promise<string | null> {
  const res = await loggedRun('WHICH', [binary], execLog);
  if (!res.ok) return null;
  const p = res.stdout.trim().split('\n')[0]?.trim();
  return p && p.startsWith('/') ? p : null;
}

/// Probe a systemd unit's active state via the allowlisted is-active query.
async function probeUnitActive(execLog: ExecLogEntry[], unit: string): Promise<boolean | null> {
  const res = await loggedRun('SYSTEMCTL_IS_ACTIVE', ['is-active', unit], execLog);
  const out = res.stdout.trim();
  if (out === 'active') return true;
  if (out === 'inactive' || out === 'failed') return false;
  const text = `${res.stderr}\n${res.stdout}`;
  if (
    /system has not been booted with systemd|failed to connect to (system scope )?bus|ENOENT|EACCES|permission denied/i.test(
      text,
    )
  ) {
    return null; // systemctl itself failed (no bus / not booted with systemd)
  }
  if (/could not be found|not found|not loaded/i.test(text)) return false; // unit missing
  return null;
}

async function inspectSignatureDb(): Promise<{
  present: boolean;
  path: string | null;
  lastUpdated: string | null;
}> {
  const dir = '/var/lib/clamav';
  try {
    const st = await fs.stat(dir);
    if (!st.isDirectory()) return { present: false, path: null, lastUpdated: null };
  } catch {
    return { present: false, path: null, lastUpdated: null };
  }
  let lastUpdated: string | null = null;
  try {
    const entries = await fs.readdir(dir);
    let newest: Date | null = null;
    for (const name of entries) {
      if (!/\.(cvd|cld)$/i.test(name)) continue;
      try {
        const fst = await fs.stat(`${dir}/${name}`);
        if (!newest || fst.mtime > newest) newest = fst.mtime;
      } catch {
        /* unreadable entry — skip */
      }
    }
    lastUpdated = newest ? newest.toISOString() : null;
  } catch {
    /* directory unreadable */
  }
  return { present: true, path: dir, lastUpdated };
}

/** Module F collector. Never throws. */
export async function collectEndpoint(execLog: ExecLogEntry[]): Promise<EndpointEvidence> {
  const notes: string[] = [];
  try {
    const clamscan = await probeBinary('clamscan', execLog);
    const clamdscan = await probeBinary('clamdscan', execLog);
    const freshclam = await probeBinary('freshclam', execLog);
    const binaryPresent = Boolean(clamscan || clamdscan || freshclam);
    const productName = binaryPresent ? 'ClamAV' : null;

    const daemonRunning = await probeUnitActive(execLog, 'clamav-daemon');
    const signatureDb = await inspectSignatureDb();
    const verifiedActive = daemonRunning === true && binaryPresent;

    if (!binaryPresent) {
      notes.push('No anti-malware product detected (probed: ClamAV)');
      notes.push('Windows Defender probe is out of scope on Linux; Windows rules handle it on Windows hosts');
    }
    if (daemonRunning === null) {
      notes.push('clamav-daemon unit state could not be determined (systemd unavailable or unit probe failed)');
    }
    if (binaryPresent && daemonRunning === false) {
      notes.push('ClamAV binaries present but clamav-daemon is not running — real-time protection inactive');
    }
    if (signatureDb.present && signatureDb.lastUpdated === null) {
      notes.push('/var/lib/clamav exists but no .cvd/.cld signature files were found');
    }

    return {
      available: true,
      source: 'which probe + systemctl is-active clamav-daemon + /var/lib/clamav',
      notes,
      productName,
      binaryPresent,
      daemonRunning,
      signatureDb,
      verifiedActive,
    };
  } catch (err) {
    return unavailableEndpoint([`Collection error: ${err instanceof Error ? err.message : String(err)}`, ...notes]);
  }
}
