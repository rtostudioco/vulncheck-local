/**
 * VulnCheck Local — Module E: System Update Auditor collector (Linux)
 * --------------------------------------------------------------------
 * Read-only. Sources: allowlisted `apt list --upgradable`,
 * `apt-get --simulate dist-upgrade` (pure simulation — no changes performed),
 * /var/run/reboot-required flag, /etc/apt/apt.conf.d unattended-upgrades
 * configuration, /var/lib/apt/lists mtime.
 * Missing information is reported as null — never inferred to be healthy.
 */

import fs from 'fs/promises';
import { loggedRun, readFileSafe } from '../../core/platform';
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

function parseUpgradable(stdout: string): string[] {
  const names: string[] = [];
  let listingSeen = false;
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!listingSeen) {
      // header line looks like "Listing... Done"
      if (/^Listing/i.test(trimmed)) listingSeen = true;
      continue;
    }
    if (!trimmed) continue;
    // format: name/suite version arch [upgradable from: old]
    const name = trimmed.split('/')[0].split(/\s+/)[0];
    if (name) names.push(name);
  }
  return names;
}

function countSecurityFromSimulation(stdout: string): { count: number; names: string[] } {
  const security = new Set<string>();
  for (const line of stdout.split('\n')) {
    if (!line.startsWith('Inst')) continue;
    if (!/security/i.test(line)) continue;
    const name = line.trim().split(/\s+/)[1];
    if (name) security.add(name);
  }
  return { count: security.size, names: [...security].sort() };
}

async function detectAutoUpdates(notes: string[]): Promise<boolean | null> {
  let auto20: string | null = null;
  try {
    auto20 = await readFileSafe('/etc/apt/apt.conf.d/20auto-upgrades');
  } catch {
    auto20 = null;
  }
  if (auto20 !== null) {
    if (/Unattended-Upgrade\s+"1"/.test(auto20)) return true;
    if (/Unattended-Upgrade\s+"0"/.test(auto20)) return false;
    notes.push('20auto-upgrades present but the Unattended-Upgrade directive was not found');
    return null;
  }
  let auto50Present = false;
  try {
    auto50Present = (await readFileSafe('/etc/apt/apt.conf.d/50unattended-upgrades')) !== null;
  } catch {
    auto50Present = false;
  }
  if (auto50Present) {
    notes.push('periodic config absent; unattended-upgrades installed but periodic schedule not found');
    return null;
  }
  notes.push('No unattended-upgrades configuration found (20auto-upgrades and 50unattended-upgrades absent)');
  return null;
}

async function detectRebootRequired(notes: string[]): Promise<boolean> {
  try {
    await fs.stat('/var/run/reboot-required');
    notes.push('/var/run/reboot-required present — a reboot is required to complete kernel/security updates');
    return true;
  } catch {
    return false;
  }
}

async function lastUpdateCheck(): Promise<string | null> {
  try {
    const st = await fs.stat('/var/lib/apt/lists');
    return st.mtime.toISOString();
  } catch {
    return null;
  }
}

/** Module E collector. Never throws; never performs an actual upgrade. */
export async function collectUpdates(execLog: ExecLogEntry[]): Promise<UpdatesEvidence> {
  const notes: string[] = [];
  try {
    let pendingUpdates: number | null = null;
    let pendingPackageNames: string[] = [];
    let aptUpgradableOk = false;

    const aptRes = await loggedRun('APT_UPGRADABLE', ['list', '--upgradable'], execLog);
    if (aptRes.ok) {
      aptUpgradableOk = true;
      const allNames = parseUpgradable(aptRes.stdout);
      pendingUpdates = allNames.length;
      pendingPackageNames = allNames.slice(0, MAX_PENDING_NAMES);
      if (allNames.length > MAX_PENDING_NAMES) {
        notes.push(`pending package name list truncated to ${MAX_PENDING_NAMES} of ${allNames.length}`);
      }
    } else {
      notes.push(
        `apt list --upgradable failed${
          aptRes.error ? ` (${aptRes.error})` : ''
        } — pending update count unknown`,
      );
    }

    let pendingSecurityUpdates: number | null = null;
    let aptSimOk = false;
    const simRes = await loggedRun('APT_SIMULATE', ['--simulate', 'dist-upgrade'], execLog);
    if (simRes.ok) {
      aptSimOk = true;
      const parsed = countSecurityFromSimulation(simRes.stdout);
      pendingSecurityUpdates = parsed.count;
      if (parsed.names.length > 0) {
        notes.push(`packages flagged security in simulation: ${parsed.names.slice(0, 10).join(', ')}`);
      }
    } else {
      notes.push(
        `apt-get --simulate dist-upgrade failed${
          simRes.error ? ` (${simRes.error})` : ''
        } — security update breakdown unavailable`,
      );
    }

    const rebootRequired = await detectRebootRequired(notes);
    const autoUpdatesEnabled = await detectAutoUpdates(notes);
    const lastCheck = await lastUpdateCheck();
    if (lastCheck === null) notes.push('/var/lib/apt/lists mtime unavailable — last update check time unknown');

    return {
      available: aptUpgradableOk || aptSimOk,
      source: 'apt list --upgradable + apt-get --simulate dist-upgrade + /var/run/reboot-required',
      notes,
      pendingUpdates,
      pendingSecurityUpdates,
      pendingPackageNames,
      rebootRequired,
      autoUpdatesEnabled,
      lastUpdateCheck: lastCheck,
    };
  } catch (err) {
    return unavailableUpdates([`Collection error: ${err instanceof Error ? err.message : String(err)}`, ...notes]);
  }
}
