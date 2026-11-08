/**
 * VulnCheck Local — Module G: Service Auditor collector (Linux)
 * ---------------------------------------------------------------
 * Read-only. Sources: allowlisted `systemctl list-units --type=service
 * --state=running` and `ps -eo comm`. Never disables or touches services.
 */

import { loggedRun } from '../../core/platform';
import type { ExecLogEntry, RiskyServiceInfo, ServicesEvidence, Severity } from '../../core/types';

const MAX_RUNNING_SERVICES = 200;
const MAX_RUNNING_PROCESSES = 200;

export function unavailableServices(notes: string[]): ServicesEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    systemdAvailable: false,
    runningServices: [],
    runningProcesses: [],
    riskyServices: [],
  };
}

interface PatternGroup {
  names: string[];
  severity: Severity;
  reason: string;
}

/// Legacy/insecure service patterns — matched on the base name (suffixes stripped).
const PATTERN_GROUPS: PatternGroup[] = [
  { names: ['telnetd', 'in.telnetd'], severity: 'CRITICAL', reason: 'plaintext remote shell service' },
  { names: ['rshd', 'rlogind', 'rexecd'], severity: 'HIGH', reason: 'legacy r-services' },
  { names: ['tftpd', 'in.tftpd'], severity: 'HIGH', reason: 'plaintext TFTP daemon' },
  { names: ['vsftpd', 'proftpd', 'pure-ftpd'], severity: 'HIGH', reason: 'plaintext FTP daemon' },
  { names: ['smbd', 'nmbd'], severity: 'MEDIUM', reason: 'Samba services running' },
  { names: ['nfsd'], severity: 'MEDIUM', reason: 'NFS server running' },
  { names: ['snmpd'], severity: 'MEDIUM', reason: 'often default community strings' },
  { names: ['memcached'], severity: 'MEDIUM', reason: 'verify binding' },
  { names: ['redis-server'], severity: 'MEDIUM', reason: 'verify auth/binding' },
  { names: ['cupsd'], severity: 'LOW', reason: 'print service running' },
];

function normalizeServiceName(name: string): string {
  return name.replace(/\.service$/i, '').toLowerCase();
}

function detectRiskyServices(serviceNames: Set<string>): RiskyServiceInfo[] {
  const found: RiskyServiceInfo[] = [];
  for (const group of PATTERN_GROUPS) {
    for (const pattern of group.names) {
      if (serviceNames.has(pattern)) {
        found.push({ name: pattern, reason: group.reason, severity: group.severity });
        break;
      }
    }
  }
  return found;
}

/** Module G collector. Never throws. */
export async function collectServices(execLog: ExecLogEntry[]): Promise<ServicesEvidence> {
  const notes: string[] = [];
  try {
    let systemdAvailable = false;
    let runningServices: string[] = [];

    const units = await loggedRun(
      'SYSTEMCTL_UNITS',
      ['list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
      execLog,
    );
    if (units.ok) {
      systemdAvailable = true;
      const lines = units.stdout
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      for (const line of lines) {
        const name = line.split(/\s+/)[0];
        if (name) runningServices.push(name);
        if (runningServices.length >= MAX_RUNNING_SERVICES) {
          notes.push(`running service list truncated to ${MAX_RUNNING_SERVICES} entries`);
          break;
        }
      }
      if (lines.length === 0) notes.push('systemctl responded but reported no running service units');
    } else {
      notes.push('systemd unavailable (container?) — process table used as fallback');
    }

    let runningProcesses: string[] = [];
    let psOk = false;
    const ps = await loggedRun('PS_COMM', ['-eo', 'comm', '--no-headers'], execLog);
    if (ps.ok) {
      psOk = true;
      const all = [...new Set(ps.stdout.split('\n').map((s) => s.trim()).filter((s) => s.length > 0))].sort();
      runningProcesses = all.slice(0, MAX_RUNNING_PROCESSES);
      if (all.length > MAX_RUNNING_PROCESSES) {
        notes.push(`process name list truncated to ${MAX_RUNNING_PROCESSES} of ${all.length} unique names`);
      }
    } else {
      notes.push(`ps -eo comm failed${ps.error ? ` (${ps.error})` : ''} — process table unavailable`);
    }

    // union of systemd unit names and process names for risk pattern matching
    const names = new Set<string>();
    for (const s of runningServices) names.add(normalizeServiceName(s));
    for (const p of runningProcesses) names.add(p.toLowerCase());
    const riskyServices = detectRiskyServices(names);

    return {
      available: systemdAvailable || psOk,
      source: 'systemctl list-units + ps -eo comm',
      notes,
      systemdAvailable,
      runningServices,
      runningProcesses,
      riskyServices,
    };
  } catch (err) {
    return unavailableServices([`Collection error: ${err instanceof Error ? err.message : String(err)}`, ...notes]);
  }
}
