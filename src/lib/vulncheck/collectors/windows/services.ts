/**
 * VulnCheck Local — Module G: Service Auditor collector (Windows)
 * -----------------------------------------------------------------
 * Read-only. Sources: allowlisted PowerShell query Get-CimInstance
 * Win32_Service (name, state, start mode, running account). Never disables
 * or touches services.
 * Flags: auto-start services that are not running, disabled Windows Update
 * stack services and legacy remote-administration services.
 */

import { asNumber, asString, failureNote, parseJsonArray, runPs } from './ps';
import type { ExecLogEntry, RiskyServiceInfo, ServicesEvidence, Severity } from '../../core/types';

const MAX_RUNNING_SERVICES = 200;
const MAX_AUTOSTOP_FLAGS = 25;

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

interface ServiceRow {
  name: string;
  displayName: string | null;
  state: string | null;
  startMode: string | null;
  startName: string | null;
  processId: number | null;
}

function parseServices(stdout: string): ServiceRow[] {
  return parseJsonArray(stdout)
    .map((r) => ({
      name: asString(r.Name),
      displayName: asString(r.DisplayName),
      state: asString(r.State)?.toLowerCase() ?? null,
      startMode: asString(r.StartMode)?.toLowerCase() ?? null,
      startName: asString(r.StartName),
      processId: asNumber(r.ProcessId),
    }))
    .filter((s): s is ServiceRow => s.name !== null);
}

/// Legacy/unsafe Windows service patterns (matched on service NAME).
const PATTERN_GROUPS: { names: string[]; severity: Severity; reason: string }[] = [
  { names: ['tlntsvr'], severity: 'CRITICAL', reason: 'Telnet server running — plaintext remote shell service' },
  { names: ['remoteregistry'], severity: 'MEDIUM', reason: 'Remote Registry service running — remote access to registry' },
  { names: ['snmp'], severity: 'MEDIUM', reason: 'SNMP service running — verify community strings/binding' },
  { names: ['sessionenv'], severity: 'LOW', reason: 'Remote Desktop Configuration service running' },
  { names: ['ssdpsrv', 'upnphost'], severity: 'LOW', reason: 'UPnP/SSDP discovery service running — verify network trust' },
];

/// The Windows Update stack — disabled members are security-relevant (VC-WIN-006).
const UPDATE_STACK = ['wuauserv', 'usosvc', 'bits'];

function detectRiskyServices(services: ServiceRow[]): { risky: RiskyServiceInfo[]; truncated: boolean } {
  const risky: RiskyServiceInfo[] = [];
  let truncated = false;

  // legacy/unsafe services that are RUNNING
  for (const group of PATTERN_GROUPS) {
    for (const pattern of group.names) {
      const svc = services.find((s) => s.name.toLowerCase() === pattern);
      if (svc && svc.state === 'running') {
        risky.push({ name: svc.name, reason: group.reason, severity: group.severity });
        break;
      }
    }
  }

  // disabled Windows Update stack services
  for (const svc of services) {
    const n = svc.name.toLowerCase();
    if (UPDATE_STACK.includes(n) && svc.startMode === 'disabled') {
      risky.push({
        name: svc.name,
        reason: `${svc.name} is Disabled — Windows Update cannot deliver security patches via this service`,
        severity: 'MEDIUM',
      });
    }
  }

  // auto-start services that are not running (may be trigger-started — low severity)
  const autoStopped = services.filter((s) => s.startMode === 'auto' && s.state !== 'running');
  if (autoStopped.length > MAX_AUTOSTOP_FLAGS) truncated = true;
  for (const svc of autoStopped.slice(0, MAX_AUTOSTOP_FLAGS)) {
    risky.push({
      name: svc.name,
      reason: `auto-start service is ${svc.state ?? 'not running'} (verify intended state; may be trigger-started)`,
      severity: 'LOW',
    });
  }

  return { risky, truncated };
}

/** Module G collector (Windows). Never throws. */
export async function collectServices(execLog: ExecLogEntry[]): Promise<ServicesEvidence> {
  const notes: string[] = [];
  try {
    const res = await runPs('PS_SERVICES', execLog);
    if (!res.ok) {
      return {
        ...unavailableServices([failureNote(res, 'Win32_Service query') + ' — service inventory unavailable']),
        source: 'Get-CimInstance Win32_Service',
      };
    }

    const services = parseServices(res.stdout);
    if (services.length === 0) {
      notes.push('Win32_Service query succeeded but returned no services — unexpected; verify service control manager');
    }

    const runningServices = services
      .filter((s) => s.state === 'running')
      .map((s) => s.name)
      .slice(0, MAX_RUNNING_SERVICES);
    const runningTotal = services.filter((s) => s.state === 'running').length;
    if (runningTotal > MAX_RUNNING_SERVICES) {
      notes.push(`running service list truncated to ${MAX_RUNNING_SERVICES} of ${runningTotal} entries`);
    }

    // Running-as account summary (account NAMES only — no credentials collected)
    const byAccount = new Map<string, number>();
    for (const s of services) {
      if (s.state !== 'running' || !s.startName) continue;
      const acct = s.startName.toLowerCase();
      byAccount.set(acct, (byAccount.get(acct) ?? 0) + 1);
    }
    if (byAccount.size > 0) {
      const summary = [...byAccount.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([acct, n]) => `${acct} (${n})`)
        .join(', ');
      notes.push(`services run as (account names only): ${summary}`);
    }

    // Windows Update stack detail (used by rule VC-WIN-006 evidence text)
    for (const name of UPDATE_STACK) {
      const svc = services.find((s) => s.name.toLowerCase() === name);
      if (svc) {
        notes.push(`${svc.name}: State=${svc.state ?? 'unknown'}, StartMode=${svc.startMode ?? 'unknown'}`);
      } else {
        notes.push(`${name}: not present on this system`);
      }
    }

    const { risky, truncated } = detectRiskyServices(services);
    if (truncated) {
      notes.push(`auto-start-stopped service flags truncated to ${MAX_AUTOSTOP_FLAGS} entries`);
    }

    notes.push('systemd is not applicable on Windows; service state collected via the Windows Service Control Manager (Win32_Service)');
    notes.push('process table (Get-Process) is not part of the read-only Windows allowlist — runningProcesses is empty by design');

    return {
      available: true,
      source: 'Get-CimInstance Win32_Service',
      notes,
      systemdAvailable: false,
      runningServices,
      runningProcesses: [],
      riskyServices: risky,
    };
  } catch (err) {
    return unavailableServices([`Collection error: ${err instanceof Error ? err.message : String(err)}`]);
  }
}
