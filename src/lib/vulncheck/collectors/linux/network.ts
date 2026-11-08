/**
 * VulnCheck Local — Module D: Network Exposure Auditor collector (Linux)
 * ------------------------------------------------------------------------
 * Read-only, local-only. Sources: allowlisted `ss -Htuln` (listening sockets)
 * and `ss -Htn state established` (active connections).
 * Unknown services are never marked secure: defaults stay LOW/INFO with
 * explanatory notes.
 */

import { loggedRun } from '../../core/platform';
import type { ExecLogEntry, NetworkEvidence, PortInfo, Severity } from '../../core/types';

export function unavailableNetwork(notes: string[]): NetworkEvidence {
  return {
    available: false,
    source: 'n/a',
    notes: [...notes],
    listeningPorts: [],
    establishedCount: null,
    establishedSamples: [],
  };
}

interface PortMeta {
  service: string;
  risk: Severity;
  note: string;
}

/// Known-port mapping (spec table). Ports not listed fall through to defaults.
const PORT_TABLE: Record<number, PortMeta> = {
  21: { service: 'ftp', risk: 'HIGH', note: 'plaintext FTP' },
  22: { service: 'ssh', risk: 'INFO', note: 'SSH remote access — verify key-based auth' },
  23: { service: 'telnet', risk: 'CRITICAL', note: 'plaintext remote shell' },
  69: { service: 'tftp', risk: 'HIGH', note: 'trivial file transfer — unauthenticated' },
  80: { service: 'http', risk: 'INFO', note: 'web service' },
  111: { service: 'rpcbind', risk: 'MEDIUM', note: 'portmapper; often unnecessary' },
  139: { service: 'netbios-ssn', risk: 'HIGH', note: 'NetBIOS session service' },
  443: { service: 'https', risk: 'INFO', note: 'web service' },
  445: { service: 'microsoft-ds', risk: 'HIGH', note: 'SMB file sharing' },
  514: { service: 'syslog', risk: 'MEDIUM', note: 'remote syslog — often unauthenticated UDP' },
  631: { service: 'ipp', risk: 'LOW', note: 'print service' },
  873: { service: 'rsync', risk: 'MEDIUM', note: 'unauthenticated rsync possible' },
  1433: { service: 'mssql', risk: 'MEDIUM', note: 'database on listening socket' },
  1521: { service: 'oracle', risk: 'MEDIUM', note: 'database on listening socket' },
  2049: { service: 'nfs', risk: 'MEDIUM', note: 'network file share' },
  3000: { service: 'node-dev', risk: 'INFO', note: 'development server' },
  3306: { service: 'mysql', risk: 'MEDIUM', note: 'database on listening socket' },
  3389: { service: 'rdp', risk: 'HIGH', note: 'remote desktop' },
  5432: { service: 'postgresql', risk: 'MEDIUM', note: 'database on listening socket' },
  5555: { service: 'adb', risk: 'MEDIUM', note: 'Android debug bridge' },
  6379: { service: 'redis', risk: 'MEDIUM', note: 'often unauthenticated' },
  8080: { service: 'http-alt', risk: 'MEDIUM', note: 'alternate web service' },
  8443: { service: 'https-alt', risk: 'LOW', note: 'alternate TLS web service' },
  9050: { service: 'tor-socks', risk: 'MEDIUM', note: 'SOCKS proxy' },
  9200: { service: 'elasticsearch', risk: 'MEDIUM', note: 'search cluster API' },
  11211: { service: 'memcached', risk: 'HIGH', note: 'amplification/abuse history' },
  27017: { service: 'mongodb', risk: 'MEDIUM', note: 'database on listening socket' },
};

const RISK_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function classifyPort(port: number, proto: 'tcp' | 'udp', bindScope: PortInfo['bindScope']): PortMeta {
  // VNC range: 5900–5903
  if (port >= 5900 && port <= 5903) {
    return { service: 'vnc', risk: 'HIGH', note: 'VNC without guaranteed encryption' };
  }
  const hit = PORT_TABLE[port];
  if (hit) return hit;
  if (bindScope === 'LOCAL') {
    return { service: 'unknown', risk: 'INFO', note: 'local-only listener' };
  }
  if (bindScope === 'ALL') {
    if (proto === 'udp') {
      return { service: 'unknown', risk: 'LOW', note: 'UDP listener bound to all interfaces' };
    }
    return {
      service: 'unknown',
      risk: 'LOW',
      note: port >= 10000 ? 'unidentified service — confirm intended' : 'unidentified service bound to all interfaces',
    };
  }
  return { service: 'unknown', risk: 'INFO', note: 'bound to a specific interface' };
}

function bindScopeOf(rawAddr: string): PortInfo['bindScope'] {
  if (rawAddr === '0.0.0.0' || rawAddr === '[::]' || rawAddr === '*' || rawAddr === '::') return 'ALL';
  if (rawAddr.startsWith('127.') || rawAddr === '[::1]' || rawAddr === '::1') return 'LOCAL';
  return 'OTHER';
}

function parseListeningSockets(stdout: string): PortInfo[] {
  const ports: PortInfo[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    let idx = 0;
    let proto: 'tcp' | 'udp' = 'tcp';
    // With -t and -u combined, ss prefixes each row with the netid (tcp/tcp6/udp/udp6)
    if (/^(tcp|tcp6|udp|udp6)$/i.test(tokens[0])) {
      proto = tokens[0].toLowerCase().startsWith('tcp') ? 'tcp' : 'udp';
      idx = 1;
    }
    const state = (tokens[idx] ?? '').toUpperCase();
    if (state !== 'LISTEN' && state !== 'UNCONN') continue;
    const local = tokens[idx + 3];
    if (!local || !local.includes(':')) continue;
    const sep = local.lastIndexOf(':');
    const rawAddr = local.slice(0, sep);
    const port = Number(local.slice(sep + 1));
    if (!Number.isFinite(port) || port < 0 || port > 65535) continue;
    const bindScope = bindScopeOf(rawAddr);
    const meta = classifyPort(port, proto, bindScope);
    ports.push({
      proto,
      port,
      address: rawAddr.replace(/[[\]]/g, ''), // strip IPv6 brackets
      bindScope,
      service: meta.service,
      risk: meta.risk,
      note: meta.note,
    });
  }
  ports.sort((a, b) => RISK_RANK[a.risk] - RISK_RANK[b.risk] || a.port - b.port);
  return ports;
}

interface EstablishedSample {
  local: string;
  remote: string;
}

function parseEstablished(stdout: string): EstablishedSample[] {
  const samples: EstablishedSample[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    // `ss -Htn state established` may omit the State column: detect numeric Recv-Q lead
    let local: string | undefined;
    let remote: string | undefined;
    if (/^\d+$/.test(tokens[0]) && tokens.length >= 4) {
      local = tokens[2];
      remote = tokens[3];
    } else if (tokens.length >= 5) {
      local = tokens[3];
      remote = tokens[4];
    }
    if (local && remote) samples.push({ local, remote });
  }
  return samples;
}

/** Module D collector. Never throws. */
export async function collectNetwork(execLog: ExecLogEntry[]): Promise<NetworkEvidence> {
  const notes: string[] = [];
  try {
    const listenRes = await loggedRun('SS_LISTEN', ['-Htuln'], execLog);
    if (!listenRes.ok) {
      return {
        ...unavailableNetwork([
          `ss (listening sockets) query failed${
            listenRes.error ? ` (${listenRes.error})` : ''
          } — network exposure could not be assessed`,
          ...notes,
        ]),
        source: 'ss -tuln + ss -tn (established)',
      };
    }

    const listeningPorts = parseListeningSockets(listenRes.stdout);
    if (listeningPorts.length === 0) {
      notes.push('ss produced no listening socket rows — host appears to have no listening TCP/UDP sockets');
    }

    let establishedCount: number | null = null;
    let establishedSamples: EstablishedSample[] = [];
    const estRes = await loggedRun('SS_ESTABLISHED', ['-Htn', 'state', 'established'], execLog);
    if (estRes.ok) {
      const lines = estRes.stdout.split('\n').filter((l) => l.trim().length > 0);
      establishedCount = lines.length;
      establishedSamples = parseEstablished(estRes.stdout).slice(0, 20);
      if (establishedSamples.length < establishedCount) {
        notes.push(`established connection samples truncated to ${establishedSamples.length} of ${establishedCount}`);
      }
    } else {
      notes.push(
        `ss (established connections) query failed${
          estRes.error ? ` (${estRes.error})` : ''
        } — active connection count unknown`,
      );
    }

    return {
      available: true,
      source: 'ss -tuln + ss -tn (established)',
      notes,
      listeningPorts,
      establishedCount,
      establishedSamples,
    };
  } catch (err) {
    return unavailableNetwork([`Collection error: ${err instanceof Error ? err.message : String(err)}`]);
  }
}
