/**
 * VulnCheck Local — Module D: Network Exposure Auditor collector (Windows)
 * --------------------------------------------------------------------------
 * Read-only, local-only. Sources: allowlisted PowerShell queries —
 * Get-NetTCPConnection (Listen/Established), Get-NetUDPEndpoint and
 * Get-NetAdapter (context only).
 * Unknown services are never marked secure: defaults stay LOW/INFO with
 * explanatory notes.
 */

import { asNumber, asString, failureNote, parseJsonArray, runPs } from './ps';
import type { ExecLogEntry, NetworkEvidence, PortInfo, Severity } from '../../core/types';

const MAX_PORTS = 500;
const MAX_SAMPLES = 20;

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

/// Known-port mapping (mirrors the Linux table plus Windows-specific listeners).
const PORT_TABLE: Record<number, PortMeta> = {
  21: { service: 'ftp', risk: 'HIGH', note: 'plaintext FTP' },
  22: { service: 'ssh', risk: 'INFO', note: 'SSH remote access — verify key-based auth' },
  23: { service: 'telnet', risk: 'CRITICAL', note: 'plaintext remote shell' },
  69: { service: 'tftp', risk: 'HIGH', note: 'trivial file transfer — unauthenticated' },
  80: { service: 'http', risk: 'INFO', note: 'web service' },
  111: { service: 'rpcbind', risk: 'MEDIUM', note: 'portmapper; often unnecessary' },
  135: { service: 'rpc-epmap', risk: 'MEDIUM', note: 'RPC endpoint mapper — restrict exposure' },
  139: { service: 'netbios-ssn', risk: 'HIGH', note: 'NetBIOS session service' },
  443: { service: 'https', risk: 'INFO', note: 'web service' },
  445: { service: 'microsoft-ds', risk: 'HIGH', note: 'SMB file sharing' },
  514: { service: 'syslog', risk: 'MEDIUM', note: 'remote syslog — often unauthenticated UDP' },
  631: { service: 'ipp', risk: 'LOW', note: 'print service' },
  1433: { service: 'mssql', risk: 'MEDIUM', note: 'SQL Server listening socket' },
  1900: { service: 'ssdp', risk: 'LOW', note: 'SSDP discovery (UPnP)' },
  2049: { service: 'nfs', risk: 'MEDIUM', note: 'network file share' },
  3000: { service: 'node-dev', risk: 'INFO', note: 'development server' },
  3306: { service: 'mysql', risk: 'MEDIUM', note: 'database on listening socket' },
  3389: { service: 'rdp', risk: 'HIGH', note: 'remote desktop' },
  5040: { service: 'cdp', risk: 'INFO', note: 'Windows Connected Devices Platform' },
  5353: { service: 'mdns', risk: 'LOW', note: 'multicast DNS' },
  5355: { service: 'llmnr', risk: 'LOW', note: 'link-local multicast name resolution' },
  5432: { service: 'postgresql', risk: 'MEDIUM', note: 'database on listening socket' },
  5357: { service: 'wsd-http', risk: 'LOW', note: 'WSD web services printer/scan' },
  5439: { service: 'unknown-db', risk: 'MEDIUM', note: 'database-like listener' },
  5555: { service: 'adb', risk: 'MEDIUM', note: 'Android debug bridge' },
  5900: { service: 'vnc', risk: 'HIGH', note: 'VNC without guaranteed encryption' },
  5985: { service: 'winrm-http', risk: 'MEDIUM', note: 'WinRM remote management (plaintext HTTP transport)' },
  5986: { service: 'winrm-https', risk: 'MEDIUM', note: 'WinRM remote management (TLS transport)' },
  6379: { service: 'redis', risk: 'MEDIUM', note: 'often unauthenticated' },
  7680: { service: 'delivery-optimization', risk: 'LOW', note: 'Windows Delivery Optimization' },
  8080: { service: 'http-alt', risk: 'MEDIUM', note: 'alternate web service' },
  8443: { service: 'https-alt', risk: 'LOW', note: 'alternate TLS web service' },
  9050: { service: 'tor-socks', risk: 'MEDIUM', note: 'SOCKS proxy' },
  9200: { service: 'elasticsearch', risk: 'MEDIUM', note: 'search cluster API' },
  11211: { service: 'memcached', risk: 'HIGH', note: 'amplification/abuse history' },
  27017: { service: 'mongodb', risk: 'MEDIUM', note: 'database on listening socket' },
  47001: { service: 'winrm', risk: 'MEDIUM', note: 'WinRM listener (WS-Management)' },
};

const RISK_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function classifyPort(port: number, proto: 'tcp' | 'udp', bindScope: PortInfo['bindScope']): PortMeta {
  if (port >= 5901 && port <= 5903) {
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
  if (rawAddr === '0.0.0.0' || rawAddr === '::' || rawAddr === '*') return 'ALL';
  if (rawAddr.startsWith('127.') || rawAddr === '::1') return 'LOCAL';
  return 'OTHER';
}

function parseTcpListen(stdout: string): PortInfo[] {
  const ports: PortInfo[] = [];
  for (const row of parseJsonArray(stdout)) {
    const port = asNumber(row.LocalPort);
    const address = asString(row.LocalAddress);
    if (port === null || port < 0 || port > 65535 || !address) continue;
    const bindScope = bindScopeOf(address);
    const meta = classifyPort(port, 'tcp', bindScope);
    ports.push({ proto: 'tcp', port, address, bindScope, service: meta.service, risk: meta.risk, note: meta.note });
  }
  return ports;
}

function parseUdpListen(stdout: string): PortInfo[] {
  const ports: PortInfo[] = [];
  for (const row of parseJsonArray(stdout)) {
    const port = asNumber(row.LocalPort);
    const address = asString(row.LocalAddress);
    if (port === null || port < 0 || port > 65535 || !address) continue;
    const bindScope = bindScopeOf(address);
    const meta = classifyPort(port, 'udp', bindScope);
    ports.push({ proto: 'udp', port, address, bindScope, service: meta.service, risk: meta.risk, note: meta.note });
  }
  return ports;
}

function dedupePorts(ports: PortInfo[]): PortInfo[] {
  const seen = new Set<string>();
  const out: PortInfo[] = [];
  for (const p of ports) {
    const key = `${p.proto}:${p.port}:${p.address}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  out.sort((a, b) => RISK_RANK[a.risk] - RISK_RANK[b.risk] || a.port - b.port);
  return out;
}

interface EstablishedSample {
  local: string;
  remote: string;
}

function parseEstablished(stdout: string): EstablishedSample[] {
  const samples: EstablishedSample[] = [];
  for (const row of parseJsonArray(stdout)) {
    const localAddr = asString(row.LocalAddress);
    const localPort = asNumber(row.LocalPort);
    const remoteAddr = asString(row.RemoteAddress);
    const remotePort = asNumber(row.RemotePort);
    if (!localAddr || localPort === null || !remoteAddr || remotePort === null) continue;
    samples.push({ local: `${localAddr}:${localPort}`, remote: `${remoteAddr}:${remotePort}` });
  }
  return samples;
}

/** Module D collector (Windows). Never throws. */
export async function collectNetwork(execLog: ExecLogEntry[]): Promise<NetworkEvidence> {
  const notes: string[] = [];
  try {
    // -------------------------------------------------------- listening sockets
    let listeningPorts: PortInfo[] = [];
    let tcpOk = false;
    let udpOk = false;

    const tcpRes = await runPs('PS_LISTEN_TCP', execLog);
    if (tcpRes.ok) {
      tcpOk = true;
      listeningPorts.push(...parseTcpListen(tcpRes.stdout));
    } else {
      notes.push(failureNote(tcpRes, 'Get-NetTCPConnection (listen) query'));
    }

    const udpRes = await runPs('PS_LISTEN_UDP', execLog);
    if (udpRes.ok) {
      udpOk = true;
      listeningPorts.push(...parseUdpListen(udpRes.stdout));
    } else {
      notes.push(failureNote(udpRes, 'Get-NetUDPEndpoint query'));
    }

    if (!tcpOk && !udpOk) {
      return {
        ...unavailableNetwork([
          'listening-socket queries failed — network exposure could not be assessed',
          ...notes,
        ]),
        source: 'Get-NetTCPConnection (listen) + Get-NetUDPEndpoint',
      };
    }

    listeningPorts = dedupePorts(listeningPorts);
    if (listeningPorts.length > MAX_PORTS) {
      notes.push(`listening port list truncated to ${MAX_PORTS} of ${listeningPorts.length} sockets`);
      listeningPorts = listeningPorts.slice(0, MAX_PORTS);
    }
    if (listeningPorts.length === 0) {
      notes.push('no listening TCP/UDP sockets were reported by the Windows socket queries');
    }

    // ---------------------------------------------------- established connections
    let establishedCount: number | null = null;
    let establishedSamples: EstablishedSample[] = [];
    const estRes = await runPs('PS_ESTABLISHED', execLog);
    if (estRes.ok) {
      const all = parseEstablished(estRes.stdout);
      establishedCount = all.length;
      establishedSamples = all.slice(0, MAX_SAMPLES);
      if (establishedSamples.length < establishedCount) {
        notes.push(`established connection samples truncated to ${establishedSamples.length} of ${establishedCount}`);
      }
    } else {
      notes.push(failureNote(estRes, 'Get-NetTCPConnection (established) query') + ' — active connection count unknown');
    }

    // ------------------------------------------------------ adapter context only
    const adapterRes = await runPs('PS_NET_ADAPTERS', execLog);
    if (adapterRes.ok) {
      const adapters = parseJsonArray(adapterRes.stdout)
        .map((r) => ({ name: asString(r.Name), status: asString(r.Status), speed: asString(r.LinkSpeed) }))
        .filter((a): a is { name: string; status: string | null; speed: string | null } => a.name !== null);
      const up = adapters.filter((a) => (a.status ?? '').toLowerCase() === 'up');
      notes.push(
        `network adapters: ${adapters.length} total, ${up.length} up (${up
          .slice(0, 8)
          .map((a) => `${a.name}${a.speed ? ` @ ${a.speed}` : ''}`)
          .join(', ')})`,
      );
    } else {
      notes.push(failureNote(adapterRes, 'Get-NetAdapter query') + ' (context only)');
    }

    return {
      available: true,
      source: 'Get-NetTCPConnection (listen/established) + Get-NetUDPEndpoint',
      notes,
      listeningPorts,
      establishedCount,
      establishedSamples,
    };
  } catch (err) {
    return unavailableNetwork([`Collection error: ${err instanceof Error ? err.message : String(err)}`]);
  }
}
