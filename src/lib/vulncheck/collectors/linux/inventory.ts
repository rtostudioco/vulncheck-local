/**
 * VulnCheck Local — Module A: System Inventory collector (Linux)
 * --------------------------------------------------------------
 * Read-only. Sources: Node `os` module, /etc/os-release, /proc/mounts,
 * allowlisted `uname -r`, `df -P`, `dpkg-query -W`.
 * This collector never throws and never guesses: missing data stays null/empty
 * and is reported through module status notes by the orchestrator.
 */

import os from 'os';
import { loggedRun, readFileSafe } from '../../core/platform';
import type { DiskInfo, ExecLogEntry, HostProfile, InterfaceInfo } from '../../core/types';

const MAX_PACKAGES_KEPT = 400;

function osFamilyOf(addrFamily: string | number): 'IPv4' | 'IPv6' | '' {
  if (typeof addrFamily === 'string') {
    const f = addrFamily.toLowerCase();
    return f === 'ipv4' ? 'IPv4' : f === 'ipv6' ? 'IPv6' : '';
  }
  if (addrFamily === 4) return 'IPv4';
  if (addrFamily === 6) return 'IPv6';
  return '';
}

/** Collect interface summary from the Node os module (works on every platform). */
export function collectInterfacesFromOs(): InterfaceInfo[] {
  const result: InterfaceInfo[] = [];
  try {
    const nets = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(nets)) {
      if (!addrs || addrs.length === 0) {
        result.push({ name, ipv4: null, ipv6: null, mac: null, internal: false });
        continue;
      }
      let ipv4: string | null = null;
      let ipv6: string | null = null;
      let mac: string | null = null;
      let internal = false;
      const v6 = addrs.filter((a) => osFamilyOf(a.family) === 'IPv6');
      const v6Preferred = v6.find((a) => !a.address.startsWith('fe80')) ?? v6[0];
      for (const a of addrs) {
        const fam = osFamilyOf(a.family);
        if (!ipv4 && fam === 'IPv4') ipv4 = a.address;
        if (!mac && a.mac && a.mac !== '00:00:00:00:00:00') mac = a.mac;
        if (a.internal) internal = true;
      }
      ipv6 = v6Preferred?.address ?? null;
      result.push({ name, ipv4, ipv6, mac, internal });
    }
  } catch {
    // os.networkInterfaces() can throw in exotic environments — return what we have.
  }
  return result;
}

function primaryIpv4(interfaces: InterfaceInfo[]): string | null {
  for (const iface of interfaces) {
    if (iface.internal) continue;
    if (iface.ipv4) return iface.ipv4;
  }
  return null;
}

/** Minimal inventory from the Node os module only (non-Linux hosts / error fallback). */
export function minimalOsInventory(): HostProfile {
  const interfaces = collectInterfacesFromOs();
  let hostname = 'unknown';
  try {
    hostname = os.hostname() || 'unknown';
  } catch {
    /* keep 'unknown' */
  }
  const totalMemoryMb = Math.round(os.totalmem() / 1048576);
  return {
    hostname,
    platform: os.platform(),
    osName: os.type(),
    osVersion: os.release(),
    osBuild: '',
    kernelVersion: os.release(),
    arch: os.arch(),
    cpuModel: os.cpus()[0]?.model ?? null,
    cpuCores: os.cpus().length || null,
    totalMemoryMb,
    usedMemoryMb: totalMemoryMb - Math.round(os.freemem() / 1048576),
    uptimeHours: Math.round((os.uptime() / 3600) * 10) / 10,
    primaryIp: primaryIpv4(interfaces),
    packageCount: null,
    packages: [],
    disks: [],
    interfaces,
  };
}

interface OsReleaseInfo {
  name: string;
  version: string;
  build: string;
}

function parseOsRelease(text: string): OsReleaseInfo {
  const map = new Map<string, string>();
  for (const line of text.split('\n')) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    map.set(m[1], m[2].replace(/^"(.*)"$/, '$1').trim());
  }
  return {
    name: map.get('NAME') ?? 'Unknown',
    version: map.get('VERSION_ID') ?? map.get('VERSION') ?? 'Unknown',
    build: map.get('BUILD_ID') ?? map.get('VERSION') ?? 'Unknown',
  };
}

/// Decode octal escapes used by /proc/mounts for whitespace characters.
function decodeProcMountPath(p: string): string {
  return p
    .replace(/\\040/g, ' ')
    .replace(/\\011/g, '\t')
    .replace(/\\012/g, '\n')
    .replace(/\\134/g, '\\');
}

async function mountFstypeMap(): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  const text = await readFileSafe('/proc/mounts');
  if (!text) return map;
  for (const line of text.split('\n')) {
    const t = line.split(/\s+/);
    if (t.length < 3) continue;
    map.set(decodeProcMountPath(t[1]), t[2]);
  }
  return map;
}

async function collectDisks(execLog: ExecLogEntry[]): Promise<DiskInfo[]> {
  const disks: DiskInfo[] = [];
  const df = await loggedRun('DF', ['-P', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs'], execLog);
  if (!df.ok) return disks;
  const fstypes = await mountFstypeMap();
  for (const line of df.stdout.split('\n').slice(1)) {
    const t = line.trim().split(/\s+/);
    if (t.length < 6) continue;
    const device = t[0];
    const blocks = Number(t[1]);
    const used = Number(t[2]);
    const usePercent = Number(t[4].replace('%', ''));
    const mount = t.slice(5).join(' ');
    if (!Number.isFinite(blocks) || !Number.isFinite(used) || !Number.isFinite(usePercent)) continue;
    // df -P does not report fs type; enrich from /proc/mounts, else 'unknown'.
    const fstype = fstypes.get(mount) ?? 'unknown';
    // Skip remote/virtual filesystems (FUSE, OSS, NFS, CIFS, procfs...) — they
    // are not local disks and distort capacity reporting.
    if (/^(fuse\.ossfs|nfs.*|cifs|smbfs|proc|sysfs|cgroup.*|devpts|ramfs|autofs|9p)$/.test(fstype)) {
      continue;
    }
    disks.push({
      device,
      fstype,
      sizeMb: Math.round(blocks / 1024), // df -P blocks are 1 KiB
      usedMb: Math.round(used / 1024),
      mount,
      usePercent,
    });
  }
  disks.sort((a, b) => a.mount.localeCompare(b.mount));
  return disks;
}

/** Module A collector. Returns a structurally complete HostProfile; never throws. */
export async function collectInventory(execLog: ExecLogEntry[]): Promise<HostProfile> {
  const base = minimalOsInventory();
  try {
    // OS release identification
    let osName = base.osName === 'Linux' ? 'Unknown' : base.osName;
    let osVersion = base.osVersion;
    let osBuild = '';
    try {
      const release = await readFileSafe('/etc/os-release');
      if (release) {
        const info = parseOsRelease(release);
        osName = info.name;
        osVersion = info.version;
        osBuild = info.build;
      }
    } catch {
      /* os-release unreadable — keep os-module fallbacks */
    }

    // Kernel version
    let kernelVersion = base.kernelVersion;
    try {
      const uname = await loggedRun('UNAME_R', ['-r'], execLog);
      if (uname.ok && uname.stdout.trim()) kernelVersion = uname.stdout.trim();
    } catch {
      /* keep os.release() fallback */
    }

    // Disks
    let disks: DiskInfo[] = [];
    try {
      disks = await collectDisks(execLog);
    } catch {
      /* disk collection failed — leave empty */
    }

    // Installed packages (dpkg systems)
    let packageCount: number | null = null;
    const packages: string[] = [];
    try {
      const dpkg = await loggedRun('DPKG_QUERY', ['-W', '--showformat=${Package}|${Version}\n'], execLog);
      if (dpkg.ok) {
        const all = dpkg.stdout
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l.includes('|'));
        packageCount = all.length;
        for (const entry of all.slice(0, MAX_PACKAGES_KEPT)) packages.push(entry);
      }
    } catch {
      /* dpkg-query failed — packageCount stays null */
    }

    const interfaces = collectInterfacesFromOs();
    return {
      hostname: base.hostname,
      platform: base.platform,
      osName,
      osVersion,
      osBuild,
      kernelVersion,
      arch: base.arch,
      cpuModel: base.cpuModel,
      cpuCores: base.cpuCores,
      totalMemoryMb: base.totalMemoryMb,
      usedMemoryMb: base.usedMemoryMb,
      uptimeHours: base.uptimeHours,
      primaryIp: primaryIpv4(interfaces),
      packageCount,
      packages,
      disks,
      interfaces,
    };
  } catch {
    // Absolute fallback — never throw out of a collector.
    return base;
  }
}
