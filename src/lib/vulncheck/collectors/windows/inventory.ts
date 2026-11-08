/**
 * VulnCheck Local — Module A: System Inventory collector (Windows)
 * -----------------------------------------------------------------
 * Read-only. Sources: Node `os` module (hostname/arch/uptime/interfaces),
 * allowlisted PowerShell queries via Win32 CIM (OS info, computer system,
 * CPU, memory, logical disks) and the uninstall registry keys.
 * This collector never throws and never guesses: missing data stays null/empty
 * and is reported through module status notes by the orchestrator.
 */

import {
  asDateIso,
  asNumber,
  asString,
  failureNote,
  parseJsonArray,
  parseJsonObject,
  runPs,
} from './ps';
import { collectInterfacesFromOs, minimalOsInventory } from '../linux/inventory';
import type { DiskInfo, ExecLogEntry, HostProfile } from '../../core/types';

const MAX_PACKAGES_KEPT = 400;

interface OsInfoParsed {
  caption: string | null;
  version: string | null;
  buildNumber: string | null;
  architecture: string | null;
  lastBoot: string | null;
}

function parseOsInfo(obj: Record<string, unknown> | null): OsInfoParsed {
  if (!obj) return { caption: null, version: null, buildNumber: null, architecture: null, lastBoot: null };
  return {
    caption: asString(obj.Caption),
    version: asString(obj.Version),
    buildNumber: asString(obj.BuildNumber),
    architecture: asString(obj.OSArchitecture),
    lastBoot: asDateIso(obj.LastBootUpTime),
  };
}

async function collectDisks(execLog: ExecLogEntry[], notes: string[]): Promise<DiskInfo[]> {
  const disks: DiskInfo[] = [];
  const res = await runPs('PS_VOLUMES', execLog);
  if (!res.ok) {
    notes.push(failureNote(res, 'Win32_LogicalDisk volume query'));
    return disks;
  }
  for (const row of parseJsonArray(res.stdout)) {
    const device = asString(row.DeviceID); // e.g. 'C:'
    const size = asNumber(row.Size);
    const free = asNumber(row.FreeSpace);
    if (!device || size === null || size <= 0) continue;
    const used = free !== null && free >= 0 ? Math.max(0, size - free) : 0;
    const sizeMb = Math.round(size / 1_048_576);
    const usedMb = Math.round(used / 1_048_576);
    disks.push({
      device,
      fstype: asString(row.FileSystem) ?? 'unknown',
      sizeMb,
      usedMb,
      mount: `${device}\\`,
      usePercent: sizeMb > 0 ? Math.round((usedMb / sizeMb) * 100) : 0,
    });
  }
  disks.sort((a, b) => a.mount.localeCompare(b.mount));
  return disks;
}

/** Module A collector (Windows). Returns a structurally complete HostProfile; never throws. */
export async function collectInventory(execLog: ExecLogEntry[]): Promise<HostProfile> {
  const notes: string[] = [];
  try {
    const base = minimalOsInventory(); // Node os module — works on Windows too

    // OS identification (Win32_OperatingSystem)
    let osInfo: OsInfoParsed = { caption: null, version: null, buildNumber: null, architecture: null, lastBoot: null };
    try {
      const res = await runPs('PS_OS_INFO', execLog);
      if (res.ok) osInfo = parseOsInfo(parseJsonObject(res.stdout));
      else notes.push(failureNote(res, 'Win32_OperatingSystem query'));
    } catch (err) {
      notes.push(`OS info collection error: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Computer system (fallback for memory/logical processors; model noted by orchestrator)
    let csLogicalProcessors: number | null = null;
    let csTotalPhysicalMemoryMb: number | null = null;
    try {
      const res = await runPs('PS_SYSTEM', execLog);
      const cs = res.ok ? parseJsonObject(res.stdout) : null;
      if (cs) {
        csLogicalProcessors = asNumber(cs.NumberOfLogicalProcessors);
        const bytes = asNumber(cs.TotalPhysicalMemory);
        csTotalPhysicalMemoryMb = bytes !== null ? Math.round(bytes / 1_048_576) : null;
      } else if (!res.ok) {
        notes.push(failureNote(res, 'Win32_ComputerSystem query'));
      }
    } catch {
      /* keep os-module fallbacks */
    }

    // CPU
    let cpuModel = base.cpuModel;
    let cpuCores = base.cpuCores;
    try {
      const res = await runPs('PS_CPU', execLog);
      if (res.ok) {
        const cpus = parseJsonArray(res.stdout);
        const first = cpus[0] ?? null;
        const name = first ? asString(first.Name) : null;
        if (name) cpuModel = name;
        const cores = first ? asNumber(first.NumberOfCores) : null;
        const logical = first ? asNumber(first.NumberOfLogicalProcessors) : null;
        const chosen = cores ?? logical ?? csLogicalProcessors;
        if (chosen !== null && chosen > 0) cpuCores = chosen;
      } else if (csLogicalProcessors !== null) {
        cpuCores = csLogicalProcessors;
      } else {
        notes.push(failureNote(res, 'Win32_Processor query'));
      }
    } catch {
      /* keep os-module fallbacks */
    }

    // Memory (Win32_OperatingSystem reports KiB)
    let totalMemoryMb = base.totalMemoryMb;
    let usedMemoryMb = base.usedMemoryMb;
    try {
      const res = await runPs('PS_MEMORY', execLog);
      const mem = res.ok ? parseJsonObject(res.stdout) : null;
      if (mem) {
        const totalKib = asNumber(mem.TotalVisibleMemorySize);
        const freeKib = asNumber(mem.FreePhysicalMemory);
        if (totalKib !== null && totalKib > 0) {
          totalMemoryMb = Math.round(totalKib / 1024);
          usedMemoryMb =
            freeKib !== null && freeKib >= 0 ? Math.max(0, totalMemoryMb - Math.round(freeKib / 1024)) : totalMemoryMb;
        }
      } else if (csTotalPhysicalMemoryMb !== null) {
        totalMemoryMb = csTotalPhysicalMemoryMb;
      } else if (!res.ok) {
        notes.push(failureNote(res, 'memory query'));
      }
    } catch {
      /* keep os-module fallbacks */
    }

    // Disks (fixed local volumes)
    let disks: DiskInfo[] = [];
    try {
      disks = await collectDisks(execLog, notes);
    } catch {
      /* disk collection failed — leave empty */
    }

    // Installed programs from uninstall registry keys ("Name|Version" rows,
    // mirroring the Linux dpkg-query "Package|Version" format)
    let packageCount: number | null = null;
    const packages: string[] = [];
    try {
      const res = await runPs('PS_PACKAGES_COUNT', execLog);
      if (res.ok) {
        const rows = parseJsonArray(res.stdout).filter((r) => asString(r.DisplayName));
        packageCount = rows.length;
        for (const row of rows.slice(0, MAX_PACKAGES_KEPT)) {
          const name = asString(row.DisplayName) ?? '';
          const version = asString(row.DisplayVersion) ?? '';
          packages.push(version ? `${name}|${version}` : name);
        }
        if (rows.length > MAX_PACKAGES_KEPT) {
          notes.push(`installed-program list truncated to ${MAX_PACKAGES_KEPT} of ${rows.length} entries`);
        }
      } else {
        notes.push(failureNote(res, 'uninstall-registry enumeration'));
      }
    } catch {
      /* packageCount stays null */
    }

    const interfaces = collectInterfacesFromOs();
    const lastBoot = osInfo.lastBoot;
    const uptimeHours =
      lastBoot !== null
        ? Math.max(0, Math.round(((Date.now() - Date.parse(lastBoot)) / 3_600_000) * 10) / 10)
        : base.uptimeHours;

    return {
      hostname: base.hostname,
      platform: base.platform,
      osName: osInfo.caption ?? base.osName,
      osVersion: osInfo.version ?? base.osVersion,
      osBuild: osInfo.buildNumber ?? '',
      kernelVersion: osInfo.version ?? null, // NT kernel version (e.g. 10.0.19045)
      arch: osInfo.architecture ? osInfo.architecture.toLowerCase().replace('-bit', 'bit') : base.arch,
      cpuModel,
      cpuCores,
      totalMemoryMb,
      usedMemoryMb,
      uptimeHours,
      primaryIp: base.primaryIp,
      packageCount,
      packages,
      disks,
      interfaces,
    };
  } catch {
    // Absolute fallback — never throw out of a collector.
    return minimalOsInventory();
  }
}
