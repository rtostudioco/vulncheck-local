/**
 * VulnCheck Local — evidence collection orchestrator
 * ---------------------------------------------------
 * Detects the platform, runs the module collectors sequentially (reporting
 * friendly progress), aggregates one shared exec log across all allowlisted
 * commands, and assembles the structurally complete EvidenceBundle.
 *
 * Honesty contract: a collector that fails, lacks privileges or finds nothing
 * is reported as UNAVAILABLE/PARTIAL with explanatory notes — never as secure.
 */

import { detectPlatform } from '../core/platform';
import { MODULES } from '../core/types';
import type {
  EvidenceBundle,
  ExecLogEntry,
  HostProfile,
  ModuleKey,
  ModuleStatus,
  Platform,
} from '../core/types';
import { collectInventory, collectInterfacesFromOs, minimalOsInventory } from './linux/inventory';
import { collectFirewall, unavailableFirewall } from './linux/firewall';
import { collectAccounts, unavailableAccounts } from './linux/users';
import { collectNetwork, unavailableNetwork } from './linux/network';
import { collectUpdates, unavailableUpdates } from './linux/updates';
import { collectEndpoint, unavailableEndpoint } from './linux/endpoint';
import { collectServices, unavailableServices } from './linux/services';
import { collectBackup, unavailableBackup } from './linux/backup';
import { collectInventory as winCollectInventory } from './windows/inventory';
import { collectFirewall as winCollectFirewall } from './windows/firewall';
import { collectAccounts as winCollectAccounts } from './windows/users';
import { collectNetwork as winCollectNetwork } from './windows/network';
import { collectUpdates as winCollectUpdates } from './windows/updates';
import { collectEndpoint as winCollectEndpoint } from './windows/endpoint';
import { collectServices as winCollectServices } from './windows/services';
import { collectBackup as winCollectBackup } from './windows/backup';

export type ProgressCallback = (step: string, percent: number) => Promise<void> | void;

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function moduleName(key: ModuleKey): string {
  return MODULES.find((m) => m.key === key)?.name ?? key;
}

function moduleStatus(
  key: ModuleKey,
  state: ModuleStatus['state'],
  source: string,
  notes: string[],
): ModuleStatus {
  return { moduleKey: key, name: moduleName(key), state, source, notes: [...notes] };
}

/// Structurally complete bundle for unsupported hosts (platforms the engine
/// does not collect on at all).
function buildNonLinuxBundle(platform: Platform, execLog: ExecLogEntry[]): EvidenceBundle {
  const notes = [
    'This build audits Linux and Windows hosts; the detected platform is not supported by this engine build.',
    `Detected platform '${process.platform}'.`,
  ];
  const inventory = minimalOsInventory();

  const modules: ModuleStatus[] = MODULES.map((m) =>
    m.key === 'inventory'
      ? moduleStatus('inventory', 'PARTIAL', 'os module (non-Linux host)', [
          'Non-Linux host: os-module basics only — disks, packages and platform-specific inventory unavailable.',
          ...notes,
        ])
      : moduleStatus(m.key, 'UNAVAILABLE', 'n/a', notes),
  );

  return {
    platform,
    collectedAt: new Date().toISOString(),
    inventory,
    firewall: unavailableFirewall(notes),
    accounts: unavailableAccounts(notes),
    network: unavailableNetwork(notes),
    updates: unavailableUpdates(notes),
    endpoint: unavailableEndpoint(notes),
    services: unavailableServices(notes),
    backup: unavailableBackup(notes),
    modules,
    execLog,
  };
}

/** Collect the full evidence bundle on a Windows host (read-only PowerShell). Never throws. */
async function collectWindowsBundle(step: (label: string, percent: number) => Promise<void>): Promise<EvidenceBundle> {
  const execLog: ExecLogEntry[] = [];
  const modules: ModuleStatus[] = [];

  // -------------------------------------------------------------- Module A
  await step('Collecting system inventory', 15);
  let inventory: HostProfile;
  try {
    inventory = await winCollectInventory(execLog);
    const notes: string[] = [];
    if (inventory.osBuild === '') {
      notes.push('Win32_OperatingSystem query did not yield a build number — OS identification limited');
    }
    if (inventory.packageCount === null) {
      notes.push('uninstall-registry enumeration unavailable — installed-program inventory incomplete');
    } else if (inventory.packages.length < inventory.packageCount) {
      notes.push(`Installed-program list truncated (${inventory.packages.length} of ${inventory.packageCount} entries)`);
    }
    if (inventory.disks.length === 0) {
      notes.push('no fixed local disk volumes were reported — disk inventory empty');
    }
    const state: ModuleStatus['state'] =
      inventory.osBuild === '' || inventory.packageCount === null || inventory.disks.length === 0
        ? 'PARTIAL'
        : 'OK';
    modules.push(
      moduleStatus(
        'inventory',
        state,
        'Win32_OperatingSystem/ComputerSystem/Processor/LogicalDisk + uninstall registry + os module',
        notes,
      ),
    );
  } catch (err) {
    inventory = minimalOsInventory();
    modules.push(
      moduleStatus('inventory', 'ERROR', 'Win32_OperatingSystem/ComputerSystem/Processor/LogicalDisk + uninstall registry + os module', [
        `Collection error: ${errMessage(err)}`,
      ]),
    );
  }

  // -------------------------------------------------------------- Module B
  await step('Auditing firewall configuration', 25);
  let firewall;
  try {
    firewall = await winCollectFirewall(execLog);
    const hardeningOk = firewall.windowsHardening?.available === true;
    const state: ModuleStatus['state'] = firewall.available
      ? firewall.active === null || !hardeningOk
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus('firewall', state, 'Get-NetFirewallProfile + registry reads (RDP/UAC/SMB1)', firewall.notes),
    );
  } catch (err) {
    firewall = unavailableFirewall([`Collection error: ${errMessage(err)}`]);
    modules.push(moduleStatus('firewall', 'ERROR', 'Get-NetFirewallProfile + registry reads (RDP/UAC/SMB1)', firewall.notes));
  }

  // -------------------------------------------------------------- Module C
  await step('Auditing user accounts', 33);
  let accounts;
  try {
    accounts = await winCollectAccounts(execLog);
    const state: ModuleStatus['state'] = accounts.available
      ? accounts.passwordPolicy.maxDays === null || Object.keys(accounts.adminGroups).length === 0
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus(
        'accounts',
        state,
        'Get-LocalUser + Get-LocalGroupMember (S-1-5-32-544) + net accounts',
        accounts.notes,
      ),
    );
  } catch (err) {
    accounts = unavailableAccounts([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus('accounts', 'ERROR', 'Get-LocalUser + Get-LocalGroupMember (S-1-5-32-544) + net accounts', accounts.notes),
    );
  }

  // -------------------------------------------------------------- Module D
  await step('Analyzing network exposure', 42);
  let network;
  try {
    network = await winCollectNetwork(execLog);
    const state: ModuleStatus['state'] = network.available
      ? network.establishedCount === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus('network', state, 'Get-NetTCPConnection (listen/established) + Get-NetUDPEndpoint', network.notes),
    );
  } catch (err) {
    network = unavailableNetwork([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus('network', 'ERROR', 'Get-NetTCPConnection (listen/established) + Get-NetUDPEndpoint', network.notes),
    );
  }

  // -------------------------------------------------------------- Module E
  await step('Checking system updates', 50);
  let updates;
  try {
    updates = await winCollectUpdates(execLog);
    const hasGaps =
      updates.pendingUpdates === null ||
      updates.rebootRequired === null ||
      updates.autoUpdatesEnabled === null;
    const state: ModuleStatus['state'] = updates.available ? (hasGaps ? 'PARTIAL' : 'OK') : 'UNAVAILABLE';
    modules.push(
      moduleStatus(
        'updates',
        state,
        'Microsoft.Update.Session COM search + reboot/NoAutoUpdate registry markers',
        updates.notes,
      ),
    );
  } catch (err) {
    updates = unavailableUpdates([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus('updates', 'ERROR', 'Microsoft.Update.Session COM search + reboot/NoAutoUpdate registry markers', updates.notes),
    );
  }

  // -------------------------------------------------------------- Module F
  await step('Checking endpoint protection', 58);
  let endpoint;
  try {
    endpoint = await winCollectEndpoint(execLog);
    const state: ModuleStatus['state'] = endpoint.available
      ? endpoint.daemonRunning === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus('endpoint', state, 'Get-MpComputerStatus + Get-MpPreference + Get-BitLockerVolume', endpoint.notes),
    );
  } catch (err) {
    endpoint = unavailableEndpoint([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus('endpoint', 'ERROR', 'Get-MpComputerStatus + Get-MpPreference + Get-BitLockerVolume', endpoint.notes),
    );
  }

  // -------------------------------------------------------------- Module G
  await step('Auditing running services', 66);
  let services;
  try {
    services = await winCollectServices(execLog);
    const state: ModuleStatus['state'] = services.available ? 'OK' : 'UNAVAILABLE';
    modules.push(moduleStatus('services', state, 'Get-CimInstance Win32_Service', services.notes));
  } catch (err) {
    services = unavailableServices([`Collection error: ${errMessage(err)}`]);
    modules.push(moduleStatus('services', 'ERROR', 'Get-CimInstance Win32_Service', services.notes));
  }

  // -------------------------------------------------------------- Module H
  await step('Auditing backup configuration', 72);
  let backup;
  try {
    backup = await winCollectBackup(execLog);
    const state: ModuleStatus['state'] = backup.available
      ? backup.lastBackupDate === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(moduleStatus('backup', state, 'wbadmin get versions + root\\default SystemRestore', backup.notes));
  } catch (err) {
    backup = unavailableBackup([`Collection error: ${errMessage(err)}`]);
    modules.push(moduleStatus('backup', 'ERROR', 'wbadmin get versions + root\\default SystemRestore', backup.notes));
  }

  if (inventory.interfaces.length === 0) {
    inventory.interfaces = collectInterfacesFromOs();
  }

  return {
    platform: 'windows',
    collectedAt: new Date().toISOString(),
    inventory,
    firewall,
    accounts,
    network,
    updates,
    endpoint,
    services,
    backup,
    modules,
    execLog,
  };
}

/** Collect the full evidence bundle. Never throws. */
export async function collectEvidence(onProgress?: ProgressCallback): Promise<EvidenceBundle> {
  const step = async (label: string, percent: number): Promise<void> => {
    if (onProgress) await onProgress(label, percent);
  };

  const execLog: ExecLogEntry[] = [];
  let platform: Platform = 'unsupported';
  try {
    platform = detectPlatform();
  } catch {
    platform = 'unsupported';
  }
  await step('Detecting platform', 5);

  if (platform === 'unsupported') {
    return buildNonLinuxBundle(platform, execLog);
  }

  if (platform === 'windows') {
    return collectWindowsBundle(step);
  }

  // -------------------------------------------------------------- Module A (Linux)
  await step('Collecting system inventory', 15);
  const modules: ModuleStatus[] = [];
  let inventory: HostProfile;
  try {
    inventory = await collectInventory(execLog);
    const notes: string[] = [];
    if (inventory.packageCount === null) {
      notes.push('dpkg-query unavailable — installed package inventory incomplete');
    } else if (inventory.packages.length < inventory.packageCount) {
      notes.push(`Package list truncated (${inventory.packages.length} of ${inventory.packageCount} entries)`);
    }
    if (inventory.disks.length === 0) {
      notes.push('df produced no usable disk rows — disk inventory empty');
    }
    const state: ModuleStatus['state'] =
      inventory.packageCount === null || inventory.disks.length === 0 ? 'PARTIAL' : 'OK';
    modules.push(moduleStatus('inventory', state, 'os module + /etc/os-release + df -P + dpkg-query', notes));
  } catch (err) {
    inventory = minimalOsInventory();
    modules.push(
      moduleStatus('inventory', 'ERROR', 'os module + /etc/os-release + df -P + dpkg-query', [
        `Collection error: ${errMessage(err)}`,
      ]),
    );
  }

  // -------------------------------------------------------------- Module B
  await step('Auditing firewall configuration', 25);
  let firewall;
  try {
    firewall = await collectFirewall(execLog);
    const state: ModuleStatus['state'] = firewall.available
      ? firewall.active === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus('firewall', state, 'which probe + /etc/ufw/*.conf + ufw status', firewall.notes),
    );
  } catch (err) {
    firewall = unavailableFirewall([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus('firewall', 'ERROR', 'which probe + /etc/ufw/*.conf + ufw status', firewall.notes),
    );
  }

  // -------------------------------------------------------------- Module C
  await step('Auditing user accounts', 33);
  let accounts;
  try {
    accounts = await collectAccounts(execLog);
    const state: ModuleStatus['state'] = accounts.available
      ? !accounts.shadowReadable || !accounts.ssh.available || accounts.passwordPolicy.maxDays === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus(
        'accounts',
        state,
        '/etc/passwd + /etc/group + /etc/shadow + /etc/login.defs + sshd_config',
        accounts.notes,
      ),
    );
  } catch (err) {
    accounts = unavailableAccounts([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus(
        'accounts',
        'ERROR',
        '/etc/passwd + /etc/group + /etc/shadow + /etc/login.defs + sshd_config',
        accounts.notes,
      ),
    );
  }

  // -------------------------------------------------------------- Module D
  await step('Analyzing network exposure', 42);
  let network;
  try {
    network = await collectNetwork(execLog);
    const state: ModuleStatus['state'] = network.available
      ? network.establishedCount === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus('network', state, 'ss -tuln + ss -tn (established)', network.notes),
    );
  } catch (err) {
    network = unavailableNetwork([`Collection error: ${errMessage(err)}`]);
    modules.push(moduleStatus('network', 'ERROR', 'ss -tuln + ss -tn (established)', network.notes));
  }

  // -------------------------------------------------------------- Module E
  await step('Checking system updates', 50);
  let updates;
  try {
    updates = await collectUpdates(execLog);
    const hasGaps =
      updates.pendingUpdates === null ||
      updates.pendingSecurityUpdates === null ||
      updates.autoUpdatesEnabled === null;
    const state: ModuleStatus['state'] = updates.available ? (hasGaps ? 'PARTIAL' : 'OK') : 'UNAVAILABLE';
    modules.push(
      moduleStatus(
        'updates',
        state,
        'apt list --upgradable + apt-get --simulate dist-upgrade + /var/run/reboot-required',
        updates.notes,
      ),
    );
  } catch (err) {
    updates = unavailableUpdates([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus(
        'updates',
        'ERROR',
        'apt list --upgradable + apt-get --simulate dist-upgrade + /var/run/reboot-required',
        updates.notes,
      ),
    );
  }

  // -------------------------------------------------------------- Module F
  await step('Checking endpoint protection', 58);
  let endpoint;
  try {
    endpoint = await collectEndpoint(execLog);
    const state: ModuleStatus['state'] = endpoint.available
      ? endpoint.daemonRunning === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus('endpoint', state, 'which probe + systemctl is-active + /var/lib/clamav', endpoint.notes),
    );
  } catch (err) {
    endpoint = unavailableEndpoint([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus('endpoint', 'ERROR', 'which probe + systemctl is-active + /var/lib/clamav', endpoint.notes),
    );
  }

  // -------------------------------------------------------------- Module G
  await step('Auditing running services', 66);
  let services;
  try {
    services = await collectServices(execLog);
    const state: ModuleStatus['state'] = services.available
      ? services.systemdAvailable
        ? 'OK'
        : 'PARTIAL'
      : 'UNAVAILABLE';
    modules.push(moduleStatus('services', state, 'systemctl list-units + ps -eo comm', services.notes));
  } catch (err) {
    services = unavailableServices([`Collection error: ${errMessage(err)}`]);
    modules.push(moduleStatus('services', 'ERROR', 'systemctl list-units + ps -eo comm', services.notes));
  }

  // -------------------------------------------------------------- Module H
  await step('Auditing backup configuration', 72);
  let backup;
  try {
    backup = await collectBackup(execLog);
    const state: ModuleStatus['state'] = backup.available
      ? backup.lastBackupDate === null
        ? 'PARTIAL'
        : 'OK'
      : 'UNAVAILABLE';
    modules.push(
      moduleStatus('backup', state, 'which probe + /etc/cron* + snapshot directories', backup.notes),
    );
  } catch (err) {
    backup = unavailableBackup([`Collection error: ${errMessage(err)}`]);
    modules.push(
      moduleStatus('backup', 'ERROR', 'which probe + /etc/cron* + snapshot directories', backup.notes),
    );
  }

  // interfaces were already gathered by the inventory collector; keep the
  // bundle's interface list consistent even on the (unlikely) error fallback.
  if (inventory.interfaces.length === 0) {
    inventory.interfaces = collectInterfacesFromOs();
  }

  return {
    platform,
    collectedAt: new Date().toISOString(),
    inventory,
    firewall,
    accounts,
    network,
    updates,
    endpoint,
    services,
    backup,
    modules,
    execLog,
  };
}
