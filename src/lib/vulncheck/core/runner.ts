/**
 * VulnCheck Local — strict command allowlist runner (spec §7)
 * -----------------------------------------------------------
 * SECURITY INVARIANTS:
 *  - Only command IDs registered here may be executed.
 *  - Only argument sets registered here may be passed (exact match).
 *  - No shell is spawned (execFile, shell: false). No string interpolation.
 *  - Every invocation is time-limited and output-size-limited.
 *  - Every command in this registry is a READ-ONLY inspection query.
 *  - A sanitized environment is provided; no secrets are passed.
 */

import { execFile } from 'child_process';
import type { ExecLogEntry } from './types';

export type CommandId =
  | 'UFW_STATUS'
  | 'SUDO_UFW_STATUS'
  | 'FIREWALL_STATE'
  | 'NFT_LIST'
  | 'IPTABLES_LIST'
  | 'SS_LISTEN'
  | 'SS_ESTABLISHED'
  | 'SYSTEMCTL_UNITS'
  | 'SYSTEMCTL_IS_ACTIVE'
  | 'DPKG_QUERY'
  | 'APT_UPGRADABLE'
  | 'APT_SIMULATE'
  | 'WHICH'
  | 'DF'
  | 'PS_COMM'
  | 'UNAME_R';

interface CommandSpec {
  file: string;
  argSets: string[][];
  timeoutMs: number;
  description: string;
}

/// Every entry must be a read-only query. Keep this list minimal and auditable.
const REGISTRY: Record<CommandId, CommandSpec> = {
  UFW_STATUS: {
    file: '/usr/sbin/ufw',
    argSets: [['status', 'verbose']],
    timeoutMs: 4000,
    description: 'Read UFW firewall status (read-only)',
  },
  SUDO_UFW_STATUS: {
    file: '/usr/bin/sudo',
    argSets: [['-n', 'ufw', 'status', 'verbose']],
    timeoutMs: 5000,
    description: 'Read UFW status via non-interactive sudo (read-only)',
  },
  FIREWALL_STATE: {
    file: '/usr/bin/firewall-cmd',
    argSets: [['--state'], ['--get-active-zones']],
    timeoutMs: 4000,
    description: 'Read firewalld state (read-only)',
  },
  NFT_LIST: {
    file: '/usr/sbin/nft',
    argSets: [['list', 'ruleset']],
    timeoutMs: 4000,
    description: 'List nftables ruleset (read-only)',
  },
  IPTABLES_LIST: {
    file: '/usr/sbin/iptables',
    argSets: [['-L', '-n']],
    timeoutMs: 4000,
    description: 'List iptables rules (read-only)',
  },
  SS_LISTEN: {
    file: '/usr/bin/ss',
    argSets: [['-Htuln']],
    timeoutMs: 4000,
    description: 'List listening TCP/UDP sockets (read-only)',
  },
  SS_ESTABLISHED: {
    file: '/usr/bin/ss',
    argSets: [['-Htn', 'state', 'established']],
    timeoutMs: 4000,
    description: 'List established TCP connections (read-only)',
  },
  SYSTEMCTL_UNITS: {
    file: '/usr/bin/systemctl',
    argSets: [['list-units', '--type=service', '--state=running', '--no-pager', '--no-legend']],
    timeoutMs: 5000,
    description: 'List running systemd services (read-only)',
  },
  SYSTEMCTL_IS_ACTIVE: {
    file: '/usr/bin/systemctl',
    argSets: [
      ['is-active', 'clamav-daemon'],
      ['is-active', 'clamav-freshclam'],
      ['is-active', 'sshd'],
      ['is-active', 'ssh'],
      ['is-active', 'ufw'],
      ['is-active', 'firewalld'],
    ],
    timeoutMs: 4000,
    description: 'Check specific unit active state (read-only)',
  },
  DPKG_QUERY: {
    file: '/usr/bin/dpkg-query',
    argSets: [['-W', '--showformat=${Package}|${Version}\n']],
    timeoutMs: 8000,
    description: 'List installed packages (read-only)',
  },
  APT_UPGRADABLE: {
    file: '/usr/bin/apt',
    argSets: [['list', '--upgradable']],
    timeoutMs: 15000,
    description: 'List upgradable packages (read-only)',
  },
  APT_SIMULATE: {
    file: '/usr/bin/apt-get',
    argSets: [['--simulate', 'dist-upgrade']],
    timeoutMs: 20000,
    description: 'Simulate dist-upgrade to enumerate pending changes (no changes performed)',
  },
  WHICH: {
    file: '/usr/bin/which',
    argSets: [
      ['clamscan'],
      ['clamdscan'],
      ['freshclam'],
      ['timeshift'],
      ['rsnapshot'],
      ['restic'],
      ['borg'],
      ['borgmatic'],
      ['duplicity'],
      ['deja-dup'],
      ['bacula'],
      ['kopia'],
      ['firewall-cmd'],
      ['ufw'],
      ['iptables'],
      ['nft'],
      ['systemctl'],
    ],
    timeoutMs: 3000,
    description: 'Detect presence of specific security/backup binaries (read-only)',
  },
  DF: {
    file: '/usr/bin/df',
    argSets: [['-P', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs']],
    timeoutMs: 4000,
    description: 'Report filesystem disk usage (read-only)',
  },
  PS_COMM: {
    file: '/usr/bin/ps',
    argSets: [['-eo', 'comm', '--no-headers']],
    timeoutMs: 4000,
    description: 'List running process names (read-only)',
  },
  UNAME_R: {
    file: '/usr/bin/uname',
    argSets: [['-r']],
    timeoutMs: 3000,
    description: 'Read kernel release (read-only)',
  },
};

export type CmdError = 'NOT_FOUND' | 'TIMEOUT' | 'PERMISSION' | 'ALLOWLIST_DENIED' | 'OTHER';

export interface CmdResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  code: number | null;
  error?: CmdError;
  ms: number;
  command: string;
}

const SANITIZED_ENV: NodeJS.ProcessEnv = {
  PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  LANG: 'C',
  LC_ALL: 'C',
  NODE_ENV: (process.env.NODE_ENV ?? 'development') as 'development' | 'production' | 'test',
};

const MAX_BUFFER_BYTES = 4 * 1024 * 1024;

/**
 * Execute an allowlisted read-only command. `args` must exactly match one of
 * the registered argument sets for the given command id.
 */
export function runCommand(id: CommandId, args: string[] = []): Promise<CmdResult> {
  return new Promise<CmdResult>((resolve) => {
    const spec = REGISTRY[id];
    const started = Date.now();

    const deny = (error: CmdError, stderr = ''): CmdResult => ({
      ok: false,
      stdout: '',
      stderr,
      code: null,
      error,
      ms: Date.now() - started,
      command: `${spec?.file ?? id} ${args.join(' ')}`.trim(),
    });

    if (!spec) return resolve(deny('ALLOWLIST_DENIED', `Unknown command id: ${id}`));

    const match = spec.argSets.some(
      (set) => set.length === args.length && set.every((a, i) => a === args[i]),
    );
    if (!match) {
      return resolve(deny('ALLOWLIST_DENIED', `Argument set not allowlisted for ${id}`));
    }

    execFile(
      spec.file,
      args,
      {
        timeout: spec.timeoutMs,
        killSignal: 'SIGKILL',
        maxBuffer: MAX_BUFFER_BYTES,
        env: { ...SANITIZED_ENV },
        cwd: '/',
        shell: false,
        windowsHide: true,
      },
      (err, stdout, stderr) => {
        const ms = Date.now() - started;
        const command = `${spec.file} ${args.join(' ')}`;
        if (!err) {
          return resolve({ ok: true, stdout: stdout.toString(), stderr: stderr.toString(), code: 0, ms, command });
        }
        const e = err as NodeJS.ErrnoException & { code?: string | number; killed?: boolean };
        let error: CmdError = 'OTHER';
        if (e.code === 'ENOENT') error = 'NOT_FOUND';
        else if (e.killed) error = 'TIMEOUT';
        else if (e.code === 'EACCES' || String(stderr).includes('Permission denied')) error = 'PERMISSION';
        return resolve({
          ok: false,
          stdout: stdout.toString(),
          stderr: stderr.toString(),
          code: typeof e.code === 'number' ? e.code : null,
          error,
          ms,
          command,
        });
      },
    );
  });
}

/// Collect an ExecLogEntry for the audit evidence trail
export function toExecLog(result: CmdResult): ExecLogEntry {
  return { command: result.command, ok: result.ok, ms: result.ms };
}

/// Convenience: probe one binary with `which`. Returns path or null.
export async function whichBinary(binary: string): Promise<string | null> {
  const allowed = REGISTRY.WHICH.argSets.some((s) => s[0] === binary);
  if (!allowed) return null;
  const res = await runCommand('WHICH', [binary]);
  if (!res.ok) return null;
  const path = res.stdout.trim().split('\n')[0]?.trim();
  return path && path.length > 0 && path.startsWith('/') ? path : null;
}

// ---------------------------------------------------------------------------
// PowerShell registry (Windows hosts) — ADDITIVE to the Linux registry above.
// ---------------------------------------------------------------------------
// SECURITY INVARIANTS (same as the Linux registry, spec §7):
//  - Only the command IDs registered here may be executed, and each executes
//    EXACTLY the static script registered for it (no user input, no
//    interpolation, no argument sets, no shell).
//  - Execution uses execFile('powershell.exe', ...) with shell: false and
//    windowsHide: true. Every invocation is time-limited (per-entry
//    timeoutMs) and output-size-limited (maxBuffer 4 MB).
//  - A sanitized environment is provided; no secrets are passed.
//  - Every script is a pure READ-ONLY inspection: Get-*/Test-Path/net
//    accounts/wbadmin get/registry reads, `-ErrorAction SilentlyContinue`
//    plus try/catch, and JSON output via ConvertTo-Json. No Set-*/New-*/
//    Remove-*/Start-*/Stop-*/Enable-*/Disable-* cmdlets. The single exception
//    required by the spec is PS_UPDATES_PENDING, which creates an in-process
//    read-only COM session (Microsoft.Update.Session) to SEARCH for pending
//    updates — it queries Windows Update and changes nothing. The COM
//    instance is created via Activator::CreateInstance (no New-* cmdlet).
//  - On non-Windows hosts runPowerShellCommand returns a graceful failure
//    WITHOUT spawning any process.
// ---------------------------------------------------------------------------

export type PsCommandId =
  | 'PS_OS_INFO'
  | 'PS_SYSTEM'
  | 'PS_CPU'
  | 'PS_MEMORY'
  | 'PS_VOLUMES'
  | 'PS_NET_ADAPTERS'
  | 'PS_LISTEN_TCP'
  | 'PS_LISTEN_UDP'
  | 'PS_ESTABLISHED'
  | 'PS_FW_PROFILES'
  | 'PS_LOCAL_USERS'
  | 'PS_PASSWORD_POLICY'
  | 'PS_ADMINS'
  | 'PS_RDP'
  | 'PS_SMB1'
  | 'PS_UAC'
  | 'PS_SERVICES'
  | 'PS_DEFENDER_STATUS'
  | 'PS_DEFENDER_PREFS'
  | 'PS_UPDATES_PENDING'
  | 'PS_PENDING_REBOOT'
  | 'PS_BACKUP_VERSIONS'
  | 'PS_PACKAGES_COUNT'
  | 'PS_BITLOCKER';

interface PsCommandSpec {
  /// Static, fully self-contained read-only PowerShell script. Never built
  /// from user input; the registry below is the complete allowlist.
  script: string;
  description: string;
  timeoutMs: number;
}

const PS_REGISTRY: Record<PsCommandId, PsCommandSpec> = {
  PS_OS_INFO: {
    script: `Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,TotalVisibleMemorySize | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read OS caption, version, build, architecture, last boot, RAM (read-only)',
    timeoutMs: 10000,
  },
  PS_SYSTEM: {
    script: `Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object Manufacturer,Model,Domain,TotalPhysicalMemory,NumberOfLogicalProcessors | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read computer system manufacturer/model/domain/memory (read-only)',
    timeoutMs: 10000,
  },
  PS_CPU: {
    script: `@(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed) | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read CPU model and core counts (read-only)',
    timeoutMs: 10000,
  },
  PS_MEMORY: {
    script: `Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read total/free physical memory in KiB (read-only)',
    timeoutMs: 10000,
  },
  PS_VOLUMES: {
    script: `@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace) | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read fixed local disk volumes and usage (read-only)',
    timeoutMs: 10000,
  },
  PS_NET_ADAPTERS: {
    script: `@(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed) | ConvertTo-Json -Compress -Depth 4`,
    description: 'List network adapters and link state (read-only)',
    timeoutMs: 10000,
  },
  PS_LISTEN_TCP: {
    script: `@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess) | ConvertTo-Json -Compress -Depth 4`,
    description: 'List listening TCP sockets (read-only)',
    timeoutMs: 10000,
  },
  PS_LISTEN_UDP: {
    script: `@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess) | ConvertTo-Json -Compress -Depth 4`,
    description: 'List UDP endpoints (read-only)',
    timeoutMs: 10000,
  },
  PS_ESTABLISHED: {
    script: `@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess) | ConvertTo-Json -Compress -Depth 4`,
    description: 'List established TCP connections (read-only)',
    timeoutMs: 10000,
  },
  PS_FW_PROFILES: {
    script: `@(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules) | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read Defender Firewall Domain/Private/Public profiles (read-only)',
    timeoutMs: 10000,
  },
  PS_LOCAL_USERS: {
    script: `@(Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,SID,LastLogon,PasswordExpires,PasswordLastSet,PasswordRequired) | ConvertTo-Json -Compress -Depth 4`,
    description: 'List local account metadata — names/SIDs only, never credentials (read-only)',
    timeoutMs: 10000,
  },
  PS_PASSWORD_POLICY: {
    script: `net accounts`,
    description: 'Read local password/lockout policy via net accounts (read-only)',
    timeoutMs: 8000,
  },
  PS_ADMINS: {
    script: `@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass,PrincipalSource) | ConvertTo-Json -Compress -Depth 4`,
    description: 'List members of the Administrators group by well-known SID (read-only)',
    timeoutMs: 10000,
  },
  PS_RDP: {
    script: [
      '$r = [ordered]@{ fDenyTSConnections = $null; userAuthentication = $null }',
      `try { $r.fDenyTSConnections = [int](Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections } catch {}`,
      `try { $r.userAuthentication = [int](Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop).UserAuthentication } catch {}`,
      '$r | ConvertTo-Json -Compress -Depth 4',
    ].join('\n'),
    description: 'Read Remote Desktop enablement + NLA registry values (read-only)',
    timeoutMs: 10000,
  },
  PS_SMB1: {
    script: [
      '$r = [ordered]@{ serverSmb1 = $null; featureState = $null; source = $null }',
      'try { $c = Get-SmbServerConfiguration -ErrorAction Stop; $r.serverSmb1 = [int][bool]$c.EnableSMB1Protocol; $r.source = \'Get-SmbServerConfiguration\' } catch {}',
      `if ($null -eq $r.serverSmb1) { try { $v = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -ErrorAction Stop; $r.serverSmb1 = [int]$v.SMB1; $r.source = 'registry:LanmanServer\\Parameters\\SMB1' } catch {} }`,
      'try { $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop; $r.featureState = [string]$f.State } catch {}',
      '$r | ConvertTo-Json -Compress -Depth 4',
    ].join('\n'),
    description: 'Read SMBv1 server configuration / optional-feature state (read-only)',
    timeoutMs: 15000,
  },
  PS_UAC: {
    script: `Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read User Account Control registry policy values (read-only)',
    timeoutMs: 10000,
  },
  PS_SERVICES: {
    script: `@(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,State,StartMode,StartName,ProcessId) | ConvertTo-Json -Compress -Depth 4`,
    description: 'List services with state/start mode/running account (read-only)',
    timeoutMs: 20000,
  },
  PS_DEFENDER_STATUS: {
    script: `Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMRunningMode,AntivirusEnabled,AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,QuickScanEndTime | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read Microsoft Defender Antivirus status (read-only)',
    timeoutMs: 15000,
  },
  PS_DEFENDER_PREFS: {
    script: `Get-MpPreference -ErrorAction SilentlyContinue | Select-Object DisableRealtimeMonitoring,PUAProtection,MAPSReporting,SubmitSamplesConsent | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read Microsoft Defender preference flags (read-only)',
    timeoutMs: 15000,
  },
  PS_UPDATES_PENDING: {
    script: [
      '# Read-only search for pending Windows Updates (no download/install).',
      '# COM session is created via Activator to avoid mutation cmdlets entirely.',
      '$out = @()',
      'try {',
      "  $session = [Activator]::CreateInstance([Type]::GetTypeFromProgID('Microsoft.Update.Session'))",
      '  $searcher = $session.CreateUpdateSearcher()',
      "  $result = $searcher.Search('IsInstalled=0')",
      '  foreach ($u in $result.Updates) {',
      '    $out += [pscustomobject]@{ Title = $u.Title; Severity = $u.MsrcSeverity; IsDownloaded = [bool]$u.IsDownloaded }',
      '  }',
      '  @($out) | ConvertTo-Json -Compress -Depth 4',
      '} catch {',
      '  [pscustomobject]@{ searchError = $_.Exception.Message } | ConvertTo-Json -Compress -Depth 4',
      '}',
    ].join('\n'),
    description: 'Search Windows Update for pending updates via read-only COM session (30s cap)',
    timeoutMs: 30000,
  },
  PS_PENDING_REBOOT: {
    script: [
      '$r = [ordered]@{ wuRebootPending = $false; cbsRebootPending = $false; pendingFileRename = $false; noAutoUpdate = $null }',
      `try { $r.wuRebootPending = [bool](Test-Path -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') } catch {}`,
      `try { $r.cbsRebootPending = [bool](Test-Path -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') } catch {}`,
      `try { $v = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue; $r.pendingFileRename = [bool]($v -and @($v.PendingFileRenameOperations).Count -gt 0) } catch {}`,
      `try { $p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue; if ($p -and $null -ne $p.NoAutoUpdate) { $r.noAutoUpdate = [int]$p.NoAutoUpdate } } catch {}`,
      '$r | ConvertTo-Json -Compress -Depth 4',
    ].join('\n'),
    description: 'Read pending-reboot markers and NoAutoUpdate policy (read-only)',
    timeoutMs: 10000,
  },
  PS_BACKUP_VERSIONS: {
    script: [
      '$r = [ordered]@{ wbadminOutput = $null; wbadminError = $null; restorePoints = @() }',
      'try { $r.wbadminOutput = (wbadmin get versions -quiet 2>&1 | Out-String) } catch { $r.wbadminError = $_.Exception.Message }',
      "try { $r.restorePoints = @(Get-CimInstance -Namespace 'root\\default' -ClassName 'SystemRestore' -ErrorAction Stop | Select-Object SequenceNumber,Description,CreationTime,RestorePointType) } catch { $r.restorePoints = @() }",
      '$r | ConvertTo-Json -Compress -Depth 4',
    ].join('\n'),
    description: 'List wbadmin backup versions + System Restore points (read-only)',
    timeoutMs: 20000,
  },
  PS_PACKAGES_COUNT: {
    script: `@(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion) | ConvertTo-Json -Compress -Depth 4`,
    description: 'Enumerate installed programs from uninstall registry keys (read-only)',
    timeoutMs: 20000,
  },
  PS_BITLOCKER: {
    script: `@(Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage) | ConvertTo-Json -Compress -Depth 4`,
    description: 'Read BitLocker volume protection status (read-only; may require elevation)',
    timeoutMs: 15000,
  },
};

/// Stable, ordered list of every registered PowerShell command (audit aid).
export const PS_COMMAND_IDS: PsCommandId[] = Object.keys(PS_REGISTRY) as PsCommandId[];

const PS_EXEC_FILE = 'powershell.exe';
const PS_EXEC_ARGS = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command'];

/// Minimal sanitized environment for PowerShell on Windows. SystemRoot is
/// required by PowerShell; nothing else (and no secrets) is forwarded.
const PS_SANITIZED_ENV: NodeJS.ProcessEnv = {
  SystemRoot: process.env.SystemRoot ?? 'C:\\Windows',
  windir: process.env.windir ?? 'C:\\Windows',
  PATH: 'C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
  PATHEXT: '.COM;.EXE;.BAT;.CMD',
  COMSPEC: 'C:\\Windows\\System32\\cmd.exe',
  TEMP: 'C:\\Windows\\Temp',
  TMP: 'C:\\Windows\\Temp',
  NODE_ENV: (process.env.NODE_ENV ?? 'development') as 'development' | 'production' | 'test',
};

/**
 * Execute an allowlisted, STATIC, read-only PowerShell script by its registry
 * id and append an ExecLogEntry to the shared exec log. Never throws.
 *
 * On non-Windows hosts this returns a graceful `powershell-unavailable`
 * failure WITHOUT spawning any process, so collectors can degrade honestly.
 */
export function runPowerShellCommand(id: PsCommandId, execLog: ExecLogEntry[]): Promise<CmdResult> {
  return new Promise<CmdResult>((resolve) => {
    const started = Date.now();
    const command = `${PS_EXEC_FILE} -NoProfile -NonInteractive -Command <${id}>`;

    const finish = (result: CmdResult): void => {
      execLog.push(toExecLog(result));
      resolve(result);
    };
    const fail = (error: CmdError, stderr: string, logCommand = command): CmdResult => ({
      ok: false,
      stdout: '',
      stderr,
      code: null,
      error,
      ms: Date.now() - started,
      command: logCommand,
    });

    const spec = PS_REGISTRY[id];
    if (!spec) {
      finish(fail('ALLOWLIST_DENIED', `Unknown PowerShell command id: ${id}`));
      return;
    }

    if (process.platform !== 'win32') {
      // Do NOT spawn anything off-Windows — report an honest skip instead.
      finish(
        fail(
          'NOT_FOUND',
          'powershell-unavailable (non-Windows host — command skipped, not executed)',
          `${command} [skipped: non-Windows host]`,
        ),
      );
      return;
    }

    execFile(
      PS_EXEC_FILE,
      [...PS_EXEC_ARGS, spec.script],
      {
        timeout: spec.timeoutMs,
        killSignal: 'SIGKILL',
        maxBuffer: MAX_BUFFER_BYTES,
        env: { ...PS_SANITIZED_ENV },
        shell: false,
        windowsHide: true,
      },
      (err, stdout, stderr) => {
        const ms = Date.now() - started;
        if (!err) {
          finish({ ok: true, stdout: stdout.toString(), stderr: stderr.toString(), code: 0, ms, command });
          return;
        }
        const e = err as NodeJS.ErrnoException & { killed?: boolean };
        let error: CmdError = 'OTHER';
        if (e.code === 'ENOENT') error = 'NOT_FOUND';
        else if (e.killed) error = 'TIMEOUT';
        finish({
          ok: false,
          stdout: stdout.toString(),
          stderr: stderr.toString(),
          code: typeof e.code === 'number' ? e.code : null,
          error,
          ms,
          command,
        });
      },
    );
  });
}
