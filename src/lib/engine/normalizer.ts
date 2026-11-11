// SENTINEL DESK 1.0 — Event Normalizer (§7 stage 2)
//
// Converts raw Windows Event Log records (XML-data shape) into the common
// normalized schema. In the desktop port this module maps from windows-rs
// EVT_HANDLE / rendered XML; here it maps the synthetic source's identical
// payload shape, so the mapping logic is production-faithful.

import type { RawWindowsEvent } from './generator'

export interface NormalizedEvent {
  id?: string
  ts: Date
  channel: string
  provider: string
  eventId: number
  level: string
  computer: string
  recordId: string
  userName?: string
  userSid?: string
  targetUserName?: string
  processId?: number
  processName?: string
  parentProcessId?: number
  parentProcessName?: string
  commandLine?: string
  ipAddress?: string
  logonType?: number
  serviceName?: string
  taskName?: string
  summary: string
  raw: string
  synthetic: boolean
  sourceRef: string
}

function str(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined
  const s = String(v).trim()
  return s === '' || s === '—' || s === '-' ? undefined : s
}

function int(v: unknown): number | undefined {
  const s = str(v)
  if (!s) return undefined
  const n = Number(s.replace(/^0x/i, '0x').startsWith('0x') ? parseInt(s, 16) : s)
  return Number.isFinite(n) ? n : undefined
}

const LOGIN_TYPES: Record<number, string> = {
  2: 'Interactive', 3: 'Network', 4: 'Batch', 5: 'Service',
  7: 'Unlock', 8: 'NetworkCleartext', 9: 'NewCredentials',
  10: 'RemoteInteractive', 11: 'CachedInteractive',
}

/** Build a one-line human summary used for search and display. */
export function buildSummary(e: Omit<NormalizedEvent, 'summary' | 'raw' | 'synthetic' | 'sourceRef' | 'provider' | 'channel'>, raw: RawWindowsEvent): string {
  const r = raw.rawData
  switch (raw.eventId) {
    case 4624:
      return `Successful ${LOGIN_TYPES[e.logonType ?? 0] ?? 'logon'} — ${e.targetUserName ?? 'unknown'} from ${e.ipAddress ?? 'local'}`
    case 4625:
      return `Failed logon (${String(r.Status ?? '')}) — ${e.targetUserName ?? 'unknown'} from ${e.ipAddress ?? 'local'}`
    case 4688:
    case 1:
      return `Process created: ${e.processName ?? 'unknown'}${e.commandLine ? ` — ${e.commandLine}` : ''}`
    case 4698:
    case 106:
      return `Scheduled task created: ${e.taskName ?? 'unknown'}${e.commandLine ? ` — ${e.commandLine}` : ''}`
    case 4702:
      return `Scheduled task updated: ${e.taskName ?? 'unknown'}`
    case 7045:
      return `Service installed: ${e.serviceName ?? 'unknown'} (${e.commandLine ?? ''})`
    case 4104:
      return `PowerShell script block: ${(String(r.ScriptBlockText ?? '')).slice(0, 160)}`
    case 4719:
      return `Audit policy changed by ${e.userName ?? 'unknown'}: ${Array.isArray(r.AuditPolicyChanges) ? (r.AuditPolicyChanges as string[]).join('; ') : 'policy modified'}`
    case 1102:
      return `Security log cleared by ${e.userName ?? 'unknown'}`
    case 104:
      return `System log cleared (${String(r.Channel ?? 'System')})`
    case 3:
      return `Network connection: ${e.processName ?? 'unknown'} → ${e.ipAddress ?? 'unknown'}`
    case 4720:
      return `User account created: ${e.targetUserName ?? 'unknown'}`
    case 4738:
      return `User account changed: ${e.targetUserName ?? 'unknown'}`
    default:
      return `${raw.provider} EID ${raw.eventId}`
  }
}

export function normalize(raw: RawWindowsEvent): NormalizedEvent {
  const r = raw.rawData
  const base = {
    ts: new Date(raw.timeCreated),
    channel: raw.channel,
    provider: raw.provider,
    eventId: raw.eventId,
    level: raw.level,
    computer: raw.computer,
    recordId: raw.recordId,
    userName: str(r.SubjectUserName ?? r.User),
    userSid: str(r.UserId),
    targetUserName: str(r.TargetUserName),
    processId: int(r.ProcessId ?? r.NewProcessId ?? r.ClientProcessId),
    processName: str(r.NewProcessName ?? r.Image),
    parentProcessId: int(r.ParentProcessId),
    parentProcessName: str(r.ParentProcessName ?? r.ParentImage),
    commandLine: str(r.CommandLine),
    ipAddress: str(r.IpAddress ?? r.DestinationIp),
    logonType: int(r.LogonType),
    serviceName: str(r.ServiceName),
    taskName: str(r.TaskName),
  }

  // Service installation: ImagePath is the command line
  if (raw.eventId === 7045 && !base.commandLine && str(r.ImagePath)) {
    base.commandLine = str(r.ImagePath)
  }
  // TaskScheduler 106 does not carry the command; pull from sibling 4698 content if present
  if ((raw.eventId === 4698) && !base.commandLine && typeof r.TaskContent === 'string') {
    const m = r.TaskContent.match(/<Command>([^<]+)<\/Command>/)
    if (m) base.commandLine = m[1]
  }
  if (raw.eventId === 4104 && !base.commandLine) {
    base.commandLine = str(r.ScriptBlockText)
  }

  const summary = buildSummary(base, raw)
  return {
    ...base,
    summary,
    raw: JSON.stringify(raw),
    synthetic: true,
    sourceRef: raw.sourceRef,
  }
}

export function normalizeBatch(raws: RawWindowsEvent[]): NormalizedEvent[] {
  return raws.map(normalize)
}
