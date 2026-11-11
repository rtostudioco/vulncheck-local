// SENTINEL DESK 1.0 — Detection rule catalog (MODULE 03)
//
// Rules are stored in a portable, Sigma-inspired JSON logic format so the same
// definitions can be re-implemented 1:1 in Rust (src-tauri) during the desktop
// port. Every rule carries its MITRE mapping (only where justified), evidence
// fields, false-positive notes and limitations (§8 MODULE 03 contract).
//
// Event-ID mappings below are verified against the Microsoft Security Auditing
// and Sysmon documentation for the channels used by the synthetic source.

export type FieldOp =
  | 'eq'
  | 'in'
  | 'neq'
  | 'contains'
  | 'regex'
  | 'startsWith'
  | 'gt'
  | 'lt'

export interface Condition {
  field: string
  op: FieldOp
  value: unknown
}

export interface ThresholdSpec {
  count: number
  windowSec: number
  groupBy: string[] // event fields defining the group (e.g. ["computer"])
}

export interface RuleLogic {
  kind: 'single' | 'threshold' | 'correlation'
  channel?: string
  channels?: string[]
  eventIds?: number[]
  conditions?: Condition[]
  threshold?: ThresholdSpec
  /// correlation kind: reference other rule ids
  signals?: { ruleId: string; minCount?: number }[]
  correlationWindowSec?: number
  /// For correlation rules: how evidence is linked
  linkBy?: string[]
}

export interface DetectionRuleDef {
  id: string
  name: string
  description: string
  version: string
  author: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  mitreId?: string
  mitreName?: string
  confidence: number
  logic: RuleLogic
  evidenceFields: string[]
  falsePositives: string
  limitations: string
}

export const DETECTION_RULES: DetectionRuleDef[] = [
  {
    id: 'SD-001',
    name: 'Multiple failed logon events',
    description:
      'Detects bursts of failed interactive or remote logon attempts (Event ID 4625) grouped per computer within a short window — the classic password-spraying / brute-force footprint.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'high',
    category: 'credential_access',
    mitreId: 'T1110',
    mitreName: 'Brute Force',
    confidence: 80,
    logic: {
      kind: 'threshold',
      channel: 'Security',
      eventIds: [4625],
      threshold: { count: 5, windowSec: 300, groupBy: ['computer'] },
      conditions: [],
    },
    evidenceFields: ['targetUserName', 'ipAddress', 'logonType', 'computer'],
    falsePositives:
      'Expired passwords after policy changes, service accounts with stale credentials, misconfigured applications retrying authentication.',
    limitations:
      'Requires Security log access with account logon auditing enabled. If auditing is off, no 4625 events exist and this rule cannot fire — absence of alerts is NOT absence of attacks.',
  },
  {
    id: 'SD-002',
    name: 'Successful logon after failed-logon burst',
    description:
      'Detects a successful logon (4624, LogonType 3 or 10) from the same computer within minutes of a failed-logon burst (≥3 × 4625) — a plausible successful brute-force hypothesis requiring human verification.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'high',
    category: 'credential_access',
    mitreId: 'T1078',
    mitreName: 'Valid Accounts',
    confidence: 65,
    logic: {
      kind: 'correlation',
      channels: ['Security'],
      signals: [
        { ruleId: 'SD-001', minCount: 1 },
      ],
      correlationWindowSec: 600,
      linkBy: ['computer'],
      eventIds: [4624],
      conditions: [{ field: 'logonType', op: 'in', value: [3, 10] }],
    },
    evidenceFields: ['userName', 'ipAddress', 'logonType', 'computer'],
    falsePositives:
      'Users who genuinely forgot their password and then typed it correctly; VPN reconnections after an outage.',
    limitations:
      'Correlates by computer and time only — it cannot verify that the successful logon used the same account as the failures. Treat as a hypothesis, never as confirmation.',
  },
  {
    id: 'SD-003',
    name: 'Suspicious PowerShell command-line patterns',
    description:
      'Flags PowerShell script-block logging (4104) or process creation (4688) content matching obfuscation and download-cradle patterns: -enc/FromBase64String, IEX/Invoke-Expression, DownloadString/DownloadFile, hidden-window switches.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'high',
    category: 'execution',
    mitreId: 'T1059.001',
    mitreName: 'Command and Scripting Interpreter: PowerShell',
    confidence: 75,
    logic: {
      kind: 'single',
      channels: ['PowerShell/Operational', 'Security'],
      eventIds: [4104, 4688],
      conditions: [
        { field: 'commandLine', op: 'regex', value: '(?i)(-enc[odedcommand]?\\s|FromBase64String|Invoke-Expression|\\bIEX\\b|DownloadString|DownloadFile|DownloadData|-nop\\s*-w\\s*hidden|-WindowStyle\\s*Hidden)' },
      ],
    },
    evidenceFields: ['commandLine', 'processName', 'userName', 'parentProcessName'],
    falsePositives:
      'Legitimate admin automation, software installers, DSC configuration tasks, base64 usage in CI agents.',
    limitations:
      'Requires PowerShell script-block logging (4104) or command-line process auditing (4688) to be enabled. Encoded payloads are detected by their wrapper pattern, not decoded.',
  },
  {
    id: 'SD-004',
    name: 'Scheduled task creation or modification',
    description:
      'Detects scheduled task registration/update events (Security 4698/4702, TaskScheduler 106) — a common persistence primitive that deserves review of the task action command.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'medium',
    category: 'persistence',
    mitreId: 'T1053.005',
    mitreName: 'Scheduled Task',
    confidence: 60,
    logic: {
      kind: 'single',
      channels: ['Security', 'TaskScheduler/Operational'],
      eventIds: [4698, 4702, 106],
      conditions: [],
    },
    evidenceFields: ['taskName', 'commandLine', 'userName', 'computer'],
    falsePositives:
      'Software update tasks, Group Policy–distributed tasks, IT maintenance scripts.',
    limitations:
      'The task action path is included when available; some channels do not carry the action command line.',
  },
  {
    id: 'SD-005',
    name: 'New service creation',
    description:
      'Detects service installation events (System 7045) — persistence or privilege-escalation vector. Severity escalates when the binary path points to user-writable locations.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'medium',
    category: 'persistence',
    mitreId: 'T1543.003',
    mitreName: 'Windows Service',
    confidence: 55,
    logic: {
      kind: 'single',
      channel: 'System',
      eventIds: [7045],
      conditions: [],
    },
    evidenceFields: ['serviceName', 'commandLine', 'userName', 'computer'],
    falsePositives: 'Legitimate software and driver installations by administrators or software distribution tools.',
    limitations:
      'Requires System channel access (usually readable by authenticated users). Path-based escalation is heuristic.',
  },
  {
    id: 'SD-006',
    name: 'Security configuration changes',
    description:
      'Detects audit-policy changes (4719), Security log clears (1102) and account management events (4720/4738) — potential defense-evasion preparation.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'medium',
    category: 'defense_evasion',
    mitreId: 'T1562',
    mitreName: 'Impair Defenses',
    confidence: 60,
    logic: {
      kind: 'single',
      channel: 'Security',
      eventIds: [4719, 1102, 4720, 4738],
      conditions: [],
    },
    evidenceFields: ['userName', 'targetUserName', 'summary', 'computer'],
    falsePositives: 'Planned hardening changes, onboarding/offboarding workflows, GPO-driven audit policy updates.',
    limitations:
      'Audit-policy change auditing must itself be enabled — a subset of tampering can disable the very telemetry this rule uses.',
  },
  {
    id: 'SD-007',
    name: 'Process execution from unusual location',
    description:
      'Detects process-creation events (4688 / Sysmon 1) where the image path resides in user-writable or staging directories: %TEMP%, Downloads, AppData\\Roaming, C:\\Users\\Public, C:\\Windows\\Temp, ProgramData subfolders.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'high',
    category: 'defense_evasion',
    mitreId: 'T1036.005',
    mitreName: 'Masquerading: Match Legitimate Name or Location',
    confidence: 70,
    logic: {
      kind: 'single',
      channels: ['Security', 'Sysmon'],
      eventIds: [4688, 1],
      conditions: [
        { field: 'processName', op: 'regex', value: '(?i)(\\\\(temp|downloads|appdata\\\\roaming|users\\\\public|windows\\\\temp|programdata\\\\[^\\\\]+)\\\\)' },
      ],
    },
    evidenceFields: ['processName', 'commandLine', 'userName', 'parentProcessName'],
    falsePositives: 'User-installed applications, portable tools deliberately deployed to user directories, browser download-and-run workflows.',
    limitations: 'Only locations with process auditing or Sysmon coverage are visible.',
  },
  {
    id: 'SD-008',
    name: 'Suspicious process-associated network activity',
    description:
      'Detects network connections (Sysmon 3) initiated by scripting binaries or LOLBins commonly abused for C2 or payload retrieval: powershell, cmd, certutil, rundll32, mshta, wscript, cscript.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'medium',
    category: 'command_and_control',
    mitreId: 'T1071',
    mitreName: 'Application Layer Protocol',
    confidence: 65,
    logic: {
      kind: 'single',
      channel: 'Sysmon',
      eventIds: [3],
      conditions: [
        { field: 'processName', op: 'regex', value: '(?i)(powershell|cmd|certutil|rundll32|mshta|wscript|cscript)\\.exe' },
        { field: 'ipAddress', op: 'regex', value: '^(?!10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)' },
      ],
    },
    evidenceFields: ['processName', 'ipAddress', 'commandLine', 'userName'],
    falsePositives: 'Administrative scripts fetching updates, package managers, approved download automation.',
    limitations: 'Requires Sysmon (Event ID 3). Sysmon is optional and must not be assumed installed — rule is inert without it.',
  },
  {
    id: 'SD-009',
    name: 'Potential persistence sequence',
    description:
      'CORRELATION: suspicious PowerShell activity (SD-003) plus a scheduled task or service modification (SD-004/SD-005) on the same computer within 15 minutes — a plausible persistence chain hypothesis.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'high',
    category: 'persistence',
    mitreId: 'T1053.005',
    mitreName: 'Scheduled Task (persistence chain)',
    confidence: 70,
    logic: {
      kind: 'correlation',
      signals: [
        { ruleId: 'SD-003', minCount: 1 },
        { ruleId: 'SD-004', minCount: 1 },
      ],
      correlationWindowSec: 900,
      linkBy: ['computer'],
    },
    evidenceFields: ['computer', 'taskName', 'serviceName', 'commandLine'],
    falsePositives: 'Legitimate deployment tooling that runs PowerShell and registers tasks in one maintenance window.',
    limitations:
      'Sequence ordering is not verified — the correlation engine links by host and time window only. Proximity is not causation.',
  },
  {
    id: 'SD-010',
    name: 'Multi-signal suspicious activity',
    description:
      'CORRELATION: three or more distinct detection rules matched on the same computer within a 20-minute window. Multi-signal convergence materially raises the priority of human review.',
    version: '1.0.0',
    author: 'Sentinel Desk Core Team',
    severity: 'critical',
    category: 'discovery',
    mitreId: 'T1059',
    mitreName: 'Command and Scripting Interpreter',
    confidence: 75,
    logic: {
      kind: 'correlation',
      signals: [{ ruleId: '*', minCount: 3 }],
      correlationWindowSec: 1200,
      linkBy: ['computer'],
    },
    evidenceFields: ['computer'],
    falsePositives: 'Correlated maintenance activity (e.g., mass software deployment touching several detection surfaces at once).',
    limitations:
      'Depends entirely on the availability and accuracy of the underlying rules. A disabled rule cannot contribute.',
  },
]

export const RULES_BY_ID = new Map(DETECTION_RULES.map((r) => [r.id, r]))
