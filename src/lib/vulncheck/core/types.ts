/**
 * VulnCheck Local — shared type contract
 * ---------------------------------------
 * Single source of truth for the audit engine, compliance rules,
 * API DTOs and the dashboard frontend.
 */

export const ENGINE_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Core enums / constants
// ---------------------------------------------------------------------------

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type CheckStatus =
  | 'PASS'
  | 'FAIL'
  | 'WARNING'
  | 'NOT_APPLICABLE'
  | 'NOT_ASSESSED'
  | 'ERROR';
export type AuditStatus = 'RUNNING' | 'COMPLETED' | 'FAILED';
export type OsTarget = 'linux' | 'windows' | 'both';
export type Platform = 'linux' | 'windows' | 'unsupported';

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const CHECK_STATUSES: CheckStatus[] = [
  'PASS',
  'FAIL',
  'WARNING',
  'NOT_APPLICABLE',
  'NOT_ASSESSED',
  'ERROR',
];

export type Category =
  | 'FIREWALL'
  | 'ACCOUNTS'
  | 'UPDATES'
  | 'NETWORK'
  | 'ENDPOINT'
  | 'SERVICES'
  | 'BACKUP';

export const CATEGORIES: Category[] = [
  'FIREWALL',
  'ACCOUNTS',
  'UPDATES',
  'NETWORK',
  'ENDPOINT',
  'SERVICES',
  'BACKUP',
];

export const CATEGORY_LABELS: Record<Category, string> = {
  FIREWALL: 'Firewall',
  ACCOUNTS: 'Account Security',
  UPDATES: 'System Updates',
  NETWORK: 'Network Exposure',
  ENDPOINT: 'Endpoint Protection',
  SERVICES: 'Service Configuration',
  BACKUP: 'Backup & Recovery',
};

/// Audit modules A–H (spec §5)
export const MODULES = [
  {
    ref: 'A',
    key: 'inventory',
    name: 'System Inventory',
    description: 'Hardware, operating system, software and network inventory.',
  },
  {
    ref: 'B',
    key: 'firewall',
    name: 'Firewall Auditor',
    description: 'Firewall product, status, profiles and exceptions (Defender Firewall / UFW / firewalld / nftables).',
  },
  {
    ref: 'C',
    key: 'accounts',
    name: 'User & Access Auditor',
    description: 'Local accounts, administrative privileges, password policy indicators, remote access. Never collects credentials.',
  },
  {
    ref: 'D',
    key: 'network',
    name: 'Network Exposure Auditor',
    description: 'Listening TCP/UDP ports, interfaces, active connections, unnecessary exposed services. Passive, local-only.',
  },
  {
    ref: 'E',
    key: 'updates',
    name: 'System Update Auditor',
    description: 'Pending updates, security updates, automatic update configuration. Verified status is distinguished from unobtainable status.',
  },
  {
    ref: 'F',
    key: 'endpoint',
    name: 'Antivirus & Protection',
    description: 'Defender / ClamAV detection. Protection is never claimed active unless verifiably running.',
  },
  {
    ref: 'G',
    key: 'services',
    name: 'Service Auditor',
    description: 'Running services, startup configuration indicators, legacy remote-administration services. Read-only; never disables anything.',
  },
  {
    ref: 'H',
    key: 'backup',
    name: 'Backup & Recovery Auditor',
    description: 'Backup software, scheduled jobs, snapshot indicators. A backup is never claimed valid without verification.',
  },
] as const;

export type ModuleKey = (typeof MODULES)[number]['key'];

// ---------------------------------------------------------------------------
// Inventory shapes (Module A)
// ---------------------------------------------------------------------------

export interface DiskInfo {
  device: string;
  fstype: string;
  sizeMb: number;
  usedMb: number;
  mount: string;
  usePercent: number;
}

export interface InterfaceInfo {
  name: string;
  ipv4: string | null;
  ipv6: string | null;
  mac: string | null;
  internal: boolean;
}

export interface HostProfile {
  hostname: string;
  platform: string;
  osName: string;
  osVersion: string;
  osBuild: string;
  kernelVersion: string | null;
  arch: string;
  cpuModel: string | null;
  cpuCores: number | null;
  totalMemoryMb: number | null;
  usedMemoryMb: number | null;
  uptimeHours: number | null;
  primaryIp: string | null;
  packageCount: number | null;
  packages: string[];
  disks: DiskInfo[];
  interfaces: InterfaceInfo[];
}

// ---------------------------------------------------------------------------
// Evidence bundles (Modules B–H) — every bundle carries availability metadata
// so a failed inspection is NEVER silently treated as secure.
// ---------------------------------------------------------------------------

interface EvidenceBase {
  available: boolean;
  source: string;
  notes: string[];
}

export interface FirewallRuleInfo {
  raw: string;
  action: string;
  target: string | null;
  port: string | null;
  proto: string | null;
  from: string | null;
}

/// Windows-specific hardening evidence (UAC / RDP / SMBv1) collected by the
/// WINDOWS firewall collector only. Additive + optional: Linux collectors and
/// all existing consumers are unaffected. `null` means "could not be read" —
/// never assumed secure.
export interface UacEvidence {
  enableLua: boolean | null;
  consentPromptBehaviorAdmin: number | null;
  promptOnSecureDesktop: boolean | null;
  source: string;
}

export interface RdpEvidence {
  /// true = RDP disabled (fDenyTSConnections = 1)
  denyTSConnections: boolean | null;
  /// true = Network Level Authentication enforced (UserAuthentication = 1)
  nlaEnforced: boolean | null;
  source: string;
}

export interface Smb1Evidence {
  /// true = SMBv1 server protocol enabled (Get-SmbServerConfiguration / registry)
  serverEnabled: boolean | null;
  /// Get-WindowsOptionalFeature State for SMB1Protocol (e.g. 'Disabled')
  featureState: string | null;
  source: string;
}

export interface WindowsHardeningEvidence {
  available: boolean;
  uac: UacEvidence;
  rdp: RdpEvidence;
  smb1: Smb1Evidence;
}

export interface FirewallEvidence extends EvidenceBase {
  product: string | null; // ufw | firewalld | nftables | iptables | windows-defender | none-detected
  active: boolean | null;
  defaultIncoming: string | null;
  defaultOutgoing: string | null;
  profiles: string[];
  rules: FirewallRuleInfo[];
  /// Populated ONLY by the Windows firewall collector (see above).
  windowsHardening?: WindowsHardeningEvidence;
}

export interface UserInfo {
  name: string;
  uid: number;
  gid: number;
  home: string;
  shell: string;
  interactive: boolean;
  admin: boolean;
  passwordStatus: 'locked' | 'set' | 'empty' | 'unknown' | 'unreadable';
  lastChangeDays: number | null;
}

export interface SshConfigInfo {
  available: boolean;
  permitRootLogin: string | null;
  passwordAuthentication: string | null;
  port: number | null;
  serviceRunning: boolean | null;
  files: string[];
}

export interface PasswordPolicyInfo {
  maxDays: number | null;
  minDays: number | null;
  minLength: number | null;
  warnDays: number | null;
  source: string;
}

export interface AccountsEvidence extends EvidenceBase {
  users: UserInfo[];
  adminGroups: Record<string, string[]>;
  passwordPolicy: PasswordPolicyInfo;
  ssh: SshConfigInfo;
  shadowReadable: boolean;
}

export interface PortInfo {
  proto: 'tcp' | 'udp';
  port: number;
  address: string;
  bindScope: 'ALL' | 'LOCAL' | 'OTHER';
  service: string;
  risk: Severity;
  note: string;
}

export interface NetworkEvidence extends EvidenceBase {
  listeningPorts: PortInfo[];
  establishedCount: number | null;
  establishedSamples: { local: string; remote: string }[];
}

export interface UpdatesEvidence extends EvidenceBase {
  pendingUpdates: number | null;
  pendingSecurityUpdates: number | null;
  pendingPackageNames: string[];
  rebootRequired: boolean | null;
  autoUpdatesEnabled: boolean | null;
  lastUpdateCheck: string | null;
}

export interface EndpointEvidence extends EvidenceBase {
  productName: string | null;
  binaryPresent: boolean;
  daemonRunning: boolean | null;
  signatureDb: { present: boolean; path: string | null; lastUpdated: string | null };
  /// true ONLY when real-time protection could actually be verified
  verifiedActive: boolean;
}

export interface RiskyServiceInfo {
  name: string;
  reason: string;
  severity: Severity;
}

export interface ServicesEvidence extends EvidenceBase {
  systemdAvailable: boolean;
  runningServices: string[];
  runningProcesses: string[];
  riskyServices: RiskyServiceInfo[];
}

export interface BackupJobInfo {
  file: string;
  schedule: string;
  command: string;
}

export interface BackupEvidence extends EvidenceBase {
  toolsDetected: string[];
  scheduledJobs: BackupJobInfo[];
  snapshotDirs: string[];
  lastBackupDate: string | null;
}

export interface ExecLogEntry {
  command: string;
  ok: boolean;
  ms: number;
}

export interface ModuleStatus {
  moduleKey: ModuleKey;
  name: string;
  state: 'OK' | 'PARTIAL' | 'UNAVAILABLE' | 'ERROR';
  source: string;
  notes: string[];
}

export interface EvidenceBundle {
  platform: Platform;
  collectedAt: string;
  inventory: HostProfile;
  firewall: FirewallEvidence;
  accounts: AccountsEvidence;
  network: NetworkEvidence;
  updates: UpdatesEvidence;
  endpoint: EndpointEvidence;
  services: ServicesEvidence;
  backup: BackupEvidence;
  modules: ModuleStatus[];
  execLog: ExecLogEntry[];
}

// ---------------------------------------------------------------------------
// Compliance rule interface (MODULE I)
// ---------------------------------------------------------------------------

export interface RuleGuide {
  problem: string;
  impact: string;
  solution: string;
  verification: string;
}

export interface RuleResult {
  status: CheckStatus;
  /// override severity (defaults to rule.severityIfFail on FAIL)
  severity?: Severity;
  /// pre-formatted evidence text shown in UI and reports
  evidence: string;
  note?: string;
}

export interface RuleDefinition {
  id: string; // e.g. VC-FW-001
  version: string;
  category: Category;
  osTarget: OsTarget;
  title: string;
  description: string;
  severityIfFail: Severity;
  /// CIS-style reference concept — never claims certification
  reference: string | null;
  guide: RuleGuide;
  evaluate(ev: EvidenceBundle): RuleResult;
}

// ---------------------------------------------------------------------------
// Scoring (MODULE J) — documented, reproducible
// ---------------------------------------------------------------------------

export interface ScoreCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  warnings: number;
  passed: number;
  failed: number;
  notAssessed: number;
  errors: number;
  notApplicable: number;
}

export interface ScoreResult {
  score: number; // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  coverage: number; // 0–100, share of assessable rules actually assessed
  counts: ScoreCounts;
  deductions: { ruleId: string; severity: Severity; points: number }[];
  totalDeduction: number;
}

export const SCORING_DEDUCTIONS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 7,
  LOW: 3,
  INFO: 0,
};

// ---------------------------------------------------------------------------
// API DTOs (contract between backend and dashboard)
// ---------------------------------------------------------------------------

export type SessionCounts = ScoreCounts;

export interface SessionSummary {
  id: string;
  startedAt: string;
  completedAt: string | null;
  status: AuditStatus;
  progress: number;
  currentStep: string | null;
  platform: string;
  engineVersion: string;
  overallScore: number | null;
  grade: string | null;
  coverage: number | null;
  findingsCount: number;
  counts: SessionCounts | null;
}

export interface FindingDTO {
  id: string;
  ruleId: string;
  ruleVersion: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  status: CheckStatus;
  evidence: string;
  riskExplanation: string;
  remediation: string;
  verification: string | null;
  osTarget: string;
  aiExplanation?: string | null;
}

export interface SessionDetail extends SessionSummary {
  profile: HostProfile | null;
  findings: FindingDTO[];
  modules: ModuleStatus[];
  limitations: string[];
  network: { listeningPorts: PortInfo[]; interfaces: InterfaceInfo[] } | null;
}

export interface MetaDTO {
  engineVersion: string;
  ruleCount: number;
  platform: string;
  aiConsentEnabled: boolean;
  retentionDays: number;
  methodology: string;
  disclaimers: string[];
}

export interface SettingsDTO {
  aiConsentEnabled: boolean;
  retentionDays: number;
  schemaVersion: number;
  engineVersion: string;
}

export interface ReportHistoryDTO {
  id: string;
  sessionId: string;
  format: string;
  fileName: string;
  generatedAt: string;
  sessionDate: string;
  overallScore: number | null;
}

// ---------------------------------------------------------------------------
// Shared methodology / disclaimer texts (single wording everywhere)
// ---------------------------------------------------------------------------

export const METHODOLOGY_TEXT =
  'Each versioned rule evaluates collected evidence and returns one of: PASS, FAIL, WARNING, ' +
  'NOT_APPLICABLE, NOT_ASSESSED or ERROR. Failures deduct points from a 0–100 posture score using ' +
  'fixed weights (CRITICAL −25, HIGH −15, MEDIUM −7, LOW −3, INFO −0); WARNING deducts half weight. ' +
  'The score starts at 100 and is floored at 0. Rules that could not be assessed do NOT deduct points; ' +
  'instead they reduce assessment coverage, which is reported alongside the score. Grade thresholds: ' +
  'A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.';

export const DISCLAIMERS = [
  'VulnCheck Local performs local, read-only, passive auditing. It never modifies systems, never disables services, never changes firewall or account configuration, and never collects credentials.',
  'The security posture score is an internal, reproducible indicator — it is NOT an official compliance score.',
  'The rule set is inspired by publicly documented CIS Benchmark concepts where technical requirements are documented. VulnCheck Local is not CIS-certified and this assessment is not a CIS compliance claim.',
  'A failed or unsupported inspection is always reported as NOT_ASSESSED / ERROR and never counted as secure.',
];

export const AI_CONSENT_TEXT =
  'AI explanations are optional and off by default. When enabled, clicking "Explain" on an individual ' +
  'finding sends only that finding\'s metadata (category, title, description and a sanitized evidence ' +
  'excerpt, truncated) to the configured AI provider. Full system inventory, hostnames, addresses and ' +
  'audit evidence sets are never transmitted automatically.';
