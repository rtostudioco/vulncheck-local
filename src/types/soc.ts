// SENTINEL DESK 1.0 — Shared domain types (frontend + backend contract)
// These types mirror the Tauri IPC command payloads documented in
// docs/ARCHITECTURE.md so the UI can later be lifted into the desktop shell
// without redesign.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type IncidentStatus =
  | 'new'
  | 'investigating'
  | 'monitoring'
  | 'resolved'
  | 'false_positive'

export type AlertStatus = 'open' | 'triaged' | 'linked_to_incident' | 'closed_fp'

export type SourceStatus = 'active' | 'demo' | 'permission_required' | 'unavailable'

export type AiMode = 'off' | 'sandbox' | 'local' | 'remote'

export interface EvidenceMatch {
  field: string
  value: string
  op: string
}

export interface EvidenceRef {
  eventId: string
  matched: EvidenceMatch[]
}

export interface EventRecord {
  id: string
  ts: string
  channel: string
  provider: string
  eventId: number
  level: string
  computer: string
  recordId?: string | null
  userName?: string | null
  targetUserName?: string | null
  processId?: number | null
  processName?: string | null
  parentProcessId?: number | null
  parentProcessName?: string | null
  commandLine?: string | null
  ipAddress?: string | null
  logonType?: number | null
  serviceName?: string | null
  taskName?: string | null
  summary?: string | null
  synthetic: boolean
  sourceRef?: string | null
}

export interface RuleSummary {
  id: string
  name: string
  description: string
  version: string
  author: string
  severity: Severity
  category: string
  mitreId?: string | null
  mitreName?: string | null
  enabled: boolean
  falsePositives?: string | null
  limitations?: string | null
  evidenceFields?: string | null
  alertCount?: number
  logic?: unknown
}

export interface AlertRecord {
  id: string
  ruleId: string
  severity: Severity
  title: string
  summary: string
  confidence: number
  status: AlertStatus
  evidence: EvidenceRef[]
  mitreId?: string | null
  computer?: string | null
  userName?: string | null
  incidentId?: string | null
  createdAt: string
  rule?: RuleSummary
}

export interface IncidentNoteRecord {
  id: string
  incidentId: string
  author: 'analyst' | 'system' | 'ai'
  body: string
  createdAt: string
}

export interface AiAnalysisRecord {
  id: string
  incidentId?: string | null
  kind: string
  provider: string
  model: string
  privacyMode: string
  promptVersion: string
  inputSummary: string
  output: string
  createdAt: string
}

export interface IncidentRecord {
  id: string
  code: string
  title: string
  severity: Severity
  status: IncidentStatus
  hypothesis?: string | null
  correlationMeta?: {
    fields: string[]
    windowSec: number
    host?: string
    inferred: boolean
  } | null
  summary?: string | null
  createdAt: string
  updatedAt: string
  alerts?: AlertRecord[]
  notes?: IncidentNoteRecord[]
  aiAnalyses?: AiAnalysisRecord[]
}

export interface SourceRecord {
  id: string
  channel: string
  displayName: string
  description?: string | null
  status: SourceStatus
  available: boolean
  requiresAdmin: boolean
  note?: string | null
  lastCollectAt?: string | null
  eventsCollected: number
}

export interface PipelineStageStat {
  stage: string
  status: 'ok' | 'error' | 'skipped'
  input: number
  output: number
  errors: string[]
  durationMs: number
}

export interface PipelineRun {
  startedAt: string
  durationMs: number
  stages: PipelineStageStat[]
  eventsIn: number
  alertsOut: number
  incidentsOut: number
  newAlerts?: { alertId: string; ruleId: string; title: string; severity: string; summary: string }[]
  newIncidents?: { id: string; code: string; title: string; severity: string }[]
}

export interface OverviewPayload {
  demoMode: true
  machine: string
  collector: {
    running: boolean
    intervalSec: number
    lastTickAt: string | null
    lastRun: PipelineRun | null
    totalCollected: number
  }
  counts: {
    events24h: number
    eventsTotal: number
    alertsOpen: number
    incidentsActive: number
    rulesEnabled: number
    rulesTotal: number
  }
  severity: { severity: Severity; alerts: number; incidents: number }[]
  eventsTrend: { time: string; events: number; alerts: number }[]
  sources: SourceRecord[]
  recentAlerts: AlertRecord[]
  recentIncidents: IncidentRecord[]
  ai: { mode: AiMode; available: boolean; provider: string; model: string }
}

export interface SettingsPayload {
  language: 'en' | 'es'
  collectorEnabled: boolean
  collectorIntervalSec: number
  retentionDays: number
  aiMode: AiMode
  aiRedaction: boolean
  tiExternalConsent: boolean
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
