// SENTINEL DESK 1.0 — typed IPC wrappers
// Every call maps 1:1 to a Tauri command in src-tauri/src/commands/*.

export interface OverviewStats {
  generatedAt: string;
  events24h: number;
  eventsTotal: number;
  openAlerts: number;
  activeIncidents: number;
  rulesEnabled: number;
  rulesTotal: number;
  bySeverity: { severity: string; alerts: number; incidents: number }[];
  volume24h: { bucket: string; events: number; alerts: number }[];
  sources: {
    channel: string;
    displayName: string;
    description: string | null;
    status: string;
    available: boolean;
    requiresAdmin: boolean;
    note: string | null;
    lastCollectAt: string | null;
    eventsCollected: number;
  }[];
  recentAlerts: { id: string; ruleId: string; severity: string; title: string; summary: string; createdAt: string }[];
  recentIncidents: { id: string; code: string; title: string; severity: string; status: string; createdAt: string }[];
}

export interface EventRow {
  id: string;
  ts: string;
  channel: string;
  provider: string;
  eventId: number;
  level: string;
  computer: string;
  userName: string | null;
  targetUserName?: string | null;
  processName?: string | null;
  commandLine?: string | null;
  ipAddress?: string | null;
  summary: string | null;
  synthetic: boolean;
  sourceRef: string | null;
  recordId?: string | null;
}

export interface RuleSummary {
  id: string;
  name: string;
  description: string;
  version: string;
  author: string;
  severity: string;
  category: string;
  mitreId: string | null;
  mitreName: string | null;
  enabled: boolean;
  logic: unknown;
  falsePositives: string | null;
  limitations: string | null;
  evidenceFields: string[];
  alertCount: number;
}

export interface RuleTestResult {
  matched: boolean;
  matchCount: number;
  fixtureEvents: number;
  explanation: string;
  evidenceSample: unknown;
  fixtureScenario: string;
  elapsedMs: number;
  ruleEnabledInDb: boolean;
}

export interface IncidentSummary {
  id: string;
  code: string;
  title: string;
  severity: string;
  status: string;
  hypothesis: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentDetail extends IncidentSummary {
  correlationMeta: { fields: string[]; windowSec: number; host: string; inferred: boolean } | null;
  summary: string | null;
  alerts: {
    id: string;
    ruleId: string;
    ruleName: string;
    severity: string;
    confidence: number;
    status: string;
    summary: string;
    createdAt: string;
  }[];
  notes: { id: string; author: string; body: string; createdAt: string }[];
}

export interface CollectorStatus {
  running: boolean;
  intervalSec: number;
  retentionDays: number;
  lastTickAt: string | null;
  collectorName: string;
}

export interface PipelineRun {
  collected: number;
  stored: number;
  duplicatesSkipped: number;
  alertsCreated: number;
  incidentsCreated: number;
  eventsPruned: number;
  durationMs: number;
  errors: string[];
  stages: { name: string; durationMs: number; input: number; output: number; errors: string[] }[];
}

import { invoke } from "@tauri-apps/api/core";

export const ipc = {
  overviewStats: () => invoke<OverviewStats>("overview_stats"),
  eventsQuery: (args: {
    channel?: string;
    level?: string;
    computer?: string;
    search?: string;
    page?: number;
    pageSize?: number;
  }) => invoke<{ events: EventRow[]; total: number; page: number; pageSize: number }>("events_query", args),
  eventGet: (id: string) => invoke<Record<string, unknown>>("event_get", { id }),
  rulesList: () => invoke<{ rules: RuleSummary[] }>("rules_list"),
  ruleToggle: (id: string, enabled: boolean) => invoke<{ id: string; enabled: boolean }>("rule_toggle", { id, enabled }),
  ruleTest: (id: string) => invoke<RuleTestResult>("rule_test", { id }),
  incidentsList: (args: { status?: string; page?: number; pageSize?: number }) =>
    invoke<{ incidents: IncidentSummary[]; total: number }>("incidents_list", args),
  incidentGet: (id: string) => invoke<IncidentDetail>("incident_get", { id }),
  incidentStatus: (id: string, status: string) => invoke<{ id: string; code: string; status: string }>("incident_status", { id, status }),
  incidentNoteAdd: (id: string, body: string) => invoke<{ id: string }>("incident_note_add", { id, body }),
  collectorStatus: () => invoke<CollectorStatus>("collector_status"),
  collectorStart: () => invoke<{ running: boolean }>("collector_start"),
  collectorStop: () => invoke<{ running: boolean }>("collector_stop"),
  collectorTick: (batchMax?: number) => invoke<{ ok: boolean; run: PipelineRun }>("collector_tick", { batchMax }),
  reportJson: (range: string) => invoke<Record<string, unknown>>("report_json", { range }),
  reportCsv: (scope: "events" | "alerts", range: string) => invoke<string>("report_csv", { scope, range }),
  settingsGet: () => invoke<{ language: string; collectorIntervalSec: number; retentionDays: number; collectorAutoStart: boolean }>("settings_get"),
  settingsSave: (args: { language?: string; collectorIntervalSec?: number; retentionDays?: number; collectorAutoStart?: boolean }) =>
    invoke<{ language: string }>("settings_save", args),
  auditList: (limit?: number) => invoke<{ entries: { actor: string; action: string; target: string | null; detail: string | null; createdAt: string }[] }>("audit_list", { limit }),
};
