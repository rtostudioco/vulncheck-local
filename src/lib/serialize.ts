// SENTINEL DESK 1.0 — DB row → API contract serializers

import type {
  Event, Alert, DetectionRule, Incident, IncidentNote, AiAnalysis,
  EventSource, Prisma,
} from '@prisma/client'
import type {
  AlertRecord, EventRecord, IncidentRecord, RuleSummary, SourceRecord,
  IncidentNoteRecord, AiAnalysisRecord, EvidenceRef,
} from '@/types/soc'

type AlertWithRefs = Prisma.AlertGetPayload<{ include: { rule: true; events: { include: { event: true } } } }>

export function serializeEvent(e: Event): EventRecord {
  return {
    id: e.id,
    ts: e.ts.toISOString(),
    channel: e.channel,
    provider: e.provider,
    eventId: e.eventId,
    level: e.level,
    computer: e.computer,
    recordId: e.recordId,
    userName: e.userName,
    targetUserName: e.targetUserName,
    processId: e.processId,
    processName: e.processName,
    parentProcessId: e.parentProcessId,
    parentProcessName: e.parentProcessName,
    commandLine: e.commandLine,
    ipAddress: e.ipAddress,
    logonType: e.logonType,
    serviceName: e.serviceName,
    taskName: e.taskName,
    summary: e.summary,
    synthetic: e.synthetic,
    sourceRef: e.sourceRef,
  }
}

export function serializeRule(r: DetectionRule, alertCount?: number): RuleSummary {
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    version: r.version,
    author: r.author,
    severity: r.severity as RuleSummary['severity'],
    category: r.category,
    mitreId: r.mitreId,
    mitreName: r.mitreName,
    enabled: r.enabled,
    falsePositives: r.falsePositives,
    limitations: r.limitations,
    evidenceFields: r.evidenceFields,
    alertCount,
    logic: r.logic ? JSON.parse(r.logic) : undefined,
  }
}

export function serializeAlert(a: AlertWithRefs): AlertRecord {
  return {
    id: a.id,
    ruleId: a.ruleId,
    severity: a.severity as AlertRecord['severity'],
    title: a.title,
    summary: a.summary,
    confidence: a.confidence,
    status: a.status as AlertRecord['status'],
    evidence: JSON.parse(a.evidence) as EvidenceRef[],
    mitreId: a.mitreId,
    computer: a.computer,
    userName: a.userName,
    incidentId: a.incidentId,
    createdAt: a.createdAt.toISOString(),
    rule: serializeRule(a.rule),
  }
}

export function serializeNote(n: IncidentNote): IncidentNoteRecord {
  return {
    id: n.id,
    incidentId: n.incidentId,
    author: n.author as IncidentNoteRecord['author'],
    body: n.body,
    createdAt: n.createdAt.toISOString(),
  }
}

export function serializeAi(a: AiAnalysis): AiAnalysisRecord {
  return {
    id: a.id,
    incidentId: a.incidentId,
    kind: a.kind,
    provider: a.provider,
    model: a.model,
    privacyMode: a.privacyMode,
    promptVersion: a.promptVersion,
    inputSummary: a.inputSummary,
    output: a.output,
    createdAt: a.createdAt.toISOString(),
  }
}

export function serializeSource(s: EventSource): SourceRecord {
  return {
    id: s.id,
    channel: s.channel,
    displayName: s.displayName,
    description: s.description,
    status: s.status as SourceRecord['status'],
    available: s.available,
    requiresAdmin: s.requiresAdmin,
    note: s.note,
    lastCollectAt: s.lastCollectAt?.toISOString() ?? null,
    eventsCollected: s.eventsCollected,
  }
}

export function serializeIncident(
  i: Prisma.IncidentGetPayload<{ include: { alerts: { include: { rule: true } }, notes: true, aiAnalyses: true } }>,
): IncidentRecord {
  return {
    id: i.id,
    code: i.code,
    title: i.title,
    severity: i.severity as IncidentRecord['severity'],
    status: i.status as IncidentRecord['status'],
    hypothesis: i.hypothesis,
    correlationMeta: i.correlationMeta ? JSON.parse(i.correlationMeta) : null,
    summary: i.summary,
    createdAt: i.createdAt.toISOString(),
    updatedAt: i.updatedAt.toISOString(),
    alerts: i.alerts.map((a) => serializeAlert(a as unknown as AlertWithRefs)),
    notes: i.notes.map(serializeNote).sort((a, b) => a.createdAt.localeCompare(b.createdAt)),
    aiAnalyses: i.aiAnalyses.map(serializeAi).sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
  }
}
