// SENTINEL DESK 1.0 — Pipeline orchestrator (§7 mandatory data flow)
//
// 1. collector    — reads the (synthetic) authorized event channels
// 2. normalizer   — converts raw records into the common schema, persists
// 3. detection    — evaluates versioned rules → alerts with evidence refs
// 4. correlation  — combines signals across time/host identifiers
// 5. incidents    — groups correlated alerts into investigation cases
//
// Every stage reports status, input/output counts, errors and duration.
// Events never disappear silently: failed items land in stage.errors.

import { db } from '@/lib/db'
import { generateBatch, type RawWindowsEvent } from './generator'
import { normalizeBatch } from './normalizer'
import { evaluateRules, evaluateCorrelations, explainMatch } from './detection'
import { DETECTION_RULES, type DetectionRuleDef } from './rules'
import type { PipelineRun, PipelineStageStat, Severity } from '@/types/soc'

// ─── In-memory collector state (per server process) ─────────────────────────

export interface CollectorState {
  running: boolean
  lastTickAt: string | null
  lastRun: PipelineRun | null
  intervalSec: number
}

const g = globalThis as unknown as { __sentinelCollector?: CollectorState }
export const collector: CollectorState = g.__sentinelCollector ?? {
  running: false,
  lastTickAt: null,
  lastRun: null,
  intervalSec: 20,
}
g.__sentinelCollector = collector

function stage(name: string, t0: number, input: number, output: number, errors: string[]): PipelineStageStat {
  return {
    stage: name,
    status: errors.length ? 'error' : 'ok',
    input,
    output,
    errors,
    durationMs: Math.max(1, Math.round(performance.now() - t0)),
  }
}

// ─── Alert persistence ──────────────────────────────────────────────────────

interface AlertDraft {
  rule: DetectionRuleDef
  evidence: { eventId: string; matched: { field: string; value: string; op: string }[] }[]
  confidence: number
  severity: Severity
  title: string
  summary: string
  computer: string
  userName?: string
}

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

function worstSeverity(defs: DetectionRuleDef[]): Severity {
  return defs.reduce<Severity>((acc, d) => (SEV_RANK[d.severity] > SEV_RANK[acc] ? d.severity : acc), 'info')
}

async function persistAlerts(drafts: AlertDraft[]): Promise<string[]> {
  const ids: string[] = []
  for (const d of drafts) {
    const alert = await db.alert.create({
      data: {
        ruleId: d.rule.id,
        severity: d.severity,
        title: d.title,
        summary: d.summary,
        confidence: d.confidence,
        status: 'open',
        evidence: JSON.stringify(d.evidence),
        mitreId: d.rule.mitreId ?? null,
        computer: d.computer,
        userName: d.userName ?? null,
      },
    })
    await db.alertEvent.createMany({
      data: [...new Set(d.evidence.map((e) => e.eventId))].map((eventId) => ({ alertId: alert.id, eventId })),
    })
    ids.push(alert.id)
  }
  return ids
}

// ─── Incident engine (MODULE 05) ────────────────────────────────────────────

async function nextIncidentCode(): Promise<string> {
  const count = await db.incident.count()
  return `INC-${String(count + 1).padStart(4, '0')}`
}

async function groupIncidents(alertIds: string[]): Promise<{ id: string; code: string; title: string; severity: string }[]> {
  if (alertIds.length === 0) return []
  const created: { id: string; code: string; title: string; severity: string }[] = []
  const alerts = await db.alert.findMany({
    where: { id: { in: alertIds }, incidentId: null },
    include: { rule: true },
  })
  if (alerts.length === 0) return []

  // Group candidate alerts by computer
  const byHost = new Map<string, typeof alerts>()
  for (const a of alerts) {
    const host = a.computer ?? 'unknown'
    const list = byHost.get(host) ?? []
    list.push(a)
    byHost.set(host, list)
  }

  const incidentWindowMs = 20 * 60 * 1000 // § MODULE 04 configurable window

  for (const [host, list] of byHost) {
    const sorted = list.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
    const cluster: typeof sorted = []
    const clusterBase = sorted[0].createdAt.getTime()

    for (const a of sorted) {
      if (a.createdAt.getTime() - clusterBase <= incidentWindowMs) cluster.push(a)
    }
    if (cluster.length === 0) continue

    // Incident creation policy: high/critical alerts always open a case;
    // medium/low cluster only when 2+ distinct rules converge.
    const topSev = cluster.reduce<Severity>((acc, a) => (SEV_RANK[a.severity as Severity] > SEV_RANK[acc] ? a.severity as Severity : acc), 'info')
    const distinctRules = new Set(cluster.map((a) => a.ruleId))
    if (SEV_RANK[topSev] < 3 && distinctRules.size < 2) continue

    const anchor = cluster.find((a) => a.severity === topSev) ?? cluster[0]
    const code = await nextIncidentCode()
    const title = anchor.title

    const incident = await db.incident.create({
      data: {
        code,
        title,
        severity: topSev,
        status: 'new',
        hypothesis: `Correlation hypothesis — NOT a confirmed compromise. ${distinctRules.size} distinct rule match(es) (${[...distinctRules].join(', ')}) on ${host} grouped within the ${Math.round(incidentWindowMs / 1000)}s correlation window. Linked by: computer. A human analyst must verify causation.`,
        correlationMeta: JSON.stringify({
          fields: ['computer'],
          windowSec: Math.round(incidentWindowMs / 1000),
          host,
          inferred: true,
        }),
        summary: null,
      },
    })

    await db.alert.updateMany({
      where: { id: { in: cluster.map((a) => a.id) } },
      data: { incidentId: incident.id, status: 'linked_to_incident' },
    })

    await db.incidentNote.create({
      data: {
        incidentId: incident.id,
        author: 'system',
        body: `Incident opened automatically by the incident engine. ${cluster.length} alert(s) grouped on host ${host} — linked fields: computer · correlation window: ${Math.round(incidentWindowMs / 1000)}s. Review each alert's evidence in the timeline before drawing conclusions.`,
      },
    })

    await db.auditLog.create({
      data: { action: 'incident.create', target: code, detail: `${cluster.length} alerts on ${host}` },
    })

    created.push({ id: incident.id, code, title, severity: topSev })
  }

  return created
}

// ─── Main tick ──────────────────────────────────────────────────────────────

export async function runPipelineTick(opts: {
  batches?: number
  scenarioKey?: string
  seed?: number
} = {}): Promise<PipelineRun> {
  const startedAt = new Date()
  const t0 = performance.now()
  const stages: PipelineStageStat[] = []
  let eventsIn = 0
  let alertsOut = 0
  let incidentsOut = 0

  // STAGE 1 — collector
  const tCol = performance.now()
  let raws: RawWindowsEvent[] = []
  const colErrors: string[] = []
  try {
    raws = generateBatch(opts)
  } catch (err) {
    colErrors.push(`collector: ${err instanceof Error ? err.message : String(err)}`)
  }
  eventsIn = raws.length
  stages.push(stage('collector', tCol, 0, raws.length, colErrors))

  // STAGE 2 — normalizer + persistence
  const tNorm = performance.now()
  const normalized = normalizeBatch(raws)
  const normErrors: string[] = []
  const eventIds: string[] = []
  for (const ev of normalized) {
    try {
      const row = await db.event.create({
        data: {
          ts: ev.ts,
          channel: ev.channel,
          provider: ev.provider,
          eventId: ev.eventId,
          level: ev.level,
          computer: ev.computer,
          recordId: ev.recordId,
          userName: ev.userName,
          userSid: ev.userSid,
          targetUserName: ev.targetUserName,
          processId: ev.processId,
          processName: ev.processName,
          parentProcessId: ev.parentProcessId,
          parentProcessName: ev.parentProcessName,
          commandLine: ev.commandLine,
          ipAddress: ev.ipAddress,
          logonType: ev.logonType,
          serviceName: ev.serviceName,
          taskName: ev.taskName,
          summary: ev.summary,
          raw: ev.raw,
          synthetic: true,
          sourceRef: ev.sourceRef,
        },
      })
      eventIds.push(row.id)
    } catch (err) {
      normErrors.push(`persist ${ev.sourceRef}: ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  stages.push(stage('normalize+persist', tNorm, normalized.length, eventIds.length, normErrors))

  // STAGE 3 — detection (single + threshold rules)
  const tDet = performance.now()
  const detErrors: string[] = []
  const nowDate = new Date()
  const evalEvents = normalized.map((ev, i) => ({ ...ev, id: eventIds[i] ?? `missing-${i}`, ts: ev.ts }))
  const enabledDefs = DETECTION_RULES.filter((r) => r.logic.kind !== 'correlation')
  const enabledRows = await db.detectionRule.findMany({ where: { enabled: true } })
  const enabledIds = new Set(enabledRows.map((r) => r.id))

  let singleMatches: ReturnType<typeof evaluateRules> = []
  try {
    singleMatches = evaluateRules(
      enabledDefs.filter((d) => enabledIds.has(d.id)),
      evalEvents,
      nowDate,
    )
  } catch (err) {
    detErrors.push(`detection: ${err instanceof Error ? err.message : String(err)}`)
  }
  stages.push(stage('detection', tDet, evalEvents.length, singleMatches.length, detErrors))

  // STAGE 4 — correlation
  const tCor = performance.now()
  const corErrors: string[] = []
  let correlationMatches: ReturnType<typeof evaluateCorrelations> = []
  try {
    const corDefs = DETECTION_RULES.filter((r) => r.logic.kind === 'correlation' && enabledIds.has(r.id))
    // Prior matches may come from alerts created in the last minutes (persistence across ticks)
    const recentCutoff = new Date(nowDate.getTime() - 30 * 60 * 1000)
    const recentAlerts = await db.alert.findMany({
      where: { createdAt: { gte: recentCutoff }, ruleId: { in: [...enabledIds] } },
      include: { events: true },
    })
    const priorFromDb: typeof singleMatches = recentAlerts.map((a) => ({
      ruleId: a.ruleId,
      evidence: (JSON.parse(a.evidence) as { eventId: string }[]).map((e) => ({ eventId: e.eventId, matched: [] })),
      confidence: a.confidence,
    }))
    const seenDb = new Set(priorFromDb.map((m) => m.evidence.map((e) => e.eventId).join(',')))
    const dedupedNew = singleMatches.filter((m) => !seenDb.has(m.evidence.map((e) => e.eventId).join(',')))
    correlationMatches = evaluateCorrelations(
      corDefs,
      [...priorFromDb, ...dedupedNew],
      evalEvents,
      nowDate,
    )
  } catch (err) {
    corErrors.push(`correlation: ${err instanceof Error ? err.message : String(err)}`)
  }
  stages.push(stage('correlation', tCor, singleMatches.length, correlationMatches.length, corErrors))

  // STAGE 4b — persist alerts (single + correlation)
  const tPersist = performance.now()
  const persistErrors: string[] = []
  const drafts: AlertDraft[] = []
  for (const m of [...singleMatches, ...correlationMatches]) {
    const def = DETECTION_RULES.find((r) => r.id === m.ruleId)
    if (!def) continue
    const evs = evalEvents.filter((e) => m.evidence.some((ev) => ev.eventId === e.id))
    const computer = evs[0]?.computer ?? 'unknown'
    const user = evs.map((e) => e.targetUserName ?? e.userName).find(Boolean)
    drafts.push({
      rule: def,
      evidence: m.evidence,
      confidence: m.confidence,
      severity: def.severity,
      title: `${def.id} · ${def.name}`,
      summary: explainMatch(def, m.evidence),
      computer,
      userName: user,
    })
  }
  // dedupe identical rule+evidence-set drafts
  const seen = new Set<string>()
  const uniqueDrafts = drafts.filter((d) => {
    const key = d.rule.id + '::' + [...new Set(d.evidence.map((e) => e.eventId))].sort().join(',')
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
  let alertIds: string[] = []
  try {
    alertIds = await persistAlerts(uniqueDrafts)
    alertsOut = alertIds.length
  } catch (err) {
    persistErrors.push(`alerts: ${err instanceof Error ? err.message : String(err)}`)
  }
  stages.push(stage('alert-persist', tPersist, uniqueDrafts.length, alertIds.length, persistErrors))

  // STAGE 5 — incident grouping
  const tInc = performance.now()
  const incErrors: string[] = []
  let incidentIds: { id: string; code: string; title: string; severity: string }[] = []
  try {
    incidentIds = await groupIncidents(alertIds)
    incidentsOut = incidentIds.length
  } catch (err) {
    incErrors.push(`incidents: ${err instanceof Error ? err.message : String(err)}`)
  }
  stages.push(stage('incident-engine', tInc, alertIds.length, incidentIds.length, incErrors))

  // STAGE 6 — source health + retention
  const tHealth = performance.now()
  const healthErrors: string[] = []
  try {
    const byChannel = new Map<string, number>()
    for (const ev of normalized) byChannel.set(ev.channel, (byChannel.get(ev.channel) ?? 0) + 1)
    const now = new Date()
    for (const [channel, n] of byChannel) {
      const src = await db.eventSource.findUnique({ where: { channel } })
      if (src) {
        await db.eventSource.update({
          where: { channel },
          data: { lastCollectAt: now, eventsCollected: { increment: n } },
        })
      }
    }
    // retention
    const settings = await db.setting.findUnique({ where: { key: 'app' } })
    const retentionDays = settings ? (JSON.parse(settings.value).retentionDays ?? 7) : 7
    const cutoff = new Date(now.getTime() - retentionDays * 24 * 3600 * 1000)
    const old = await db.event.deleteMany({ where: { ts: { lt: cutoff } } })
    if (old.count > 0) {
      // clean orphaned evidence links & alerts whose events were pruned
      await db.$executeRawUnsafe(
        `DELETE FROM AlertEvent WHERE eventId NOT IN (SELECT id FROM Event)`,
      ).catch(() => undefined)
    }
  } catch (err) {
    healthErrors.push(`health/retention: ${err instanceof Error ? err.message : String(err)}`)
  }
  stages.push(stage('source-health', tHealth, 0, 0, healthErrors))

  const run: PipelineRun = {
    startedAt: startedAt.toISOString(),
    durationMs: Math.max(1, Math.round(performance.now() - t0)),
    stages,
    eventsIn,
    alertsOut,
    incidentsOut,
    newAlerts: uniqueDrafts.filter((_, i) => alertIds.includes(alertIds[i])).map((d, i) => ({
      alertId: alertIds[i], ruleId: d.rule.id, title: d.title, severity: d.severity, summary: d.summary,
    })),
    newIncidents: incidentIds,
  }

  collector.lastTickAt = nowDate.toISOString()
  collector.lastRun = run

  return run
}

/** Rule test harness (MODULE 03 test cases): force a scenario and evaluate one rule. */
export async function testRule(ruleId: string): Promise<{
  matched: boolean
  matchCount: number
  fixtureEvents: number
  explanation?: string
  evidenceSample?: unknown
}> {
  const def = DETECTION_RULES.find((r) => r.id === ruleId)
  if (!def) throw new Error(`Unknown rule ${ruleId}`)

  const scenarioKey = SCENARIO_FOR_RULE[ruleId] ?? 'benign_noise'
  const raws = generateBatch({ batches: 2, scenarioKey, seed: 42, spanMinutes: 2 })
  const normalized = normalizeBatch(raws)
  const events = normalized.map((ev, i) => ({ ...ev, id: `test-${i}`, ts: ev.ts }))

  let matches = evaluateRules([def], events, new Date())

  if (matches.length === 0 && def.logic.kind === 'correlation') {
    // Correlation rules need prior matches from their signal rules
    const baseDefs = DETECTION_RULES.filter((r) => r.logic.kind !== 'correlation' && r.id !== ruleId)
    const prior = evaluateRules(baseDefs, events, new Date())
    matches = evaluateCorrelations([def], prior, events, new Date())
  }

  return {
    matched: matches.length > 0,
    matchCount: matches.length,
    fixtureEvents: events.length,
    explanation: matches.length
      ? explainMatch(def, matches[0].evidence)
      : `No match against fixture "${scenarioKey}". ${def.limitations}`,
    evidenceSample: matches[0]?.evidence?.slice(0, 4),
  }
}

const SCENARIO_FOR_RULE: Record<string, string> = {
  'SD-001': 'brute_force',
  'SD-002': 'brute_force',
  'SD-003': 'powershell_cradle',
  'SD-004': 'task_persistence',
  'SD-005': 'service_install_userpath',
  'SD-006': 'audit_tamper',
  'SD-007': 'service_install_userpath',
  'SD-008': 'lolbin_network',
  'SD-009': 'persistence_chain',
  'SD-010': 'persistence_chain',
}
