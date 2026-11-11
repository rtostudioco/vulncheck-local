// SENTINEL DESK 1.0 — Detection Engine (§7 stage 3)
//
// Evaluates normalized events against the versioned rule catalog. Supports
// three logic kinds:
//   single      — per-event condition matchers
//   threshold   — grouped count within a time window (e.g. 5× 4625 / 5 min)
//   correlation — combinations of prior rule alerts (+ optional direct event
//                 conditions) within a window, linked by shared identifiers
//
// Every match returns the matched evidence (event ids + which fields matched
// with which operator) so the UI can explain WHY a rule fired (§8, §9).

import { RULES_BY_ID, type Condition, type DetectionRuleDef } from './rules'
import type { NormalizedEvent } from './normalizer'
import type { EvidenceMatch, EvidenceRef } from '@/types/soc'

export interface DetectionMatch {
  ruleId: string
  evidence: EvidenceRef[]
  confidence: number
}

interface FieldBag {
  [k: string]: unknown
}

function fieldBag(e: NormalizedEvent): FieldBag {
  return {
    ts: e.ts,
    channel: e.channel,
    eventId: e.eventId,
    level: e.level,
    computer: e.computer,
    userName: e.userName,
    userSid: e.userSid,
    targetUserName: e.targetUserName,
    processId: e.processId,
    processName: e.processName,
    parentProcessName: e.parentProcessName,
    commandLine: e.commandLine,
    ipAddress: e.ipAddress,
    logonType: e.logonType,
    serviceName: e.serviceName,
    taskName: e.taskName,
    summary: e.summary,
  }
}

function checkCondition(cond: Condition, bag: FieldBag): EvidenceMatch | null {
  const value = bag[cond.field]
  if (value === undefined || value === null) return null
  const vs = String(value)
  let ok = false
  switch (cond.op) {
    case 'eq': ok = vs === String(cond.value); break
    case 'neq': ok = vs !== String(cond.value); break
    case 'in': ok = Array.isArray(cond.value) && (cond.value as unknown[]).some((v) => String(v) === vs); break
    case 'contains': ok = vs.toLowerCase().includes(String(cond.value).toLowerCase()); break
    case 'startsWith': ok = vs.toLowerCase().startsWith(String(cond.value).toLowerCase()); break
    case 'regex': ok = safeRegex(String(cond.value), vs); break
    case 'gt': ok = Number(value) > Number(cond.value); break
    case 'lt': ok = Number(value) < Number(cond.value); break
    default: ok = false
  }
  return ok ? { field: cond.field, value: vs.slice(0, 300), op: cond.op } : null
}

function safeRegex(pattern: string, value: string): boolean {
  try {
    // Sigma-style inline flags (e.g. "(?i)") are not valid JS RegExp syntax —
    // convert them to constructor flags so rules stay portable.
    let flags = ''
    let p = pattern
    const m = /^\(\?([a-z]+)\)/.exec(p)
    if (m) {
      flags = m[1].replace(/[^imsu]/g, '')
      p = p.slice(m[0].length)
    }
    return new RegExp(p, flags).test(value)
  } catch {
    return false
  }
}

function checkEvent(def: DetectionRuleDef, e: NormalizedEvent): EvidenceRef | null {
  const logic = def.logic
  if (logic.eventIds && !logic.eventIds.includes(e.eventId)) return null
  if (logic.channel && e.channel !== logic.channel) return null
  if (logic.channels && !logic.channels.includes(e.channel)) return null
  const bag = fieldBag(e)
  const matched: EvidenceMatch[] = []
  for (const cond of logic.conditions ?? []) {
    const m = checkCondition(cond, bag)
    if (!m) return null // all conditions must match (AND)
    matched.push(m)
  }
  return { eventId: e.id ?? 'unknown', matched }
}

/**
 * Evaluate "single" and "threshold" rules over a window of events.
 * `events` should be pre-filtered to a reasonable evaluation window.
 */
export function evaluateRules(
  defs: DetectionRuleDef[],
  events: NormalizedEvent[],
  now: Date = new Date(),
): DetectionMatch[] {
  const matches: DetectionMatch[] = []

  for (const def of defs) {
    const logic = def.logic
    if (logic.kind === 'correlation') continue // handled by correlation stage

    if (logic.kind === 'single') {
      for (const e of events) {
        const ev = checkEvent(def, e)
        if (ev) {
          matches.push({ ruleId: def.id, evidence: [ev], confidence: def.confidence })
        }
      }
      continue
    }

    // threshold
    const th = logic.threshold!
    const groups = new Map<string, NormalizedEvent[]>()
    for (const e of events) {
      const ev = checkEvent(def, e)
      if (!ev) continue
      const key = th.groupBy.map((f) => String(fieldBag(e)[f] ?? '')).join('|')
      const list = groups.get(key) ?? []
      list.push(e)
      groups.set(key, list)
    }
    for (const [key, group] of groups) {
      // sliding-window count within the group
      const sorted = [...group].sort((a, b) => a.ts.getTime() - b.ts.getTime())
      for (let i = 0; i < sorted.length; i++) {
        const inWindow = sorted.filter(
          (x) => x.ts.getTime() >= sorted[i].ts.getTime() &&
                 x.ts.getTime() <= sorted[i].ts.getTime() + th.windowSec * 1000,
        )
        if (inWindow.length >= th.count) {
          const evidence: EvidenceRef[] = inWindow.map((e) => ({
            eventId: e.id ?? 'unknown',
            matched: [
              { field: 'eventId', value: String(e.eventId), op: 'eq' },
              { field: 'computer', value: e.computer, op: 'eq' },
              ...(e.targetUserName ? [{ field: 'targetUserName', value: e.targetUserName, op: 'in' }] : []),
              ...(e.ipAddress ? [{ field: 'ipAddress', value: e.ipAddress, op: 'eq' }] : []),
            ],
          }))
          matches.push({
            ruleId: def.id,
            evidence,
            confidence: Math.min(95, def.confidence + inWindow.length - th.count),
          })
          const host = key.split('|')[0] || 'host'
          void host
          break // one match per group
        }
      }
    }
  }

  void now
  return matches
}

/**
 * Correlation stage: combine prior alerts (from signal rules) and, for rules
 * with direct event conditions, matching events — all linked by shared fields
 * within a time window. Returns matches whose evidence lists BOTH the
 * contributing alerts' events and the matched link fields.
 */
export function evaluateCorrelations(
  defs: DetectionRuleDef[],
  priorMatches: DetectionMatch[],
  events: NormalizedEvent[],
  now: Date = new Date(),
): DetectionMatch[] {
  const matches: DetectionMatch[] = []
  const matchByRule = new Map<string, DetectionMatch[]>()
  for (const m of priorMatches) {
    const list = matchByRule.get(m.ruleId) ?? []
    list.push(m)
    matchByRule.set(m.ruleId, list)
  }

  for (const def of defs) {
    const logic = def.logic
    if (logic.kind !== 'correlation') continue
    const windowMs = (logic.correlationWindowSec ?? 900) * 1000
    const hostKey = (e: NormalizedEvent) => e.computer

    // Resolve required signals
    const signalSpecs = logic.signals ?? []
    const wildcard = signalSpecs.find((s) => s.ruleId === '*')
    const explicit = signalSpecs.filter((s) => s.ruleId !== '*')

    // Pre-index: which prior matches fall on each host (cheap window queries)
    const eventsById = new Map(events.map((e) => [e.id ?? '', e]))

    const priorInWindow = (anchorStart: number, anchorEnd: number, host: string) => {
      const perRule = new Map<string, DetectionMatch[]>()
      for (const m of priorMatches) {
        if (m.ruleId === def.id) continue
        const evs = m.evidence
          .map((ev) => eventsById.get(ev.eventId))
          .filter((e): e is NormalizedEvent => Boolean(e))
        const inWindow = evs.some((e) =>
          hostKey(e) === host &&
          e.ts.getTime() >= anchorStart - windowMs &&
          e.ts.getTime() <= anchorEnd + windowMs)
        if (inWindow) {
          const list = perRule.get(m.ruleId) ?? []
          list.push(m)
          perRule.set(m.ruleId, list)
        }
      }
      return perRule
    }

    const produced = new Set<string>()
    // Anchors: any signal-rule match can anchor a candidate correlation
    const anchorMatches = wildcard
      ? priorMatches
      : explicit.flatMap((s) => matchByRule.get(s.ruleId) ?? [])

    for (const anchor of anchorMatches) {
      const anchorEvents = events.filter((e) => anchor.evidence.some((ev) => ev.eventId === (e.id ?? '')))
      if (anchorEvents.length === 0) continue
      const anchorStart = Math.min(...anchorEvents.map((e) => e.ts.getTime()))
      const anchorEnd = Math.max(...anchorEvents.map((e) => e.ts.getTime()))
      const anchorHost = hostKey(anchorEvents[0])

      const windowEvents = events.filter((e) => {
        if (hostKey(e) !== anchorHost) return false
        return e.ts.getTime() >= anchorStart - windowMs && e.ts.getTime() <= anchorEnd + windowMs
      })

      // Which signal rules have at least one match inside the window?
      const perRule = priorInWindow(anchorStart, anchorEnd, anchorHost)

      // Direct event conditions on this correlation rule itself (e.g. SD-002's 4624)
      const directEvidence: EvidenceRef[] = []
      if (logic.eventIds) {
        for (const e of windowEvents) {
          const ev = checkEvent(def, e)
          if (ev) directEvidence.push(ev)
        }
      }

      let satisfied = false
      if (wildcard) {
        satisfied = perRule.size >= (wildcard.minCount ?? 1)
      } else {
        satisfied = explicit.every((s) => (perRule.get(s.ruleId)?.length ?? 0) >= (s.minCount ?? 1))
        if (satisfied && logic.eventIds && directEvidence.length === 0) satisfied = false
      }
      if (!satisfied) continue

      const evidence: EvidenceRef[] = [
        ...anchor.evidence,
        ...[...perRule.values()].flatMap((list) => list.flatMap((m) => m.evidence)),
        ...directEvidence,
      ]
      // Deduplicate by eventId, merging matched fields
      const merged = new Map<string, EvidenceRef>()
      for (const ev of evidence) {
        const existing = merged.get(ev.eventId)
        if (existing) {
          const fields = new Map(existing.matched.map((m) => [m.field, m]))
          for (const m of ev.matched) fields.set(m.field, m)
          existing.matched = [...fields.values()]
        } else {
          merged.set(ev.eventId, { ...ev })
        }
      }

      // Avoid emitting duplicate matches from different anchors covering the
      // same evidence set
      const fingerprint = [...merged.keys()].sort().join('|')
      if (produced.has(fingerprint)) continue
      produced.add(fingerprint)

      matches.push({
        ruleId: def.id,
        evidence: [...merged.values()],
        confidence: def.confidence,
      })
    }
  }

  void now
  return matches
}

/** Human-readable explanation of why a rule matched (for alerts/UI). */
export function explainMatch(def: DetectionRuleDef, evidence: EvidenceRef[]): string {
  const n = evidence.length
  const link = def.logic.linkBy?.join(', ') ?? def.logic.threshold?.groupBy.join(', ') ?? 'time'
  if (def.logic.kind === 'correlation') {
    const signals = (def.logic.signals ?? []).map((s) => s.ruleId === '*' ? 'any rule' : s.ruleId).join(' + ')
    return `${n} evidence event(s) linked by ${link} within ${def.logic.correlationWindowSec ?? 0}s — signals: ${signals}`
  }
  if (def.logic.kind === 'threshold') {
    const th = def.logic.threshold!
    return `${n} matching event(s) ≥ threshold ${th.count} in ${th.windowSec}s grouped by ${th.groupBy.join(', ')}`
  }
  const fields = [...new Set(evidence.flatMap((e) => e.matched.map((m) => m.field)))]
  if (fields.length === 0) {
    const ids = def.logic.eventIds?.join('/') ?? 'any'
    const channels = def.logic.channels?.join(', ') ?? def.logic.channel ?? 'any channel'
    return `Event ID ${ids} observed on channel: ${channels}`
  }
  return `Event matched conditions on: ${fields.join(', ')}`
}
