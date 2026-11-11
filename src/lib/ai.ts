// SENTINEL DESK 1.0 — AI Gateway (MODULE 08)
//
// Restrictions enforced here (§8):
//  - Reads ONLY the explicitly selected incident's evidence summary
//  - Redacts sensitive values before any model call when privacy mode is on
//  - Records provider, model, timestamp, prompt version, redacted input, output
//  - Cannot execute commands, cannot modify rules, cannot declare compromise

import ZAI from 'z-ai-web-dev-sdk'
import { db } from '@/lib/db'
import type { IncidentRecord } from '@/types/soc'

export const PROMPT_VERSION = 'sd-analyst-v1'

export interface AiContext {
  mode: string
  redaction: boolean
}

/** Redact sensitive values — hostnames, usernames, IPs, long command args. */
export function redactText(text: string): string {
  return text
    .replace(/\b(WS|SRV|DC)-[A-Z0-9]+-\d+\b/gi, '[HOST_REDACTED]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP_REDACTED]')
    .replace(/\b(?:adm|svc)?\.?[a-z]+\.[a-z]{2,10}\b(?=[\s,)]|$)/gi, '[USER_REDACTED]')
    .replace(/(?<=\\)[A-Za-z0-9_\- .]{3,}(?=\.exe|\.ps1|\.dll|\.vbs|\.bat)/gi, '[FILE]')
    .replace(/(-enc\s+)[A-Za-z0-9+/=]{20,}/gi, '$1[BASE64_REDACTED]')
}

export interface EvidenceBundle {
  code: string
  severity: string
  status: string
  hypothesis?: string | null
  alerts: {
    ruleId: string
    title: string
    severity: string
    confidence: number
    summary: string | null
    mitreId?: string | null
  }[]
  events: {
    time: string
    channel: string
    eventId: number
    level: string
    computer: string | null
    userName?: string | null
    processName?: string | null
    commandLine?: string | null
    ipAddress?: string | null
    taskName?: string | null
    serviceName?: string | null
    summary?: string | null
  }[]
  notes: { author: string; body: string | null }[]
}

/** Build the redactable evidence bundle for one incident — nothing else. */
export function buildEvidenceBundle(incident: IncidentRecord & { alerts?: { evidence: unknown }[] & { createdAt?: string }[] }): EvidenceBundle {
  const bundle: EvidenceBundle = {
    code: incident.code,
    severity: incident.severity,
    status: incident.status,
    hypothesis: incident.hypothesis ?? null,
    alerts: (incident.alerts ?? []).map((a) => ({
      ruleId: a.ruleId,
      title: a.title,
      severity: a.severity,
      confidence: a.confidence,
      summary: a.summary,
      mitreId: a.mitreId ?? null,
    })),
    events: [],
    notes: (incident.notes ?? []).filter((n) => n.author !== 'ai').map((n) => ({ author: n.author, body: n.body })),
  }
  return bundle
}

export function applyPrivacy(bundle: EvidenceBundle, redaction: boolean): EvidenceBundle {
  if (!redaction) return bundle
  const r = (s?: string | null) => (s ? redactText(s) : s ?? null)
  return {
    ...bundle,
    hypothesis: r(bundle.hypothesis),
    alerts: bundle.alerts.map((a) => ({ ...a, summary: r(a.summary) })),
    events: bundle.events.map((e) => ({
      ...e,
      computer: r(e.computer),
      userName: r(e.userName),
      processName: r(e.processName),
      commandLine: r(e.commandLine),
      ipAddress: r(e.ipAddress),
      summary: r(e.summary),
    })),
    notes: bundle.notes.map((n) => ({ ...n, body: r(n.body) })),
  }
}

const SYSTEM_PROMPT = `You are the Sentinel Desk AI Security Analyst, part of a local-first SOC investigation tool.
Rules you MUST follow:
1. You analyze ONLY the evidence bundle provided. Never invent events, processes, IPs or users.
2. Your output is advisory. Never declare a "confirmed compromise" — always describe plausibility and uncertainty.
3. Structure your answer in Markdown with exactly these sections:
   ## What likely happened
   ## Evidence supporting this view
   ## Possible benign explanations
   ## MITRE ATT&CK context
   ## Recommended human investigation steps
4. Recommended steps must be manual, safe actions for a human administrator (check logs, verify accounts, review scheduled tasks...). Never suggest running destructive or automated commands.
5. Be concise and factual. Reference specific events (by time and event id) when explaining.
6. Clearly note when evidence is insufficient to conclude anything.`

export interface AiResult {
  provider: string
  model: string
  output: string
  privacyMode: string
  inputSummary: string
}

export async function analyzeIncident(
  bundle: EvidenceBundle,
  ctx: AiContext,
): Promise<AiResult> {
  const userPrompt = [
    `Analyze this incident investigation bundle (Sentinel Desk incident ${bundle.code}).`,
    `Severity: ${bundle.severity} · Status: ${bundle.status}`,
    '',
    'CORRELATION HYPOTHESIS (auto-generated, unverified):',
    bundle.hypothesis ?? '(none)',
    '',
    'ALERTS:',
    ...bundle.alerts.map((a) => `- [${a.ruleId}] ${a.title} (sev=${a.severity}, conf=${a.confidence}%, mitre=${a.mitreId ?? 'n/a'}) — ${a.summary}`),
    '',
    'EVENTS (chronological):',
    ...bundle.events.map((e) => `- ${e.time} | ${e.channel} EID ${e.eventId} | ${e.level} | host=${e.computer ?? '?'} | user=${e.userName ?? '?'} | proc=${e.processName ?? '?'} | ip=${e.ipAddress ?? '-'} | ${e.summary ?? ''}${e.commandLine ? ` | cmd=${e.commandLine}` : ''}`),
    '',
    'ANALYST NOTES:',
    ...bundle.notes.map((n) => `- (${n.author}) ${n.body}`),
    '',
    'Produce the structured analysis now.',
  ].join('\n')

  let provider = 'sandbox-assistant'
  let model = 'glm-4-sandbox'
  let privacyMode = ctx.redaction ? 'redacted' : 'full_evidence'
  let output = ''

  try {
    const zai = await ZAI.create()
    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'assistant', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
      thinking: { type: 'disabled' },
    })
    output = completion.choices[0]?.message?.content ?? ''
    if (!output.trim()) throw new Error('Empty model response')
  } catch {
    // Honest degradation: never fabricate an "AI success"
    provider = 'offline-fallback'
    model = 'deterministic-heuristic'
    output = [
      '## What likely happened',
      '> ⚠️ The AI provider was unavailable. This is a **deterministic fallback summary** assembled from the incident metadata only — it is not a model interpretation.',
      '',
      `Incident ${bundle.code} groups ${bundle.alerts.length} alert(s) at severity **${bundle.severity}**.`,
      bundle.hypothesis ?? '',
      '',
      '## Evidence supporting this view',
      ...bundle.alerts.map((a) => `- ${a.ruleId}: ${a.summary} (confidence ${a.confidence}%)`),
      '',
      '## Possible benign explanations',
      '- Administrative tooling that legitimately touches several detection surfaces in one maintenance window.',
      '- Software deployment or update tasks (verify change tickets before concluding anything).',
      '',
      '## MITRE ATT&CK context',
      ...[...new Set(bundle.alerts.map((a) => a.mitreId).filter(Boolean))].map((m) => `- ${m}`),
      '',
      '## Recommended human investigation steps',
      '1. Review each alert\'s evidence events in the incident timeline.',
      '2. Verify with the system owner whether the processes and tasks are authorized.',
      '3. Check credential hygiene for the involved accounts.',
      '4. Document findings in the incident notes.',
    ].join('\n')
  }

  const inputSummary = userPrompt.slice(0, 2000)

  return { provider, model, output, privacyMode, inputSummary }
}

export async function recordAiAnalysis(params: {
  incidentId: string | null
  kind: string
  result: AiResult
}): Promise<string> {
  const row = await db.aiAnalysis.create({
    data: {
      incidentId: params.incidentId,
      kind: params.kind,
      provider: params.result.provider,
      model: params.result.model,
      privacyMode: params.result.privacyMode,
      promptVersion: PROMPT_VERSION,
      inputSummary: params.result.inputSummary,
      output: params.result.output,
    },
  })
  await db.auditLog.create({
    data: { action: 'ai.analyze', target: params.incidentId ?? 'none', detail: `${params.result.provider}/${params.result.model}` },
  })
  return row.id
}
