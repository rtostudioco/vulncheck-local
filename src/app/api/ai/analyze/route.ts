import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap, getSettings } from '@/lib/bootstrap'
import { serializeIncident } from '@/lib/serialize'
import { buildEvidenceBundle, applyPrivacy, analyzeIncident, recordAiAnalysis } from '@/lib/ai'

export const dynamic = 'force-dynamic'
export const maxDuration = 60

export async function POST(req: NextRequest) {
  try {
    await ensureBootstrap()
    const body = (await req.json()) as { incidentId?: string }
    if (!body.incidentId) return NextResponse.json({ error: 'incident_required' }, { status: 400 })

    const settings = await getSettings()
    const aiMode = (settings.aiMode as string) ?? 'sandbox'
    if (aiMode === 'off') {
      return NextResponse.json({ error: 'ai_disabled' }, { status: 409 })
    }

    const row = await db.incident.findUnique({
      where: { id: body.incidentId },
      include: { alerts: { include: { rule: true, events: { include: { event: true } } } }, notes: true, aiAnalyses: true },
    })
    if (!row) return NextResponse.json({ error: 'not_found' }, { status: 404 })
    const incident = serializeIncident(row)

    // Populate the bundle with the incident's own evidence events only
    const bundle = buildEvidenceBundle(incident)
    const seen = new Set<string>()
    for (const alert of incident.alerts ?? []) {
      for (const evRef of alert.evidence ?? []) {
        if (seen.has(evRef.eventId)) continue
        seen.add(evRef.eventId)
        const ev = await db.event.findUnique({ where: { id: evRef.eventId } })
        if (!ev) continue
        bundle.events.push({
          time: ev.ts.toISOString(),
          channel: ev.channel,
          eventId: ev.eventId,
          level: ev.level,
          computer: ev.computer,
          userName: ev.userName ?? ev.targetUserName,
          processName: ev.processName,
          commandLine: ev.commandLine,
          ipAddress: ev.ipAddress,
          taskName: ev.taskName,
          serviceName: ev.serviceName,
          summary: ev.summary,
        })
      }
    }
    bundle.events.sort((a, b) => a.time.localeCompare(b.time))

    const redaction = settings.aiRedaction !== false
    const privateBundle = applyPrivacy(bundle, redaction)
    const result = await analyzeIncident(privateBundle, { mode: aiMode, redaction })
    const id = await recordAiAnalysis({ incidentId: body.incidentId, kind: 'incident_summary', result })

    return NextResponse.json({
      analysis: {
        id,
        incidentId: body.incidentId,
        kind: 'incident_summary',
        provider: result.provider,
        model: result.model,
        privacyMode: result.privacyMode,
        promptVersion: 'sd-analyst-v1',
        inputSummary: result.inputSummary,
        output: result.output,
        createdAt: new Date().toISOString(),
      },
      sentBundle: privateBundle, // privacy preview: exactly what the model received
    })
  } catch (err) {
    console.error('ai analyze error', err)
    return NextResponse.json({ error: 'ai_failed' }, { status: 500 })
  }
}
