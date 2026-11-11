import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap, getSettings } from '@/lib/bootstrap'
import { collector } from '@/lib/engine/pipeline'
import { createHash } from 'crypto'

export const dynamic = 'force-dynamic'

const RANGES: Record<string, number> = { '24h': 1, '7d': 7, '30d': 30 }

function csvEscape(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v)
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/**
 * SOC REPORTS (MODULE 10)
 * format=json → full structured report with integrity metadata
 * format=csv&scope=events|alerts → tabular export (bounded)
 * Report NEVER represents synthetic demo collection as complete coverage.
 */
export async function GET(req: NextRequest) {
  try {
    await ensureBootstrap()
    const sp = req.nextUrl.searchParams
    const format = sp.get('format') ?? 'json'
    const range = sp.get('range') ?? '7d'
    const scope = sp.get('scope') ?? 'events'

    const days = RANGES[range] ?? 7
    const since = range === 'all' ? new Date(0) : new Date(Date.now() - days * 24 * 3600 * 1000)
    const now = new Date()

    if (format === 'csv') {
      if (scope === 'alerts') {
        const alerts = await db.alert.findMany({
          where: { createdAt: { gte: since } },
          include: { rule: true },
          orderBy: { createdAt: 'desc' },
          take: 5000,
        })
        const header = ['id', 'createdAt', 'ruleId', 'ruleName', 'severity', 'confidence', 'status', 'computer', 'userName', 'mitreId', 'summary']
        const lines = [header.join(',')]
        for (const a of alerts) {
          lines.push([
            a.id, a.createdAt.toISOString(), a.ruleId, a.rule.name, a.severity,
            a.confidence, a.status, a.computer ?? '', a.userName ?? '', a.mitreId ?? '', a.summary,
          ].map(csvEscape).join(','))
        }
        return new NextResponse(lines.join('\n'), {
          headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': `attachment; filename="sentinel-alerts-${range}.csv"`,
          },
        })
      }
      const events = await db.event.findMany({
        where: { ts: { gte: since } },
        orderBy: { ts: 'desc' },
        take: 5000,
      })
      const header = ['id', 'ts', 'channel', 'provider', 'eventId', 'level', 'computer', 'userName', 'targetUserName', 'processName', 'commandLine', 'ipAddress', 'serviceName', 'taskName', 'summary', 'synthetic', 'sourceRef']
      const lines = [header.join(',')]
      for (const e of events) {
        lines.push([
          e.id, e.ts.toISOString(), e.channel, e.provider, e.eventId, e.level, e.computer,
          e.userName ?? '', e.targetUserName ?? '', e.processName ?? '', e.commandLine ?? '',
          e.ipAddress ?? '', e.serviceName ?? '', e.taskName ?? '', e.summary ?? '',
          e.synthetic, e.sourceRef ?? '',
        ].map(csvEscape).join(','))
      }
      return new NextResponse(lines.join('\n'), {
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="sentinel-events-${range}.csv"`,
        },
      })
    }

    // JSON report
    const [sources, rules, alerts, incidents] = await Promise.all([
      db.eventSource.findMany({ orderBy: { channel: 'asc' } }),
      db.detectionRule.findMany({ orderBy: { id: 'asc' } }),
      db.alert.findMany({
        where: { createdAt: { gte: since } },
        include: { rule: true },
        orderBy: { createdAt: 'desc' },
        take: 1000,
      }),
      db.incident.findMany({
        where: { createdAt: { gte: since } },
        include: { alerts: { include: { rule: true } }, notes: true, aiAnalyses: true },
        orderBy: { createdAt: 'desc' },
        take: 200,
      }),
    ])

    const payload = {
      report: {
        product: 'Sentinel Desk',
        version: '1.0.0',
        generatedAt: now.toISOString(),
        range: { from: since.toISOString(), to: now.toISOString(), label: range },
        collectionLimitations: {
          sourceType: 'synthetic_demo',
          statement: 'This build collects NO real Windows telemetry. All events originate from the clearly labeled synthetic fixture source (synthetic=true). Incomplete or demo collection is never represented as complete coverage.',
          adminRequiredChannels: ['Security (partial, depending on audit policy)'],
          unavailableChannels: ['Sysmon (optional, not assumed installed)'],
        },
        pipeline: collector.lastRun,
        sources: sources.map((s) => ({
          channel: s.channel, status: s.status, available: s.available,
          requiresAdmin: s.requiresAdmin, eventsCollected: s.eventsCollected,
          lastCollectAt: s.lastCollectAt?.toISOString() ?? null,
        })),
        detectionRules: rules.map((r) => ({
          id: r.id, name: r.name, version: r.version, severity: r.severity,
          mitreId: r.mitreId, enabled: r.enabled,
        })),
        summary: {
          eventsInReport: await db.event.count({ where: { ts: { gte: since } } }),
          alertsInReport: alerts.length,
          incidentsInReport: incidents.length,
          bySeverity: ['critical', 'high', 'medium', 'low', 'info'].map((sev) => ({
            severity: sev,
            alerts: alerts.filter((a) => a.severity === sev).length,
            incidents: incidents.filter((i) => i.severity === sev).length,
          })),
        },
        alerts: alerts.map((a) => ({
          id: a.id, createdAt: a.createdAt.toISOString(), ruleId: a.ruleId,
          ruleName: a.rule.name, severity: a.severity, confidence: a.confidence,
          status: a.status, computer: a.computer, userName: a.userName,
          mitreId: a.mitreId, summary: a.summary, evidence: JSON.parse(a.evidence),
        })),
        incidents: incidents.map((i) => ({
          id: i.id, code: i.code, title: i.title, severity: i.severity, status: i.status,
          hypothesis: i.hypothesis,
          correlationMeta: i.correlationMeta ? JSON.parse(i.correlationMeta) : null,
          createdAt: i.createdAt.toISOString(), updatedAt: i.updatedAt.toISOString(),
          alerts: i.alerts.map((a) => ({ ruleId: a.ruleId, severity: a.severity, summary: a.summary })),
          notes: i.notes.map((n) => ({ author: n.author, body: n.body, createdAt: n.createdAt.toISOString() })),
          aiAnalyses: i.aiAnalyses.map((x) => ({
            aiGenerated: true,
            provider: x.provider, model: x.model,
            privacyMode: x.privacyMode, promptVersion: x.promptVersion,
            createdAt: x.createdAt.toISOString(),
            output: x.output,
          })),
        })),
      },
    }

    // Integrity metadata: SHA-256 over the canonical JSON body
    const canonical = JSON.stringify(payload)
    const integrity = createHash('sha256').update(canonical).digest('hex')
    const body = JSON.stringify({ ...payload, integrity: { algorithm: 'SHA-256', digest: integrity, covers: 'report payload excluding this field' } }, null, 2)

    return new NextResponse(body, {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="sentinel-report-${range}.json"`,
      },
    })
  } catch (err) {
    console.error('report error', err)
    return NextResponse.json({ error: 'report_failed' }, { status: 500 })
  }
}
