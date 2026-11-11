import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap, getSettings } from '@/lib/bootstrap'
import { collector } from '@/lib/engine/pipeline'
import { serializeAlert, serializeIncident, serializeSource } from '@/lib/serialize'
import { DETECTION_RULES } from '@/lib/engine/rules'

export const dynamic = 'force-dynamic'

export async function GET() {
  try {
    await ensureBootstrap()
    const settings = await getSettings()
    const now = new Date()
    const since24h = new Date(now.getTime() - 24 * 3600 * 1000)

    const [
      events24h, eventsTotal, alertsOpen, incidentsActive, rulesEnabled, rulesTotal,
      bySeverity, trendRaw, sources, recentAlerts, recentIncidents, totalCollectedAgg,
    ] = await Promise.all([
      db.event.count({ where: { ts: { gte: since24h } } }),
      db.event.count(),
      db.alert.count({ where: { status: 'open' } }),
      db.incident.count({ where: { status: { in: ['new', 'investigating', 'monitoring'] } } }),
      db.detectionRule.count({ where: { enabled: true } }),
      db.detectionRule.count(),
      db.alert.groupBy({ by: ['severity'], _count: { _all: true } }),
      db.event.findMany({
        where: { ts: { gte: since24h } },
        select: { ts: true },
        orderBy: { ts: 'asc' },
      }),
      db.eventSource.findMany({ orderBy: { channel: 'asc' } }),
      db.alert.findMany({
        include: { rule: true, events: { include: { event: true } } },
        orderBy: { createdAt: 'desc' },
        take: 6,
      }),
      db.incident.findMany({
        include: { alerts: { include: { rule: true } }, notes: true, aiAnalyses: true },
        orderBy: { updatedAt: 'desc' },
        take: 5,
      }),
      db.eventSource.aggregate({ _sum: { eventsCollected: true } }),
    ])

    // Incident counts per severity
    const incBySeverity = await db.incident.groupBy({ by: ['severity'], _count: { _all: true } })

    const severityBuckets = ['critical', 'high', 'medium', 'low', 'info'].map((sev) => ({
      severity: sev,
      alerts: bySeverity.find((b) => b.severity === sev)?._count._all ?? 0,
      incidents: incBySeverity.find((b) => b.severity === sev)?._count._all ?? 0,
    }))

    // hourly trend buckets
    const buckets = new Map<string, { events: number; alerts: number }>()
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 3600 * 1000)
      d.setMinutes(0, 0, 0)
      buckets.set(d.toISOString(), { events: 0, alerts: 0 })
    }
    for (const e of trendRaw) {
      const d = new Date(e.ts)
      d.setMinutes(0, 0, 0)
      const k = d.toISOString()
      const b = buckets.get(k)
      if (b) b.events++
    }
    const recentAlertTimes = await db.alert.findMany({
      where: { createdAt: { gte: since24h } },
      select: { createdAt: true },
    })
    for (const a of recentAlertTimes) {
      const d = new Date(a.createdAt)
      d.setMinutes(0, 0, 0)
      const b = buckets.get(d.toISOString())
      if (b) b.alerts++
    }

    const aiMode = (settings.aiMode as string) ?? 'sandbox'

    return NextResponse.json({
      demoMode: true,
      machine: 'WS-FINANCE-04',
      collector: {
        running: collector.running,
        intervalSec: collector.intervalSec,
        lastTickAt: collector.lastTickAt,
        lastRun: collector.lastRun,
        totalCollected: totalCollectedAgg._sum.eventsCollected ?? 0,
      },
      counts: {
        events24h,
        eventsTotal,
        alertsOpen,
        incidentsActive,
        rulesEnabled,
        rulesTotal,
      },
      severity: severityBuckets,
      eventsTrend: [...buckets.entries()].map(([time, v]) => ({ time, ...v })),
      sources: sources.map(serializeSource),
      recentAlerts: recentAlerts.map(serializeAlert),
      recentIncidents: recentIncidents.map((i) => serializeIncident(i)),
      ai: {
        mode: aiMode,
        available: aiMode !== 'off',
        provider: aiMode === 'off' ? '—' : 'sandbox-assistant',
        model: aiMode === 'off' ? '—' : 'glm-4-sandbox',
      },
    })
  } catch (err) {
    console.error('overview error', err)
    return NextResponse.json({ error: 'overview_failed' }, { status: 500 })
  }
}
