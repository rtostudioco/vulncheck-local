import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap, getSettings, saveSettings } from '@/lib/bootstrap'
import { collector } from '@/lib/engine/pipeline'

export const dynamic = 'force-dynamic'

export async function GET() {
  await ensureBootstrap()
  const settings = await getSettings()
  const audit = await db.auditLog.findMany({ orderBy: { createdAt: 'desc' }, take: 50 })
  return NextResponse.json({ settings, audit })
}

export async function PATCH(req: NextRequest) {
  try {
    await ensureBootstrap()
    const patch = (await req.json()) as Record<string, unknown>

    // Validate known keys only
    const allowed = ['language', 'collectorEnabled', 'collectorIntervalSec', 'retentionDays', 'aiMode', 'aiRedaction', 'tiExternalConsent']
    const safe: Record<string, unknown> = {}
    for (const k of allowed) if (k in patch) safe[k] = patch[k]
    if ('collectorIntervalSec' in safe) {
      const n = Number(safe.collectorIntervalSec)
      if (!Number.isFinite(n) || n < 5 || n > 600) safe.collectorIntervalSec = 20
    }
    if ('retentionDays' in safe) {
      const n = Number(safe.retentionDays)
      if (!Number.isFinite(n) || n < 1 || n > 365) safe.retentionDays = 7
    }
    if ('aiMode' in safe && !['off', 'sandbox', 'local', 'remote'].includes(String(safe.aiMode))) {
      safe.aiMode = 'sandbox'
    }

    const next = await saveSettings(safe)
    return NextResponse.json({ settings: next })
  } catch (err) {
    console.error('settings patch error', err)
    return NextResponse.json({ error: 'settings_failed' }, { status: 500 })
  }
}

/** Reset application data (factory state) — audited. */
export async function DELETE() {
  try {
    await ensureBootstrap()
    await db.alertEvent.deleteMany({})
    await db.alert.deleteMany({})
    await db.incidentNote.deleteMany({})
    await db.aiAnalysis.deleteMany({})
    await db.incident.deleteMany({})
    await db.event.deleteMany({})
    await db.indicator.deleteMany({})
    await db.auditLog.deleteMany({})
    await db.eventSource.updateMany({ data: { eventsCollected: 0, lastCollectAt: null } })
    return NextResponse.json({ ok: true })
  } catch (err) {
    console.error('settings reset error', err)
    return NextResponse.json({ error: 'reset_failed' }, { status: 500 })
  }
}
