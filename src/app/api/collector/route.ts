import { NextRequest, NextResponse } from 'next/server'
import { ensureBootstrap, getSettings, saveSettings } from '@/lib/bootstrap'
import { collector, runPipelineTick } from '@/lib/engine/pipeline'

export const dynamic = 'force-dynamic'

/**
 * Collector control surface.
 * Single source of truth = persisted `collectorEnabled` setting.
 * The in-memory `collector.running` flag is kept in sync for pipeline
 * reporting; GET derives state from the setting so the header, Live Monitor
 * and Overview always agree (even after a server restart).
 */
export async function GET() {
  await ensureBootstrap()
  const settings = await getSettings()
  return NextResponse.json({
    running: Boolean(settings.collectorEnabled),
    intervalSec: Number(settings.collectorIntervalSec ?? 20),
    lastTickAt: collector.lastTickAt,
    lastRun: collector.lastRun,
  })
}

export async function POST(req: NextRequest) {
  try {
    await ensureBootstrap()
    const body = (await req.json().catch(() => ({}))) as { action?: string; batches?: number; scenario?: string }
    const action = body.action ?? 'tick'

    if (action === 'tick') {
      const settings = await getSettings()
      const interval = Number(settings.collectorIntervalSec ?? 20)
      collector.intervalSec = interval
      collector.running = Boolean(settings.collectorEnabled)
      const scenario = typeof body.scenario === 'string' && body.scenario.length <= 40 ? body.scenario : undefined
      const batches = Math.min(6, Math.max(1, Number(body.batches ?? 2)))
      const run = await runPipelineTick({ batches, scenarioKey: scenario })
      return NextResponse.json({ ok: true, run })
    }

    if (action === 'start') {
      collector.running = true
      await saveSettings({ collectorEnabled: true })
      return NextResponse.json({ ok: true, running: true })
    }

    if (action === 'stop') {
      collector.running = false
      await saveSettings({ collectorEnabled: false })
      return NextResponse.json({ ok: true, running: false })
    }

    return NextResponse.json({ error: 'unknown_action' }, { status: 400 })
  } catch (err) {
    console.error('collector error', err)
    return NextResponse.json({ error: 'collector_failed' }, { status: 500 })
  }
}
