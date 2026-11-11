import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { serializeEvent } from '@/lib/serialize'

export const dynamic = 'force-dynamic'

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params
    const ev = await db.event.findUnique({ where: { id } })
    if (!ev) return NextResponse.json({ error: 'not_found' }, { status: 404 })

    // Which alerts reference this event (traceability, §7 provenance)
    const alertLinks = await db.alertEvent.findMany({
      where: { eventId: id },
      include: { alert: { include: { rule: true } } },
    })

    return NextResponse.json({
      event: serializeEvent(ev),
      raw: ev.raw ? JSON.parse(ev.raw) : null,
      alerts: alertLinks.map((l) => ({
        id: l.alert.id,
        ruleId: l.alert.ruleId,
        title: l.alert.title,
        severity: l.alert.severity,
        incidentId: l.alert.incidentId,
      })),
    })
  } catch (err) {
    console.error('event detail error', err)
    return NextResponse.json({ error: 'event_detail_failed' }, { status: 500 })
  }
}
