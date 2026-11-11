import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap } from '@/lib/bootstrap'
import { serializeEvent } from '@/lib/serialize'
import type { Prisma } from '@prisma/client'

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    await ensureBootstrap()
    const sp = req.nextUrl.searchParams
    const page = Math.max(1, Number(sp.get('page') ?? 1))
    const pageSize = Math.min(200, Math.max(10, Number(sp.get('pageSize') ?? 50)))
    const q = sp.get('q')?.trim()
    const channel = sp.get('channel')
    const level = sp.get('level')
    const hours = Number(sp.get('hours') ?? 0)

    const where: Prisma.EventWhereInput = {}
    if (channel && channel !== 'all') where.channel = channel
    if (level && level !== 'all') where.level = level
    if (hours > 0) where.ts = { gte: new Date(Date.now() - hours * 3600 * 1000) }
    if (q) {
      where.OR = [
        { summary: { contains: q } },
        { computer: { contains: q } },
        { userName: { contains: q } },
        { targetUserName: { contains: q } },
        { processName: { contains: q } },
        { commandLine: { contains: q } },
        { ipAddress: { contains: q } },
        { serviceName: { contains: q } },
        { taskName: { contains: q } },
      ]
    }

    const [total, rows] = await Promise.all([
      db.event.count({ where }),
      db.event.findMany({
        where,
        orderBy: { ts: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
    ])

    return NextResponse.json({
      total,
      page,
      pageSize,
      events: rows.map(serializeEvent),
    })
  } catch (err) {
    console.error('events list error', err)
    return NextResponse.json({ error: 'events_list_failed' }, { status: 500 })
  }
}

/** Delete all collected events + dependent alerts/incidents (data management, §11). */
export async function DELETE() {
  try {
    await db.alertEvent.deleteMany({})
    await db.alert.deleteMany({})
    await db.incidentNote.deleteMany({})
    await db.aiAnalysis.deleteMany({})
    await db.incident.deleteMany({})
    const n = await db.event.deleteMany({})
    await db.eventSource.updateMany({ data: { eventsCollected: 0, lastCollectAt: null } })
    await db.auditLog.create({ data: { action: 'data.purge', target: 'events', detail: `${n.count} events` } })
    return NextResponse.json({ deleted: n.count })
  } catch (err) {
    console.error('events purge error', err)
    return NextResponse.json({ error: 'purge_failed' }, { status: 500 })
  }
}
