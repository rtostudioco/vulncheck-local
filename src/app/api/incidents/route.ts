import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap } from '@/lib/bootstrap'
import { serializeIncident } from '@/lib/serialize'
import type { Prisma } from '@prisma/client'

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    await ensureBootstrap()
    const sp = req.nextUrl.searchParams
    const status = sp.get('status')
    const where: Prisma.IncidentWhereInput = status && status !== 'all' ? { status } : {}
    const incidents = await db.incident.findMany({
      where,
      include: { alerts: { include: { rule: true } }, notes: true, aiAnalyses: true },
      orderBy: { updatedAt: 'desc' },
      take: 100,
    })
    return NextResponse.json({ incidents: incidents.map(serializeIncident) })
  } catch (err) {
    console.error('incidents list error', err)
    return NextResponse.json({ error: 'incidents_failed' }, { status: 500 })
  }
}
