import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap } from '@/lib/bootstrap'
import { serializeIncident } from '@/lib/serialize'

export const dynamic = 'force-dynamic'

const VALID_STATUSES = ['new', 'investigating', 'monitoring', 'resolved', 'false_positive']

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    await ensureBootstrap()
    const { id } = await params
    const incident = await db.incident.findUnique({
      where: { id },
      include: { alerts: { include: { rule: true } }, notes: true, aiAnalyses: true },
    })
    if (!incident) return NextResponse.json({ error: 'not_found' }, { status: 404 })
    return NextResponse.json({ incident: serializeIncident(incident) })
  } catch (err) {
    console.error('incident detail error', err)
    return NextResponse.json({ error: 'incident_failed' }, { status: 500 })
  }
}

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    await ensureBootstrap()
    const { id } = await params
    const body = (await req.json()) as { status?: string; title?: string }
    const data: { status?: string; title?: string } = {}
    if (body.status) {
      if (!VALID_STATUSES.includes(body.status)) {
        return NextResponse.json({ error: 'invalid_status' }, { status: 400 })
      }
      data.status = body.status
    }
    if (body.title) data.title = body.title.slice(0, 200)

    const incident = await db.incident.update({
      where: { id },
      data,
      include: { alerts: { include: { rule: true } }, notes: true, aiAnalyses: true },
    })
    await db.auditLog.create({
      data: { action: 'incident.update', target: incident.code, detail: JSON.stringify(data) },
    })
    return NextResponse.json({ incident: serializeIncident(incident) })
  } catch (err) {
    console.error('incident patch error', err)
    return NextResponse.json({ error: 'incident_update_failed' }, { status: 500 })
  }
}
