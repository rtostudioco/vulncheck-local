import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap } from '@/lib/bootstrap'
import { serializeNote } from '@/lib/serialize'

export const dynamic = 'force-dynamic'

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    await ensureBootstrap()
    const { id } = await params
    const body = (await req.json()) as { body?: string }
    const text = (body.body ?? '').trim()
    if (!text) return NextResponse.json({ error: 'empty_note' }, { status: 400 })

    const note = await db.incidentNote.create({
      data: { incidentId: id, author: 'analyst', body: text.slice(0, 4000) },
    })
    await db.incident.update({ where: { id }, data: { updatedAt: new Date() } })
    return NextResponse.json({ note: serializeNote(note) })
  } catch (err) {
    console.error('note create error', err)
    return NextResponse.json({ error: 'note_failed' }, { status: 500 })
  }
}
