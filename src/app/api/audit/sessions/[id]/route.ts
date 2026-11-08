import { NextResponse } from 'next/server';
import { deleteSession, getSessionDetail } from '@/lib/vulncheck/db/repo';
import { ensureSeeded } from '@/lib/vulncheck/db/seed';

export const dynamic = 'force-dynamic';

type Params = { params: Promise<{ id: string }> };

export async function GET(_req: Request, { params }: Params) {
  try {
    await ensureSeeded();
    const { id } = await params;
    const detail = await getSessionDetail(id);
    if (!detail) {
      return NextResponse.json({ error: 'Audit session not found' }, { status: 404 });
    }
    return NextResponse.json(detail);
  } catch (err) {
    console.error('[api:audit/sessions/:id] error', err);
    return NextResponse.json({ error: 'Failed to load the audit session' }, { status: 500 });
  }
}

export async function DELETE(_req: Request, { params }: Params) {
  try {
    await ensureSeeded();
    const { id } = await params;
    await deleteSession(id);
    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error('[api:audit/sessions/:id DELETE] error', err);
    return NextResponse.json({ error: 'Failed to delete the audit session' }, { status: 500 });
  }
}
