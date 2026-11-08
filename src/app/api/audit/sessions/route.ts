import { NextResponse } from 'next/server';
import { listSessions } from '@/lib/vulncheck/db/repo';
import { ensureSeeded } from '@/lib/vulncheck/db/seed';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    await ensureSeeded();
    const sessions = await listSessions(25);
    return NextResponse.json({ sessions });
  } catch (err) {
    console.error('[api:audit/sessions] error', err);
    return NextResponse.json({ error: 'Failed to list audit sessions' }, { status: 500 });
  }
}
