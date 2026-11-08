import { db } from '@/lib/db';
import { NextResponse } from 'next/server';
import type { ReportHistoryDTO } from '@/lib/vulncheck/core/types';
import { ensureSeeded } from '@/lib/vulncheck/db/seed';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    await ensureSeeded();
    const rows = await db.reportHistory.findMany({
      orderBy: { generatedAt: 'desc' },
      take: 40,
      include: { session: { select: { startedAt: true, overallScore: true } } },
    });
    const reports: ReportHistoryDTO[] = rows.map((r) => ({
      id: r.id,
      sessionId: r.sessionId,
      format: r.format,
      fileName: r.fileName,
      generatedAt: r.generatedAt.toISOString(),
      sessionDate: r.session.startedAt.toISOString(),
      overallScore: r.session.overallScore,
    }));
    return NextResponse.json({ reports });
  } catch (err) {
    console.error('[api:reports/history] error', err);
    return NextResponse.json({ error: 'Failed to list report history' }, { status: 500 });
  }
}
