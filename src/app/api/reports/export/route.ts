import { NextResponse } from 'next/server';
import { getSessionDetail } from '@/lib/vulncheck/db/repo';
import { ensureSeeded } from '@/lib/vulncheck/db/seed';
import { exportFileName, generateCsv, generateJson } from '@/lib/vulncheck/reporting/exports';
import { recordReport } from '@/lib/vulncheck/reporting/history';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  try {
    await ensureSeeded();
    const { searchParams } = new URL(req.url);
    const sessionId = searchParams.get('sessionId');
    const format = searchParams.get('format');
    if (!sessionId) {
      return NextResponse.json({ error: 'sessionId query parameter is required' }, { status: 400 });
    }
    if (format !== 'json' && format !== 'csv') {
      return NextResponse.json({ error: 'format must be json or csv' }, { status: 400 });
    }

    const detail = await getSessionDetail(sessionId);
    if (!detail) {
      return NextResponse.json({ error: 'Audit session not found' }, { status: 404 });
    }
    if (detail.status !== 'COMPLETED') {
      return NextResponse.json({ error: 'Export available once the audit has completed' }, { status: 409 });
    }

    const fileName = exportFileName(detail, format);
    await recordReport(sessionId, format.toUpperCase(), fileName).catch(() => undefined);

    if (format === 'json') {
      return new NextResponse(generateJson(detail), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="${fileName}"`,
          'Cache-Control': 'no-store',
        },
      });
    }
    return new NextResponse(generateCsv(detail), {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${fileName}"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch (err) {
    console.error('[api:reports/export] error', err);
    return NextResponse.json({ error: 'Failed to generate the export' }, { status: 500 });
  }
}
