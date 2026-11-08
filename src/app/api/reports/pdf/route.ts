import { NextResponse } from 'next/server';
import { getSessionDetail } from '@/lib/vulncheck/db/repo';
import { ensureSeeded } from '@/lib/vulncheck/db/seed';
import { generatePdf, pdfFileName } from '@/lib/vulncheck/reporting/pdf';
import { recordReport } from '@/lib/vulncheck/reporting/history';

export const dynamic = 'force-dynamic';
export const maxDuration = 120;

export async function GET(req: Request) {
  try {
    await ensureSeeded();
    const { searchParams } = new URL(req.url);
    const sessionId = searchParams.get('sessionId');
    if (!sessionId) {
      return NextResponse.json({ error: 'sessionId query parameter is required' }, { status: 400 });
    }

    const detail = await getSessionDetail(sessionId);
    if (!detail) {
      return NextResponse.json({ error: 'Audit session not found' }, { status: 404 });
    }
    if (detail.status !== 'COMPLETED') {
      return NextResponse.json({ error: 'Report available once the audit has completed' }, { status: 409 });
    }

    const bytes = generatePdf(detail);
    const fileName = pdfFileName(detail);
    await recordReport(sessionId, 'PDF', fileName).catch(() => undefined);

    return new NextResponse(new Uint8Array(bytes), {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${fileName}"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch (err) {
    console.error('[api:reports/pdf] error', err);
    return NextResponse.json({ error: 'Failed to generate the PDF report' }, { status: 500 });
  }
}
