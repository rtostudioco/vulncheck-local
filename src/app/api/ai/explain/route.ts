import { NextResponse } from 'next/server';
import { explainFinding } from '@/lib/vulncheck/ai/explain';
import { ensureSeeded, getSetting } from '@/lib/vulncheck/db/seed';
import { getSessionDetail } from '@/lib/vulncheck/db/repo';

export const dynamic = 'force-dynamic';
export const maxDuration = 120;

/**
 * AI explanation for ONE finding — gated behind explicit consent
 * (spec §8: no transmission without explicit user consent).
 */
export async function POST(req: Request) {
  try {
    await ensureSeeded();
    const consent = (await getSetting('ai_consent_enabled')) === 'true';
    if (!consent) {
      return NextResponse.json(
        { error: 'AI explanations are disabled. Enable them in Settings first (explicit consent required).' },
        { status: 403 },
      );
    }

    const body = (await req.json().catch(() => ({}))) as { sessionId?: string; findingId?: string };
    if (!body.sessionId || !body.findingId) {
      return NextResponse.json({ error: 'sessionId and findingId are required' }, { status: 400 });
    }

    const detail = await getSessionDetail(body.sessionId);
    if (!detail) {
      return NextResponse.json({ error: 'Audit session not found' }, { status: 404 });
    }
    const finding = detail.findings.find((f) => f.id === body.findingId);
    if (!finding) {
      return NextResponse.json({ error: 'Finding not found in this session' }, { status: 404 });
    }

    const osContext = detail.profile
      ? `${detail.profile.osName} (${detail.platform})`
      : detail.platform;

    const explanation = await explainFinding(finding, osContext);
    return NextResponse.json({ explanation });
  } catch (err) {
    console.error('[api:ai/explain] error', err);
    return NextResponse.json({ error: 'AI explanation failed. The application remains fully functional without AI.' }, { status: 502 });
  }
}
