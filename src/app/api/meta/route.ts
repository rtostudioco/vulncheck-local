import { NextResponse } from 'next/server';
import { detectPlatform } from '@/lib/vulncheck/core/platform';
import { ALL_RULES } from '@/lib/vulncheck/compliance/rules';
import {
  DISCLAIMERS,
  ENGINE_VERSION,
  METHODOLOGY_TEXT,
  type MetaDTO,
} from '@/lib/vulncheck/core/types';
import { ensureSeeded, getSetting } from '@/lib/vulncheck/db/seed';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    await ensureSeeded();
    const aiConsent = (await getSetting('ai_consent_enabled')) === 'true';
    const retention = Number(await getSetting('retention_days') ?? '90');

    const meta: MetaDTO = {
      engineVersion: ENGINE_VERSION,
      ruleCount: ALL_RULES.length,
      platform: detectPlatform(),
      aiConsentEnabled: aiConsent,
      retentionDays: Number.isFinite(retention) && retention > 0 ? retention : 90,
      methodology: METHODOLOGY_TEXT,
      disclaimers: DISCLAIMERS,
    };
    return NextResponse.json(meta);
  } catch (err) {
    console.error('[api:meta] error', err);
    return NextResponse.json({ error: 'Failed to load application metadata' }, { status: 500 });
  }
}
