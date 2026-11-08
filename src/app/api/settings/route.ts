import { NextResponse } from 'next/server';
import type { SettingsDTO } from '@/lib/vulncheck/core/types';
import { ensureSeeded, getSetting, setSetting, SCHEMA_VERSION } from '@/lib/vulncheck/db/seed';
import { ENGINE_VERSION } from '@/lib/vulncheck/core/types';

export const dynamic = 'force-dynamic';

async function readSettings(): Promise<SettingsDTO> {
  const aiConsentEnabled = (await getSetting('ai_consent_enabled')) === 'true';
  const rawRetention = Number(await getSetting('retention_days') ?? '90');
  return {
    aiConsentEnabled,
    retentionDays: Number.isFinite(rawRetention) && rawRetention > 0 ? rawRetention : 90,
    schemaVersion: Number(SCHEMA_VERSION),
    engineVersion: ENGINE_VERSION,
  };
}

export async function GET() {
  try {
    await ensureSeeded();
    return NextResponse.json(await readSettings());
  } catch (err) {
    console.error('[api:settings GET] error', err);
    return NextResponse.json({ error: 'Failed to load settings' }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    await ensureSeeded();
    const body = (await req.json().catch(() => ({}))) as {
      aiConsentEnabled?: unknown;
      retentionDays?: unknown;
    };

    if (typeof body.aiConsentEnabled === 'boolean') {
      await setSetting('ai_consent_enabled', body.aiConsentEnabled ? 'true' : 'false');
    }

    if (body.retentionDays !== undefined) {
      const days = Number(body.retentionDays);
      if (!Number.isFinite(days) || days < 7 || days > 365) {
        return NextResponse.json({ error: 'retentionDays must be a number between 7 and 365' }, { status: 400 });
      }
      await setSetting('retention_days', String(Math.round(days)));
    }

    return NextResponse.json(await readSettings());
  } catch (err) {
    console.error('[api:settings POST] error', err);
    return NextResponse.json({ error: 'Failed to save settings' }, { status: 500 });
  }
}
