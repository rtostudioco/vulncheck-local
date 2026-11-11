import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap, getSettings } from '@/lib/bootstrap'

export const dynamic = 'force-dynamic'

/**
 * EXTERNAL LOOKUP — strictly consent-gated (MODULE 07).
 * Requires: settings.tiExternalConsent === true AND per-request consent flag.
 * In this sandbox build there is no external reputation provider configured,
 * so the honest result is "provider unavailable" and the verdict is NEVER
 * inferred from an unavailable provider (§8 MODULE 07 rule).
 */
export async function POST(req: NextRequest) {
  try {
    await ensureBootstrap()
    const body = (await req.json()) as { value?: string; consent?: boolean }
    const value = (body.value ?? '').trim()
    if (!value || !body.consent) {
      return NextResponse.json({ error: 'consent_required' }, { status: 403 })
    }
    const settings = await getSettings()
    if (!settings.tiExternalConsent) {
      return NextResponse.json({ error: 'global_consent_disabled' }, { status: 403 })
    }

    await db.auditLog.create({
      data: { action: 'ti.external_lookup', target: value.slice(0, 120), detail: 'user-authorized lookup attempt' },
    })

    return NextResponse.json({
      available: false,
      reason: 'no_external_provider_configured',
      disclosure: 'Only the indicator value was recorded in the local audit log. No data was transmitted: no external reputation provider is configured in this build.',
      verdict: 'unknown', // stays unknown — never inferred
    })
  } catch (err) {
    console.error('ti lookup error', err)
    return NextResponse.json({ error: 'lookup_failed' }, { status: 500 })
  }
}

export async function GET() {
  await ensureBootstrap()
  const settings = await getSettings()
  const indicators = await db.indicator.findMany({ orderBy: { createdAt: 'desc' }, take: 50 })
  return NextResponse.json({
    indicators: indicators.map((i) => ({
      id: i.id,
      type: i.type,
      value: i.value,
      verdict: i.verdict,
      source: i.source,
      note: i.note,
      createdAt: i.createdAt.toISOString(),
    })),
    globalConsent: Boolean(settings.tiExternalConsent),
  })
}
