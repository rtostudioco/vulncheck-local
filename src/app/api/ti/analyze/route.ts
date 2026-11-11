import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { ensureBootstrap } from '@/lib/bootstrap'

export const dynamic = 'force-dynamic'

// ─── Indicator format validation + local heuristics (MODULE 07) ─────────────

export type IndicatorType = 'hash' | 'ip' | 'domain' | 'url' | 'invalid'

const RE = {
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
  domain: /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i,
  url: /^https?:\/\/[^\s/$.?#].[^\s]*$/i,
}

export function classify(value: string): IndicatorType {
  const v = value.trim()
  if (RE.md5.test(v) || RE.sha1.test(v) || RE.sha256.test(v)) return 'hash'
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v)
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number)
    if (octets.every((o) => o >= 0 && o <= 255)) return 'ip'
    return 'invalid'
  }
  if (RE.url.test(v)) return 'url'
  if (RE.domain.test(v)) return 'domain'
  return 'invalid'
}

export interface LocalCheck {
  id: string
  detailKey: string
  hit: boolean
}

export function localChecks(value: string, type: IndicatorType): LocalCheck[] {
  const checks: LocalCheck[] = []
  const v = value.trim().toLowerCase()

  if (type === 'ip') {
    const octets = v.split('.').map(Number)
    const [a, b] = octets
    if (a === 127) checks.push({ id: 'loopback', detailKey: 'ti.localhost', hit: true })
    else if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254))
      checks.push({ id: 'private', detailKey: 'ti.privateIp', hit: true })
    else checks.push({ id: 'public', detailKey: 'ti.publicIp', hit: true })
  }

  if (type === 'domain' || type === 'url') {
    const host = type === 'url' ? safeHost(v) : v
    if (host) {
      if (host.startsWith('xn--') || host.includes('.xn--'))
        checks.push({ id: 'punycode', detailKey: 'ti.punycode', hit: true })
      const tld = host.split('.').pop() ?? ''
      if (['zip', 'mov', 'top', 'xyz', 'tk', 'gq', 'cf', 'ml'].includes(tld))
        checks.push({ id: 'sus_tld', detailKey: 'ti.susTld', hit: true })
    }
  }

  if (type === 'url') {
    if (/\.(exe|dll|ps1|bat|vbs|scr|cmd|msi|jar)(\?|$)/i.test(v) || /\/payload|\/drop|\/gate/i.test(v))
      checks.push({ id: 'sus_pattern', detailKey: 'ti.susPattern', hit: true })
  }

  return checks
}

function safeHost(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return null
  }
}

// ─── POST /api/ti/analyze ───────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  try {
    await ensureBootstrap()
    const body = (await req.json()) as { value?: string }
    const value = (body.value ?? '').trim()
    if (!value || value.length > 500) {
      return NextResponse.json({ error: 'bad_indicator' }, { status: 400 })
    }

    const type = classify(value)
    if (type === 'invalid') {
      return NextResponse.json({ type, error: 'invalid_format' }, { status: 422 })
    }

    // Local verdict from stored indicators
    const stored = await db.indicator.findUnique({ where: { value } })

    // Does this indicator appear in locally stored events? (traceability)
    let eventRefs = 0
    if (type === 'ip') eventRefs = await db.event.count({ where: { ipAddress: value } })
    else if (type === 'domain') eventRefs = await db.event.count({ where: { commandLine: { contains: value } } })
    else if (type === 'url') eventRefs = await db.event.count({ where: { commandLine: { contains: safeHost(value) ?? value } } })

    const checks = localChecks(value, type)
    const verdict = stored?.verdict ?? 'unknown'

    return NextResponse.json({
      type,
      value,
      verdict,
      source: stored?.source ?? 'local',
      note: stored?.note ?? null,
      checks,
      eventRefs,
      external: null as null | { available: boolean; reason: string },
    })
  } catch (err) {
    console.error('ti analyze error', err)
    return NextResponse.json({ error: 'ti_failed' }, { status: 500 })
  }
}
