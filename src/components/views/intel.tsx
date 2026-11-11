'use client'

// SENTINEL DESK 1.0 — MODULE 07: Threat Intelligence
// Local indicator analysis with explicit, consent-gated external lookups.
// An unavailable external provider is NEVER interpreted as a clean/malicious verdict.

import { useCallback, useEffect, useState } from 'react'
import { useApp } from '@/stores/app-store'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, Mono, SectionTitle } from '@/components/shared/ui-atoms'
import { cn } from '@/lib/utils'
import { toast } from 'sonner'
import { Activity, Globe, Loader2, RefreshCw, Search } from 'lucide-react'

// ─── API contract types ─────────────────────────────────────────────────────

type IndicatorType = 'hash' | 'ip' | 'domain' | 'url'
type Verdict = 'unknown' | 'benign' | 'suspicious' | 'malicious'

interface TiCheck {
  id: string
  detailKey: string
  hit: boolean
}

interface TiAnalyzeResult {
  type: IndicatorType
  value: string
  verdict: Verdict
  source: string
  note: string | null
  checks: TiCheck[]
  eventRefs: number
  external: null
}

interface IndicatorRow {
  id: string
  type: string
  value: string
  verdict: string
  source: string
  note: string | null
  createdAt: string
}

interface LookupPayload {
  indicators: IndicatorRow[]
  globalConsent: boolean
}

// ─── Mapping helpers (labels/classes always via i18n + sev-* utilities) ─────

const TYPE_KEY: Record<IndicatorType, string> = {
  hash: 'ti.type.hash',
  ip: 'ti.type.ip',
  domain: 'ti.type.domain',
  url: 'ti.type.url',
}

const VERDICT_CLASS: Record<Verdict, string> = {
  unknown: 'sev-info',
  benign: 'sev-success',
  suspicious: 'sev-medium',
  malicious: 'sev-critical',
}

function typeKey(type: string): string {
  return type in TYPE_KEY ? TYPE_KEY[type as IndicatorType] : 'common.unknown'
}

function verdictClass(v: string): string {
  return v in VERDICT_CLASS ? VERDICT_CLASS[v as Verdict] : 'sev-info'
}

function verdictKey(v: string): string {
  return v in VERDICT_CLASS ? `ti.v.${v}` : 'ti.v.unknown'
}

/** Localized relative time (no hardcoded text — Intl provides the words). */
function relTime(iso: string, locale: string): string {
  const diffMs = new Date(iso).getTime() - Date.now()
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  const mins = Math.round(diffMs / 60000)
  if (Math.abs(mins) < 60) return rtf.format(mins, 'minute')
  const hours = Math.round(diffMs / 3_600_000)
  if (Math.abs(hours) < 24) return rtf.format(hours, 'hour')
  return rtf.format(Math.round(diffMs / 86_400_000), 'day')
}

// ─── View ────────────────────────────────────────────────────────────────────

export function IntelView() {
  const t = useApp((s) => s.t)
  const lang = useApp((s) => s.lang)
  const locale = lang === 'es' ? 'es-ES' : 'en-US'

  // Analysis form state
  const [input, setInput] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [invalid, setInvalid] = useState(false)
  const [result, setResult] = useState<TiAnalyzeResult | null>(null)

  // External (consent-gated) lookup state
  const [extConsent, setExtConsent] = useState(false)
  const [extBusy, setExtBusy] = useState(false)
  const [ext, setExt] = useState<{ disclosure: string | null; error: boolean } | null>(null)

  // Recent indicators
  const [recent, setRecent] = useState<IndicatorRow[] | null>(null)
  const [recentLoading, setRecentLoading] = useState(true)
  const [recentError, setRecentError] = useState(false)

  const loadRecent = useCallback(async () => {
    try {
      setRecentError(false)
      const res = await fetch('/api/ti/lookup')
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as LookupPayload
      setRecent(data.indicators)
    } catch {
      setRecentError(true)
    } finally {
      setRecentLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadRecent()
  }, [loadRecent])

  const runAnalyze = async () => {
    const value = input.trim()
    if (!value || analyzing) return
    setAnalyzing(true)
    setInvalid(false)
    setExt(null)
    setExtConsent(false)
    try {
      const res = await fetch('/api/ti/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      })
      if (res.status === 422) {
        setInvalid(true)
        setResult(null)
        return
      }
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as TiAnalyzeResult
      setResult(data)
      void loadRecent()
    } catch {
      toast.error(t('common.error'), { description: t('common.errorBody') })
    } finally {
      setAnalyzing(false)
    }
  }

  const runLookup = async () => {
    if (!result || extBusy) return
    setExtBusy(true)
    try {
      const res = await fetch('/api/ti/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: result.value, consent: true }),
      })
      if (res.status === 403) {
        setExt({ disclosure: null, error: true })
        return
      }
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as { disclosure: string; verdict: Verdict }
      setExt({ disclosure: data.disclosure, error: false })
    } catch {
      toast.error(t('common.error'), { description: t('common.errorBody') })
    } finally {
      setExtBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{t('ti.title')}</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">{t('ti.subtitle')}</p>
          </div>
          <Button size="sm" variant="outline" onClick={() => void loadRecent()}>
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> {t('common.refresh')}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Analysis column */}
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardContent className="p-5">
              <SectionTitle title={t('ti.title')} />
              <form
                className="flex flex-col gap-2 sm:flex-row sm:items-start"
                onSubmit={(e) => {
                  e.preventDefault()
                  void runAnalyze()
                }}
              >
                <div className="min-w-0 flex-1 space-y-1.5">
                  <Input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={t('ti.placeholder')}
                    aria-label={t('ti.placeholder')}
                    aria-invalid={invalid}
                    className="min-h-[44px] font-mono text-sm sm:min-h-0"
                  />
                  {invalid && (
                    <Badge variant="outline" className="sev-medium">
                      {t('ti.type.invalid')}
                    </Badge>
                  )}
                </div>
                <Button type="submit" disabled={analyzing || input.trim().length === 0} className="min-h-[44px] sm:min-h-0">
                  {analyzing ? (
                    <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
                  ) : (
                    <Search className="mr-1.5 h-3.5 w-3.5" aria-hidden />
                  )}
                  {t('ti.analyze')}
                </Button>
              </form>

              {/* Result */}
              {result && (
                <div className="mt-5 rounded-lg border border-border/70 p-4">
                  {/* Row 1: type chip + value + verdict */}
                  <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
                    <div className="flex min-w-0 items-center gap-2">
                      <Badge variant="outline" className="sev-info shrink-0">
                        {t(TYPE_KEY[result.type])}
                      </Badge>
                      <Mono className="min-w-0 break-all text-sm text-foreground">{result.value}</Mono>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                        {t('ti.verdict')}
                      </span>
                      <Badge variant="outline" className={cn('font-medium', VERDICT_CLASS[result.verdict])}>
                        {t(verdictKey(result.verdict))}
                      </Badge>
                    </div>
                  </div>

                  {/* Local checks */}
                  <div className="mt-4 border-t pt-3">
                    <p className="text-xs font-semibold">{t('ti.localChecks')}</p>
                    {result.checks.length === 0 ? (
                      <p className="mt-2 text-xs text-muted-foreground">{t('ti.noChecks')}</p>
                    ) : (
                      <ul className="mt-2 space-y-1.5">
                        {result.checks.map((c) => (
                          <li key={c.id} className="flex items-start gap-2 text-xs leading-relaxed">
                            <span
                              className={cn(
                                'mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full',
                                c.hit ? 'bg-primary' : 'bg-muted-foreground/40',
                              )}
                              aria-hidden
                            />
                            <span>{t(c.detailKey)}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {/* Traceability: local evidence refs + stored note */}
                  {result.eventRefs > 0 && (
                    <p className="sev-info mt-3 rounded-md border px-2.5 py-1.5 text-xs leading-relaxed">
                      {t('ti.evidenceRefs', { n: result.eventRefs })}
                    </p>
                  )}
                  {result.note && <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{result.note}</p>}

                  {/* External lookup — optional, consent-gated */}
                  <div className="mt-4 border-t pt-3">
                    <p className="text-xs font-semibold">{t('ti.extTitle')}</p>
                    <div className="sev-info mt-2 rounded-md border px-3 py-2">
                      <p className="text-[11px] leading-relaxed">{t('ti.extDisclosure')}</p>
                    </div>
                    <div className="mt-2.5 flex min-h-[44px] items-start gap-2.5 py-1 sm:min-h-0 sm:py-0">
                      <Checkbox
                        id="ti-ext-consent"
                        checked={extConsent}
                        onCheckedChange={(v) => setExtConsent(v === true)}
                        className="mt-0.5"
                      />
                      <Label htmlFor="ti-ext-consent" className="text-xs font-normal leading-relaxed">
                        {t('ti.extConsent')}
                      </Label>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      className="mt-3 min-h-[44px] sm:min-h-0"
                      disabled={!extConsent || extBusy}
                      onClick={() => void runLookup()}
                    >
                      {extBusy ? (
                        <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
                      ) : (
                        <Globe className="mr-1.5 h-3.5 w-3.5" aria-hidden />
                      )}
                      {t('ti.extLookup')}
                    </Button>

                    {ext && !ext.error && (
                      <div className="mt-3 space-y-2">
                        <div className="rounded-md border border-border bg-muted/40 px-3 py-2">
                          <p className="text-[11px] leading-relaxed text-muted-foreground">{ext.disclosure}</p>
                        </div>
                        <p className="text-[11px] leading-relaxed text-muted-foreground">{t('ti.extUnavailable')}</p>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                            {t('ti.verdict')}
                          </span>
                          <Badge variant="outline" className="sev-info font-medium">
                            {t('ti.v.unknown')}
                          </Badge>
                        </div>
                      </div>
                    )}
                    {ext && ext.error && (
                      <div className="sev-medium mt-3 rounded-md border px-3 py-2">
                        <p className="text-xs font-medium">{t('common.error')}</p>
                        <p className="mt-0.5 text-[11px] leading-relaxed opacity-90">{t('st.tiConsent')}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Recent indicators */}
        <Card>
          <CardContent className="p-5">
            <SectionTitle title={t('ti.recent')} />
            {recentLoading ? (
              <div className="space-y-2">
                {[...Array(4)].map((_, i) => (
                  <Skeleton key={i} className="h-16" />
                ))}
              </div>
            ) : recentError ? (
              <EmptyState
                icon={Activity}
                title={t('common.error')}
                hint={t('common.errorBody')}
                action={
                  <Button onClick={() => void loadRecent()} variant="outline" size="sm">
                    {t('common.retry')}
                  </Button>
                }
              />
            ) : !recent || recent.length === 0 ? (
              <p className="py-8 text-center text-xs text-muted-foreground">{t('ti.recentEmpty')}</p>
            ) : (
              <ul className="scroll-slim max-h-96 space-y-2 overflow-y-auto pr-0.5">
                {recent.map((ind) => (
                  <li key={ind.id} className="rounded-md border border-border/60 px-2.5 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <Mono className="min-w-0 truncate text-[11px] text-foreground">{ind.value}</Mono>
                      <span className="shrink-0 text-[10px] text-muted-foreground">
                        {relTime(ind.createdAt, locale)}
                      </span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <Badge variant="outline" className="text-[10px]">
                        {t(typeKey(ind.type))}
                      </Badge>
                      <Badge variant="outline" className={cn('text-[10px] font-medium', verdictClass(ind.verdict))}>
                        {t(verdictKey(ind.verdict))}
                      </Badge>
                    </div>
                    {ind.note && <p className="mt-1 line-clamp-2 text-[10px] text-muted-foreground/80">{ind.note}</p>}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
