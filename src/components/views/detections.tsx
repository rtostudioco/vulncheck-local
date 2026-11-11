'use client'

// SENTINEL DESK 1.0 — MODULE 03: Threat Detection Engine
// Versioned, explainable rule cards: enable/disable toggles, synthetic-fixture
// testing, correlation markers and expandable rule documentation
// (false positives, limitations, evidence fields, portable rule logic).

import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useApp } from '@/stores/app-store'
import type { RuleSummary } from '@/types/soc'
import { SeverityBadge, EmptyState, Mono, StatCard } from '@/components/shared/ui-atoms'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { toast } from 'sonner'
import {
  Activity, BellRing, ChevronDown, FlaskConical, Loader2, RefreshCw,
  ShieldAlert, ShieldCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// ── Helpers ──────────────────────────────────────────────────────────────────

interface RuleTestResult {
  matched: boolean
  matchCount: number
  fixtureEvents: number
  explanation: string
  evidenceSample: unknown
}

function hasCorrelationKind(logic: unknown): boolean {
  if (typeof logic !== 'object' || logic === null) return false
  return (logic as { kind?: unknown }).kind === 'correlation'
}

function parseEvidenceFields(raw: string | null | undefined): string[] {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((f): f is string => typeof f === 'string')
  } catch {
    return []
  }
}

function DocSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{title}</p>
      {children}
    </div>
  )
}

// ── Rule card ────────────────────────────────────────────────────────────────

function RuleCard({ rule, onToggle }: { rule: RuleSummary; onToggle: (rule: RuleSummary, enabled: boolean) => void }) {
  const t = useApp((s) => s.t)
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<RuleTestResult | null>(null)
  const [docsOpen, setDocsOpen] = useState(false)

  const correlation = hasCorrelationKind(rule.logic)
  const evidenceFields = parseEvidenceFields(rule.evidenceFields)
  const hasDocs = Boolean(
    rule.falsePositives || rule.limitations || evidenceFields.length > 0 || rule.logic != null,
  )

  const runTest = async () => {
    setTesting(true)
    try {
      const res = await fetch(`/api/rules/${encodeURIComponent(rule.id)}/test`, { method: 'POST' })
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as RuleTestResult
      setResult(data)
      toast(t('tn.testDone'))
    } catch {
      toast.error(t('common.error'))
    } finally {
      setTesting(false)
    }
  }

  return (
    <Card className={cn('transition-opacity', !rule.enabled && 'opacity-60')}>
      <CardContent className="flex h-full flex-col gap-3 p-5">
        {/* Header: id · name · severity · enable switch */}
        <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Mono className="text-[12px] font-semibold text-primary">{rule.id}</Mono>
            <span className="truncate text-sm font-medium">{rule.name}</span>
            <SeverityBadge severity={rule.severity} className="text-[10px]" />
            {!rule.enabled && (
              <Badge variant="outline" className="text-[10px] font-normal text-muted-foreground">
                {t('dt.disabled')}
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-muted-foreground">
              {rule.enabled ? t('dt.enabled') : t('dt.disabled')}
            </span>
            <Switch
              checked={rule.enabled}
              onCheckedChange={(v) => onToggle(rule, v)}
              aria-label={`${rule.id} — ${rule.enabled ? t('dt.enabled') : t('dt.disabled')}`}
              className="h-6 w-11"
            />
          </div>
        </div>

        {/* Meta: MITRE · correlation · alert count */}
        <div className="flex flex-wrap items-center gap-1.5">
          {rule.mitreId && (
            <Badge variant="outline" className="gap-1.5 text-[10.5px] font-normal">
              <span className="text-muted-foreground">{t('dt.mitre')}</span>
              <Mono className="text-[10.5px] text-foreground">{rule.mitreId}</Mono>
              {rule.mitreName && <span className="text-muted-foreground">{rule.mitreName}</span>}
            </Badge>
          )}
          {correlation && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge variant="outline" className="cursor-help text-[10.5px] font-normal">
                  {t('dt.correlation')}
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="max-w-64">
                <p className="text-xs leading-relaxed">{t('dt.correlationDesc')}</p>
              </TooltipContent>
            </Tooltip>
          )}
          <Badge variant="outline" className="text-[10.5px] font-normal text-muted-foreground">
            {rule.alertCount ?? 0} {t('dt.alerts')}
          </Badge>
        </div>

        {/* Category · version · author */}
        <p className="text-[11.5px] text-muted-foreground">
          {t('dt.category')}: <Mono className="text-[11px]">{rule.category}</Mono>
          {' · '}v<Mono className="text-[11px]">{rule.version}</Mono>
          {' · '}
          <Mono className="text-[11px]">{rule.author}</Mono>
        </p>

        <p className="text-sm leading-relaxed text-muted-foreground">{rule.description}</p>

        {/* Synthetic-fixture test result */}
        {result && (
          result.matched ? (
            <div className="sev-success rounded-md border px-3 py-2.5" role="status">
              <p className="flex items-center gap-1.5 text-xs font-semibold">
                <ShieldCheck className="h-3.5 w-3.5 shrink-0" aria-hidden />
                {t('dt.testPassed')}
              </p>
              <p className="mt-1.5 break-words font-mono text-xs leading-relaxed opacity-90">{result.explanation}</p>
              <p className="mt-1 text-[11px] opacity-80">
                {t('dt.testEvents')}: <span className="font-mono">{result.fixtureEvents}</span>
              </p>
            </div>
          ) : (
            <div className="sev-medium rounded-md border px-3 py-2.5" role="status">
              <p className="flex items-center gap-1.5 text-xs font-semibold">
                <ShieldAlert className="h-3.5 w-3.5 shrink-0" aria-hidden />
                {t('dt.testNoMatch')}
              </p>
              <p className="mt-1.5 break-words font-mono text-xs leading-relaxed opacity-90">{result.explanation}</p>
            </div>
          )
        )}

        {/* Actions + expandable documentation */}
        <Collapsible open={docsOpen} onOpenChange={setDocsOpen} className="mt-auto">
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button variant="outline" size="sm" className="min-h-11 gap-1.5" onClick={() => void runTest()} disabled={testing}>
              {testing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              ) : (
                <FlaskConical className="h-3.5 w-3.5" aria-hidden />
              )}
              {testing ? t('dt.testing') : t('dt.test')}
            </Button>
            {hasDocs && (
              <CollapsibleTrigger asChild>
                <Button variant="ghost" size="sm" className="min-h-11 gap-1.5" aria-expanded={docsOpen}>
                  <ChevronDown
                    className={cn('h-3.5 w-3.5 transition-transform', docsOpen && 'rotate-180')}
                    aria-hidden
                  />
                  {t('common.details')}
                </Button>
              </CollapsibleTrigger>
            )}
          </div>

          <CollapsibleContent>
            <div className="scroll-slim mt-3 max-h-80 space-y-3.5 overflow-y-auto border-t border-border/60 pt-3">
              {rule.falsePositives && (
                <DocSection title={t('dt.falsePositives')}>
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{rule.falsePositives}</p>
                </DocSection>
              )}
              {rule.limitations && (
                <DocSection title={t('dt.limitations')}>
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{rule.limitations}</p>
                </DocSection>
              )}
              {evidenceFields.length > 0 && (
                <DocSection title={t('dt.evidenceFields')}>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {evidenceFields.map((f) => (
                      <Badge
                        key={f}
                        variant="outline"
                        className="font-mono text-[10.5px] font-normal text-muted-foreground"
                      >
                        {f}
                      </Badge>
                    ))}
                  </div>
                </DocSection>
              )}
              {rule.logic != null && (
                <DocSection title={t('dt.logic')}>
                  <pre className="scroll-slim mt-1.5 max-h-48 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-[10.5px] leading-relaxed text-muted-foreground">
                    {JSON.stringify(rule.logic, null, 2)}
                  </pre>
                </DocSection>
              )}
            </div>
          </CollapsibleContent>
        </Collapsible>
      </CardContent>
    </Card>
  )
}

// ── View ─────────────────────────────────────────────────────────────────────

export function DetectionsView() {
  const t = useApp((s) => s.t)
  const [rules, setRules] = useState<RuleSummary[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  /** rule ids with an in-flight toggle — polling must not clobber their state */
  const pendingRef = useRef<Set<string>>(new Set())

  const load = useCallback(async () => {
    try {
      setError(false)
      const res = await fetch('/api/rules')
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as { rules: RuleSummary[] }
      setRules((prev) => {
        if (!prev || pendingRef.current.size === 0) return data.rules
        // keep local state for rules being toggled right now
        return data.rules.map((r) => {
          const local = prev.find((p) => p.id === r.id)
          return pendingRef.current.has(r.id) && local ? local : r
        })
      })
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 20000)
    return () => clearInterval(id)
  }, [load])

  const toggleRule = useCallback(
    async (rule: RuleSummary, enabled: boolean) => {
      pendingRef.current.add(rule.id)
      setRules((rs) => (rs ? rs.map((r) => (r.id === rule.id ? { ...r, enabled } : r)) : rs))
      try {
        const res = await fetch('/api/rules', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: rule.id, enabled }),
        })
        if (!res.ok) throw new Error('bad status')
        const data = (await res.json()) as { rule: RuleSummary }
        setRules((rs) => (rs ? rs.map((r) => (r.id === rule.id ? data.rule : r)) : rs))
        toast(t('tn.ruleToggled', { id: rule.id, state: enabled ? 'ON' : 'OFF' }))
      } catch {
        setRules((rs) => (rs ? rs.map((r) => (r.id === rule.id ? { ...r, enabled: !enabled } : r)) : rs))
        toast.error(t('common.error'))
      } finally {
        pendingRef.current.delete(rule.id)
      }
    },
    [t],
  )

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-80" />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
        </div>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-52" />
          ))}
        </div>
      </div>
    )
  }

  if (error || !rules) {
    return (
      <EmptyState
        icon={Activity}
        title={t('common.error')}
        hint={t('common.errorBody')}
        action={<Button onClick={() => void load()} variant="outline" size="sm">{t('common.retry')}</Button>}
      />
    )
  }

  const enabledCount = rules.filter((r) => r.enabled).length
  const totalAlerts = rules.reduce((acc, r) => acc + (r.alertCount ?? 0), 0)

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{t('dt.title')}</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">{t('dt.subtitle')}</p>
          </div>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> {t('common.refresh')}
          </Button>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <StatCard
          label={t('dt.rules')}
          value={`${enabledCount}/${rules.length}`}
          icon={ShieldCheck}
          tone="success"
        />
        <StatCard label={t('dt.alerts')} value={totalAlerts} icon={BellRing} tone="high" />
      </div>

      {/* Rule cards */}
      {rules.length === 0 ? (
        <EmptyState icon={ShieldCheck} title={t('common.empty')} hint={t('dt.subtitle')} />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {rules.map((rule) => (
            <RuleCard key={rule.id} rule={rule} onToggle={(r, v) => void toggleRule(r, v)} />
          ))}
        </div>
      )}
    </div>
  )
}
