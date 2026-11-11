'use client'

// SENTINEL DESK 1.0 — MODULE 08: AI Security Analyst
// Explainable, privacy-preserving AI assistance. Output is ALWAYS labeled as
// AI-generated and is advisory only — it can never confirm a compromise.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useApp } from '@/stores/app-store'
import type { AiAnalysisRecord, IncidentRecord, SettingsPayload } from '@/types/soc'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { EmptyState, Mono, SectionTitle } from '@/components/shared/ui-atoms'
import { cn } from '@/lib/utils'
import { toast } from 'sonner'
import ReactMarkdown, { type Components } from 'react-markdown'
import { Activity, Ban, Bot, History, Loader2, Play, ShieldAlert } from 'lucide-react'

// ─── API contract types ─────────────────────────────────────────────────────

type AiMode = 'off' | 'sandbox' | 'local' | 'remote'

interface SentAlert {
  ruleId: string
  title: string
  severity: string
  confidence: number
  summary: string | null
  mitreId?: string | null
}

interface SentEvent {
  time: string
  channel: string
  eventId: number
  level: string
  computer: string | null
  userName?: string | null
  processName?: string | null
  commandLine?: string | null
  ipAddress?: string | null
  taskName?: string | null
  serviceName?: string | null
  summary?: string | null
}

interface SentBundle {
  code: string
  severity: string
  status: string
  hypothesis?: string | null
  alerts: SentAlert[]
  events: SentEvent[]
  notes: { author: string; body: string }[]
}

interface AnalyzeResponse {
  analysis: AiAnalysisRecord
  sentBundle: SentBundle
}

// ─── Markdown styling (dark graphite, no typography plugin) ─────────────────

const MD: Components = {
  h1: ({ children }) => <h1 className="mb-1.5 mt-3 text-base font-semibold first:mt-0">{children}</h1>,
  h2: ({ children }) => <h2 className="mb-1.5 mt-3 text-sm font-semibold first:mt-0">{children}</h2>,
  h3: ({ children }) => <h3 className="mb-1 mt-2.5 text-sm font-semibold first:mt-0">{children}</h3>,
  p: ({ children }) => <p className="my-1.5 text-sm leading-relaxed last:mb-0">{children}</p>,
  ul: ({ children }) => <ul className="my-1.5 list-disc space-y-1 pl-5">{children}</ul>,
  ol: ({ children }) => <ol className="my-1.5 list-decimal space-y-1 pl-5">{children}</ol>,
  li: ({ children }) => <li className="text-sm leading-relaxed">{children}</li>,
  strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
  em: ({ children }) => <em className="italic">{children}</em>,
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noreferrer" className="underline underline-offset-2">
      {children}
    </a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-2 border-l-2 border-border pl-3 text-sm text-muted-foreground">{children}</blockquote>
  ),
  code: ({ children, className }) => (
    <code className={cn('font-mono text-[12px]', !className && 'rounded bg-muted px-1 py-0.5')}>{children}</code>
  ),
  pre: ({ children }) => (
    <pre className="scroll-slim my-2 overflow-x-auto rounded-md border bg-muted/40 p-3 text-[12px] leading-relaxed">
      {children}
    </pre>
  ),
  hr: () => <hr className="my-3 border-border" />,
  table: ({ children }) => (
    <div className="scroll-slim my-2 overflow-x-auto">
      <table className="w-full text-xs">{children}</table>
    </div>
  ),
  th: ({ children }) => <th className="border border-border bg-muted/40 px-2 py-1 text-left font-medium">{children}</th>,
  td: ({ children }) => <td className="border border-border px-2 py-1">{children}</td>,
}

const AI_MODES: AiMode[] = ['off', 'sandbox', 'local', 'remote']

// ─── View ────────────────────────────────────────────────────────────────────

export function AiAnalystView() {
  const t = useApp((s) => s.t)
  const lang = useApp((s) => s.lang)
  const locale = lang === 'es' ? 'es-ES' : 'en-US'

  const [settings, setSettings] = useState<SettingsPayload | null>(null)
  const [incidents, setIncidents] = useState<IncidentRecord[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  const [selectedId, setSelectedId] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState<AnalyzeResponse | null>(null)
  const [inlineError, setInlineError] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const loadSettings = useCallback(async () => {
    const res = await fetch('/api/settings')
    if (!res.ok) throw new Error('bad status')
    const data = (await res.json()) as { settings: SettingsPayload }
    setSettings(data.settings)
  }, [])

  const loadIncidents = useCallback(async () => {
    const res = await fetch('/api/incidents')
    if (!res.ok) throw new Error('bad status')
    const data = (await res.json()) as { incidents: IncidentRecord[] }
    setIncidents(data.incidents)
  }, [])

  const loadAll = useCallback(async () => {
    try {
      setError(false)
      setLoading(true)
      await Promise.all([loadSettings(), loadIncidents()])
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [loadSettings, loadIncidents])

  useEffect(() => {
    void loadAll()
  }, [loadAll])

  const mode: AiMode = settings?.aiMode && AI_MODES.includes(settings.aiMode) ? settings.aiMode : 'off'
  const aiOff = mode === 'off'
  const redaction = settings ? settings.aiRedaction !== false : true
  const incident = useMemo(
    () => (incidents ?? []).find((i) => i.id === selectedId) ?? null,
    [incidents, selectedId],
  )

  // Deterministic privacy preview — mirrors the server bundle builder:
  // unique evidence events + non-AI notes, before any data leaves the view.
  const preview = useMemo(() => {
    if (!incident) return null
    const eventIds = new Set<string>()
    for (const a of incident.alerts ?? []) {
      for (const ev of a.evidence ?? []) eventIds.add(ev.eventId)
    }
    return {
      events: eventIds.size,
      alerts: (incident.alerts ?? []).length,
      notes: (incident.notes ?? []).filter((n) => n.author !== 'ai').length,
    }
  }, [incident])

  // Actual sent bundle (only meaningful for the incident that was analyzed)
  const sent = result && incident && result.analysis.incidentId === incident.id ? result.sentBundle : null

  const history = useMemo(() => {
    const rows = incident?.aiAnalyses ?? []
    return [...rows].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  }, [incident])

  const runAnalysis = async () => {
    if (!incident || aiOff || analyzing) return
    setAnalyzing(true)
    setInlineError(null)
    try {
      const res = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incidentId: incident.id }),
      })
      if (res.status === 409) {
        setInlineError(t('ai.off'))
        toast.error(t('ai.off'))
        return
      }
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as AnalyzeResponse
      setResult(data)
      setExpandedId(null)
      void loadIncidents().catch(() => undefined) // refresh history
    } catch {
      setInlineError(t('ai.error'))
      toast.error(t('ai.error'))
    } finally {
      setAnalyzing(false)
    }
  }

  // ── Loading / error shells ──
  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-72" />
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-4 lg:col-span-2">
            <Skeleton className="h-28" />
            <Skeleton className="h-64" />
          </div>
          <Skeleton className="h-96" />
        </div>
      </div>
    )
  }

  if (error || !settings || !incidents) {
    return (
      <EmptyState
        icon={Activity}
        title={t('common.error')}
        hint={t('common.errorBody')}
        action={
          <Button onClick={() => void loadAll()} variant="outline" size="sm">
            {t('common.retry')}
          </Button>
        }
      />
    )
  }

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <h1 className="text-lg font-semibold tracking-tight">{t('ai.title')}</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">{t('ai.subtitle')}</p>
      </div>

      {/* Restrictions banner — always visible */}
      <div className="sev-info flex items-start gap-2.5 rounded-lg border px-4 py-2.5">
        <Ban className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
        <p className="text-xs leading-relaxed">{t('ai.cannot')}</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {/* Status card */}
          <Card>
            <CardContent className="p-5">
              <SectionTitle title={t('ai.mode')} />
              <div className="flex items-center gap-2.5">
                <span
                  className={cn('h-2 w-2 rounded-full', aiOff ? 'bg-muted-foreground/50' : 'bg-primary pulse-dot')}
                  aria-hidden
                />
                <p className="text-sm font-medium">{t(`ai.mode.${mode}`)}</p>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{t(`ai.modeNote.${mode}`)}</p>
              {aiOff && (
                <div className="sev-medium mt-3 flex items-start gap-2.5 rounded-md border px-3 py-2.5">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                  <p className="text-sm font-medium leading-relaxed">{t('ai.off')}</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Incident picker + privacy preview + run */}
          <Card>
            <CardContent className="p-5">
              <SectionTitle title={t('ai.pickIncident')} />
              {incidents.length === 0 ? (
                <EmptyState icon={Bot} title={t('ai.noIncidents')} />
              ) : (
                <div className="space-y-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="ai-incident-picker" className="text-xs text-muted-foreground">
                      {t('ai.pickIncident')}
                    </Label>
                    <Select
                      value={selectedId ?? ''}
                      onValueChange={(v) => {
                        setSelectedId(v)
                        setResult(null)
                        setInlineError(null)
                        setExpandedId(null)
                      }}
                    >
                      <SelectTrigger id="ai-incident-picker" className="min-h-[44px] w-full">
                        <SelectValue placeholder={t('ai.pickIncident')} />
                      </SelectTrigger>
                      <SelectContent>
                        {incidents.map((i) => (
                          <SelectItem key={i.id} value={i.id}>
                            {i.code} — {i.title}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  {/* Privacy preview panel */}
                  <div className="rounded-lg border border-border/70 p-4">
                    <p className="text-xs font-semibold">{t('ai.privacy')}</p>
                    <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{t('ai.privacyNote')}</p>

                    {!incident ? (
                      <p className="mt-3 text-xs text-muted-foreground">{t('ai.pickIncident')}</p>
                    ) : sent ? (
                      /* Actual bundle the model received */
                      <div className="mt-3 space-y-1.5 rounded-md border bg-muted/30 px-3 py-2.5 font-mono text-[11px] leading-relaxed">
                        <p>
                          {t('common.events')}: {sent.events.length} · {t('common.alerts')}: {sent.alerts.length} ·{' '}
                          {t('in.notes')}: {sent.notes.length}
                        </p>
                        {sent.alerts.slice(0, 3).map((a, idx) => (
                          <p key={`${a.ruleId}-${idx}`} className="text-foreground">
                            · {a.ruleId} — {a.title}
                          </p>
                        ))}
                        {sent.events.slice(0, 3).map((e) => (
                          <p key={`${e.time}-${e.eventId}`} className="truncate text-muted-foreground">
                            · {e.summary ?? e.commandLine ?? `#${e.eventId}`}
                          </p>
                        ))}
                      </div>
                    ) : (
                      /* Deterministic preview of what WOULD be sent */
                      <div className="mt-3 space-y-1.5 rounded-md border bg-muted/30 px-3 py-2.5 font-mono text-[11px] leading-relaxed">
                        <p>
                          {t('common.events')}: {preview?.events ?? 0} · {t('common.alerts')}: {preview?.alerts ?? 0} ·{' '}
                          {t('in.notes')}: {preview?.notes ?? 0}
                        </p>
                        <p>
                          {t('st.redaction')}: {redaction ? 'ON' : 'OFF'}
                        </p>
                        {(incident.alerts ?? []).slice(0, 3).map((a) => (
                          <p key={a.id} className="text-foreground">
                            · {a.ruleId} — {a.title}
                          </p>
                        ))}
                        <p className="text-muted-foreground">computer=•••• userName=•••• ipAddress=••••</p>
                      </div>
                    )}
                  </div>

                  {/* Run */}
                  <div className="flex flex-col gap-2">
                    <Button
                      onClick={() => void runAnalysis()}
                      disabled={!incident || aiOff || analyzing}
                      className="min-h-[44px] sm:self-start"
                    >
                      {analyzing ? (
                        <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
                      ) : (
                        <Play className="mr-1.5 h-3.5 w-3.5" aria-hidden />
                      )}
                      {analyzing ? t('ai.analyzing') : t('ai.analyze')}
                    </Button>
                    {inlineError && (
                      <p className="sev-critical rounded-md border px-3 py-2 text-xs leading-relaxed">{inlineError}</p>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Output */}
          {result && (
            <Card>
              <CardContent className="p-5">
                <SectionTitle title={t('ai.output')} />
                <Badge
                  variant="outline"
                  className="sev-info h-auto gap-1.5 whitespace-normal py-1 text-left text-[11px] font-medium leading-relaxed"
                >
                  <Bot className="h-3 w-3 shrink-0" aria-hidden />
                  {t('in.aiDisclaimer')}
                </Badge>
                <p className="mt-2.5 font-mono text-[11px] leading-relaxed text-muted-foreground">
                  {result.analysis.provider} · {result.analysis.model} · {result.analysis.privacyMode} ·{' '}
                  {t('ai.promptVersion')}: {result.analysis.promptVersion} ·{' '}
                  {new Date(result.analysis.createdAt).toLocaleString(locale)}
                </p>
                <div className="mt-3 rounded-lg border border-border/70 p-4">
                  <ReactMarkdown components={MD}>{result.analysis.output}</ReactMarkdown>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* History */}
        <Card>
          <CardContent className="p-5">
            <SectionTitle title={t('ai.history')} />
            {!incident || history.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">{t('ai.historyEmpty')}</p>
            ) : (
              <ul className="scroll-slim max-h-[28rem] space-y-2 overflow-y-auto pr-0.5">
                {history.map((a) => {
                  const expanded = expandedId === a.id
                  return (
                    <li key={a.id} className="rounded-md border border-border/60">
                      <button
                        type="button"
                        onClick={() => setExpandedId(expanded ? null : a.id)}
                        aria-expanded={expanded}
                        className="flex w-full flex-col gap-1 rounded-md p-2.5 text-left transition-colors hover:bg-accent/50"
                      >
                        <span className="flex items-center justify-between gap-2">
                          <Mono className="text-[11px] text-foreground">
                            {new Date(a.createdAt).toLocaleString(locale)}
                          </Mono>
                          <Mono className="truncate text-[10px] text-muted-foreground">
                            {a.provider}/{a.model}
                          </Mono>
                        </span>
                        <span className="line-clamp-2 text-[11px] leading-relaxed text-muted-foreground">
                          {a.output.slice(0, 120)}
                        </span>
                      </button>
                      {expanded && (
                        <div className="border-t px-3 py-2.5">
                          <ReactMarkdown components={MD}>{a.output}</ReactMarkdown>
                        </div>
                      )}
                    </li>
                  )
                })}
              </ul>
            )}
            <p className="mt-3 flex items-start gap-1.5 border-t pt-3 text-[10.5px] leading-relaxed text-muted-foreground">
              <History className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
              {t('ai.recorded')}
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
