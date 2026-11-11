'use client'

// SENTINEL DESK 1.0 — MODULE 05: Incident Center + MODULE 06 evidence views
// Master/detail layout. Every incident stays traceable to source events.
// Correlation hypotheses are always labeled as hypotheses — never confirmations.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { useApp } from '@/stores/app-store'
import type { AlertRecord, AiAnalysisRecord, IncidentNoteRecord, IncidentRecord } from '@/types/soc'
import {
  SeverityBadge, IncidentStatusBadge, EmptyState, SectionTitle, Mono, ConfidenceBar,
} from '@/components/shared/ui-atoms'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Markdown } from '@/components/shared/markdown'
import {
  ChevronDown, ChevronRight, FolderSearch, GitBranch, Link2, Loader2,
  Network, Plus, Bot, RefreshCw, StickyNote, Clock, ShieldAlert,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const STATUSES = ['new', 'investigating', 'monitoring', 'resolved', 'false_positive'] as const

export function IncidentsView() {
  const t = useApp((s) => s.t)
  const setView = useApp((s) => s.setView)
  const setFocusIncidentId = useApp((s) => s.setFocusIncidentId)
  const focusId = useApp((s) => s.focusIncidentId)

  const [incidents, setIncidents] = useState<IncidentRecord[] | null>(null)
  const [error, setError] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const load = useCallback(async () => {
    try {
      setError(false)
      const res = await fetch('/api/incidents')
      if (!res.ok) throw new Error()
      const data = await res.json()
      setIncidents(data.incidents)
    } catch {
      setError(true)
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [load])

  useEffect(() => {
    if (focusId) {
      setSelectedId(focusId)
      useApp.getState().setFocusIncidentId(null)
    }
  }, [focusId])

  const filtered = useMemo(
    () => (incidents ?? []).filter((i) => statusFilter === 'all' || i.status === statusFilter),
    [incidents, statusFilter],
  )
  const selected = filtered.find((i) => i.id === selectedId) ?? null

  const updateStatus = async (id: string, status: string) => {
    try {
      const res = await fetch(`/api/incidents/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      })
      if (!res.ok) throw new Error()
      await load()
      toast.success(t('in.updateStatus'))
    } catch {
      toast.error(t('common.error'))
    }
  }

  if (error) {
    return (
      <EmptyState
        icon={FolderSearch}
        title={t('common.error')}
        hint={t('common.errorBody')}
        action={<Button onClick={load} variant="outline" size="sm">{t('common.retry')}</Button>}
      />
    )
  }

  return (
    <div className="space-y-5">
      {/* Heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{t('in.title')}</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">{t('in.subtitle')}</p>
          </div>
          <div className="flex items-center gap-2">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="h-9 w-44" aria-label={t('in.status')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('common.all')}</SelectItem>
                {STATUSES.map((s) => <SelectItem key={s} value={s}>{t(`in.st.${s}`)}</SelectItem>)}
              </SelectContent>
            </Select>
            <Button size="sm" variant="outline" onClick={load}><RefreshCw className="mr-1.5 h-3.5 w-3.5" />{t('common.refresh')}</Button>
          </div>
        </div>
      </div>

      {incidents === null ? (
        <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
          <Skeleton className="h-96" />
          <Skeleton className="h-96" />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={FolderSearch}
          title={t('in.empty')}
          hint={t('ov.pipelineNone')}
        />
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-[340px_1fr]">
          {/* Master list */}
          <Card>
            <CardContent className="p-2">
              <ul className="scroll-slim max-h-[70vh] space-y-1 overflow-y-auto p-1">
                {filtered.map((i) => (
                  <li key={i.id}>
                    <button
                      onClick={() => setSelectedId(i.id)}
                      aria-current={selectedId === i.id}
                      className={cn(
                        'w-full rounded-md border border-transparent px-3 py-2.5 text-left transition-colors',
                        selectedId === i.id ? 'border-primary/40 bg-accent' : 'hover:bg-accent/60',
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <Mono className="text-[11px] font-semibold text-primary">{i.code}</Mono>
                        <SeverityBadge severity={i.severity} className="text-[10px]" />
                      </div>
                      <p className="mt-1 truncate text-xs font-medium">{i.title}</p>
                      <div className="mt-1.5 flex items-center justify-between gap-2">
                        <IncidentStatusBadge status={i.status} className="text-[10px]" />
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {new Date(i.updatedAt).toLocaleDateString()} {new Date(i.updatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {/* Detail */}
          {selected ? (
            <IncidentDetail
              key={selected.id}
              incident={selected}
              onStatus={updateStatus}
              onOpenTimeline={() => {
                setFocusIncidentId(selected.id)
                setView('timeline')
              }}
            />
          ) : (
            <Card>
              <CardContent className="flex h-64 items-center justify-center">
                <p className="text-sm text-muted-foreground">{t('in.detail')}</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Detail panel ───────────────────────────────────────────────────────────

function IncidentDetail({
  incident, onStatus, onOpenTimeline,
}: {
  incident: IncidentRecord
  onStatus: (id: string, status: string) => Promise<void>
  onOpenTimeline: () => void
}) {
  const t = useApp((s) => s.t)
  const [alertsOpen, setAlertsOpen] = useState<Set<string>>(new Set())

  const meta = incident.correlationMeta

  const toggleAlert = (id: string) => {
    setAlertsOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-4">
      {/* Header card */}
      <Card>
        <CardContent className="p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <Mono className="text-sm font-semibold text-primary">{incident.code}</Mono>
                <SeverityBadge severity={incident.severity} />
                <IncidentStatusBadge status={incident.status} />
              </div>
              <h2 className="mt-2 text-base font-semibold leading-snug">{incident.title}</h2>
              <p className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{t('in.created')}: {new Date(incident.createdAt).toLocaleString()}</span>
                <span>{t('in.updated')}: {new Date(incident.updatedAt).toLocaleString()}</span>
              </p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <Select value={incident.status} onValueChange={(v) => onStatus(incident.id, v)}>
                <SelectTrigger className="h-9 w-44" aria-label={t('in.updateStatus')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STATUSES.map((s) => <SelectItem key={s} value={s}>{t(`in.st.${s}`)}</SelectItem>)}
                </SelectContent>
              </Select>
              <Button size="sm" variant="outline" onClick={onOpenTimeline}>
                <GitBranch className="mr-1.5 h-3.5 w-3.5" />{t('in.timeline')}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Hypothesis — explicitly labeled as hypothesis */}
      <Card className="border-[#5a4a1e]/60">
        <CardContent className="p-5">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-[#e5bc55]" aria-hidden />
            <h3 className="text-sm font-semibold text-[#e5bc55]">{t('in.hypothesis')}</h3>
          </div>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{incident.hypothesis}</p>
          {meta && (
            <div className="mt-3 flex flex-wrap items-center gap-2 border-t pt-3">
              <Link2 className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
              <span className="text-xs text-muted-foreground">{t('in.linkedBy')}:</span>
              {meta.fields.map((f) => <Badge key={f} variant="outline" className="font-mono text-[10px]">{f}</Badge>)}
              <span className="text-xs text-muted-foreground">· {t('in.timeWindow')}: {Math.round(meta.windowSec / 60)} {t('common.min')}{meta.host ? ` · ${meta.host}` : ''}</span>
              <Badge variant="outline" className="sev-info text-[10px]">inferred</Badge>
            </div>
          )}
          <p className="mt-3 text-[11px] italic text-muted-foreground/80">{t('in.inferred')}</p>
        </CardContent>
      </Card>

      {/* Related alerts with evidence */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle title={t('in.alerts')} sub={t('in.evidence', { n: incident.alerts?.length ?? 0 })} />
          <ul className="space-y-2">
            {(incident.alerts ?? []).map((a) => (
              <AlertEvidenceRow
                key={a.id}
                alert={a}
                open={alertsOpen.has(a.id)}
                onToggle={() => toggleAlert(a.id)}
              />
            ))}
          </ul>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        {/* AI summary */}
        <AiSummaryCard incidentId={incident.id} analyses={incident.aiAnalyses ?? []} />

        {/* Notes */}
        <NotesCard incidentId={incident.id} notes={incident.notes ?? []} />
      </div>
    </div>
  )
}

// ─── Alert evidence row ─────────────────────────────────────────────────────

function AlertEvidenceRow({ alert, open, onToggle }: { alert: AlertRecord; open: boolean; onToggle: () => void }) {
  const t = useApp((s) => s.t)
  return (
    <li className="rounded-md border border-border/70">
      <button
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left transition-colors hover:bg-accent/50"
      >
        {open ? <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />}
        <Mono className="shrink-0 text-[11px] font-semibold text-primary">{alert.ruleId}</Mono>
        <span className="min-w-0 flex-1 truncate text-xs">{alert.summary}</span>
        <SeverityBadge severity={alert.severity} className="hidden shrink-0 text-[10px] sm:inline-flex" />
      </button>
      {open && (
        <div className="border-t px-3 py-3">
          <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            {alert.mitreId && <Mono>{t('dt.mitre')}: {alert.mitreId}</Mono>}
            {alert.computer && <Mono>{alert.computer}</Mono>}
            {alert.userName && <Mono>{alert.userName}</Mono>}
          </div>
          <ConfidenceBar value={alert.confidence} />
          <p className="mt-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{t('in.matchedFields')}</p>
          <ul className="mt-1.5 space-y-1">
            {alert.evidence.map((ev) => (
              <li key={ev.eventId} className="rounded border border-border/50 bg-muted/30 px-2 py-1.5">
                <Mono className="text-[10.5px] text-muted-foreground">
                  event {ev.eventId.slice(-8)}
                </Mono>
                <div className="mt-1 flex flex-wrap gap-1">
                  {ev.matched.map((m, j) => (
                    <Badge key={j} variant="outline" className="font-mono text-[9.5px] text-muted-foreground">
                      {m.field} {m.op === 'regex' ? '~' : m.op === 'in' ? '∈' : '='} {m.value.length > 42 ? m.value.slice(0, 42) + '…' : m.value}
                    </Badge>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  )
}

// ─── AI summary ─────────────────────────────────────────────────────────────

function AiSummaryCard({ incidentId, analyses }: { incidentId: string; analyses: IncidentRecord['aiAnalyses'] }) {
  const t = useApp((s) => s.t)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(false)
  const [list, setList] = useState<AiAnalysisRecord[]>(analyses ?? [])
  const [openId, setOpenId] = useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setErr(false)
    try {
      const res = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incidentId }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data?.error ?? 'failed')
      if (data.analysis) {
        setList((prev) => [data.analysis, ...prev])
        setOpenId(data.analysis.id)
      }
    } catch {
      setErr(true)
      toast.error(t('ai.error'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardContent className="p-5">
        <SectionTitle
          title={t('in.aiSummary')}
          right={
            <Button size="sm" onClick={run} disabled={busy}>
              {busy ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Bot className="mr-1.5 h-3.5 w-3.5" />}
              {busy ? t('ai.analyzing') : t('in.askAi')}
            </Button>
          }
        />
        <div className="mb-3 flex items-start gap-2 rounded-md border border-[#1d454e] bg-[#0e272c]/40 px-3 py-2">
          <Bot className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#5cbecd]" aria-hidden />
          <p className="text-[11px] leading-relaxed text-[#5cbecd]">{t('in.aiDisclaimer')}</p>
        </div>
        {err && <p className="mb-2 text-xs text-[#f07a72]">{t('ai.error')}</p>}
        {list.length === 0 ? (
          <p className="py-6 text-center text-xs text-muted-foreground">{t('ai.historyEmpty')}</p>
        ) : (
          <ul className="scroll-slim max-h-96 space-y-2 overflow-y-auto">
            {list.map((a) => (
              <li key={a.id} className="rounded-md border border-border/70">
                <button
                  className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left hover:bg-accent/50"
                  onClick={() => setOpenId(openId === a.id ? null : a.id)}
                  aria-expanded={openId === a.id}
                >
                  <Mono className="text-[10.5px] text-muted-foreground">
                    {a.provider} · {a.model} · {new Date(a.createdAt).toLocaleString()}
                  </Mono>
                  {openId === a.id ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                </button>
                {openId === a.id && (
                  <div className="border-t px-3 py-3">
                    <Markdown content={a.output} />
                    <p className="mt-2 border-t pt-2 font-mono text-[10px] text-muted-foreground/70">
                      {t('ai.promptVersion')}: {a.promptVersion} · privacy: {a.privacyMode}
                    </p>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

// ─── Notes ──────────────────────────────────────────────────────────────────

function NotesCard({
  incidentId, notes,
}: {
  incidentId: string
  notes: IncidentRecord['notes']
}) {
  const t = useApp((s) => s.t)
  const [list, setList] = useState<IncidentNoteRecord[]>(notes ?? [])
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)

  const add = async () => {
    const body = text.trim()
    if (!body) return
    setBusy(true)
    try {
      const res = await fetch(`/api/incidents/${incidentId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ body }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error()
      setList((prev) => [...prev, data.note])
      setText('')
    } catch {
      toast.error(t('common.error'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardContent className="p-5">
        <SectionTitle title={t('in.notes')} right={<StickyNote className="h-4 w-4 text-muted-foreground" aria-hidden />} />
        <ul className="scroll-slim mb-3 max-h-64 space-y-2 overflow-y-auto">
          {list.map((n) => (
            <li key={n.id} className="rounded-md border border-border/60 px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <Badge variant="outline" className={cn(
                  'text-[9.5px] font-medium',
                  n.author === 'analyst' ? 'sev-info' : n.author === 'system' ? 'sev-low' : 'sev-medium',
                )}>
                  {n.author}
                </Badge>
                <Mono className="text-[10px] text-muted-foreground">{new Date(n.createdAt).toLocaleString()}</Mono>
              </div>
              <p className="mt-1.5 whitespace-pre-wrap text-xs leading-relaxed text-muted-foreground">{n.body}</p>
            </li>
          ))}
          {list.length === 0 && <p className="py-4 text-center text-xs text-muted-foreground">{t('tl.noNotes')}</p>}
        </ul>
        <div className="space-y-2">
          <Textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={t('in.notePlaceholder')}
            className="min-h-20 resize-y"
            aria-label={t('in.notePlaceholder')}
          />
          <Button size="sm" onClick={add} disabled={busy || !text.trim()}>
            {busy ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Plus className="mr-1.5 h-3.5 w-3.5" />}
            {t('in.addNote')}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
