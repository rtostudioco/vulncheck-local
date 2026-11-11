'use client'

// SENTINEL DESK 1.0 — MODULE 02: Live Monitor
// Real-time event stream inspection: filterable event table + normalized
// detail panel with provenance, related alerts and raw payload.

import { Fragment, useCallback, useEffect, useRef, useState, type KeyboardEvent } from 'react'
import { useApp } from '@/stores/app-store'
import type { EventRecord, PipelineRun } from '@/types/soc'
import { LevelBadge, SeverityBadge, EmptyState, Mono, SectionTitle } from '@/components/shared/ui-atoms'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'
import {
  Activity, ChevronDown, ChevronLeft, ChevronRight, Loader2, Pause, Play, Search, Zap,
} from 'lucide-react'

const PAGE_SIZE = 50
const AUTO_INTERVAL_MS = 10_000
const DEBOUNCE_MS = 300

const CHANNELS = [
  'Security',
  'System',
  'PowerShell/Operational',
  'TaskScheduler/Operational',
  'Sysmon',
] as const

const LEVELS = ['Information', 'Warning', 'Error', 'Critical'] as const

interface EventsResponse {
  total: number
  page: number
  pageSize: number
  events: EventRecord[]
}

interface CollectorStatus {
  running: boolean
  intervalSec: number
  lastTickAt: string | null
  lastRun: PipelineRun | null
}

interface DetailAlertRef {
  id: string
  ruleId: string
  title: string
  severity: string
  incidentId: string | null
}

interface EventDetailResponse {
  event: EventRecord
  raw: unknown
  alerts: DetailAlertRef[]
}

interface FieldRow {
  label: string
  value: string
  wide?: boolean
}

/** Normalized schema fields shown in the detail panel — labels are the
 *  common-schema field identifiers themselves (they are not UI copy). */
function buildFieldRows(ev: EventRecord): FieldRow[] {
  const rows: FieldRow[] = []
  const push = (label: string, value: string | number | null | undefined, wide = false) => {
    if (value === null || value === undefined || value === '') return
    rows.push({ label, value: String(value), wide })
  }
  push('computer', ev.computer)
  push('userName', ev.userName)
  push('targetUserName', ev.targetUserName)
  push('processId', ev.processId)
  push('processName', ev.processName)
  push('parentProcessName', ev.parentProcessName)
  push('commandLine', ev.commandLine, true)
  push('ipAddress', ev.ipAddress)
  push('logonType', ev.logonType)
  push('serviceName', ev.serviceName)
  push('taskName', ev.taskName)
  push('summary', ev.summary, true)
  return rows
}

function fmtTime(ts: string): string {
  return new Date(ts).toLocaleTimeString([], {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  })
}

function basename(path: string): string {
  const idx = path.lastIndexOf('\\')
  return idx >= 0 ? path.slice(idx + 1) : path
}

export function LiveMonitorView() {
  const t = useApp((s) => s.t)

  // ── Data state ─────────────────────────────────────────────────────────
  const [events, setEvents] = useState<EventRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  // ── Filters / pagination ───────────────────────────────────────────────
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [channel, setChannel] = useState<string>('all')
  const [level, setLevel] = useState<string>('all')
  const [hours, setHours] = useState<string>('0') // '0' = all, '24', '168'
  const [page, setPage] = useState(1)

  // ── Collector ──────────────────────────────────────────────────────────
  const [collectorRunning, setCollectorRunning] = useState<boolean | null>(null)
  const [collectorBusy, setCollectorBusy] = useState<'start' | 'stop' | null>(null)
  const [ticking, setTicking] = useState(false)

  // ── Detail panel ───────────────────────────────────────────────────────
  const [selected, setSelected] = useState<EventRecord | null>(null)
  const [detail, setDetail] = useState<EventDetailResponse | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState(false)

  // ── Auto-refresh ───────────────────────────────────────────────────────
  const [auto, setAuto] = useState(false)

  // Sequence guards: only the latest request may write state (races from
  // filter changes + auto-refresh would otherwise interleave).
  const eventsSeq = useRef(0)
  const detailSeq = useRef(0)

  const hasActiveFilters =
    debouncedQuery.trim() !== '' || channel !== 'all' || level !== 'all' || hours !== '0'

  // ── Event list fetching ────────────────────────────────────────────────
  const loadEvents = useCallback(async (silent = false) => {
    const seq = ++eventsSeq.current
    try {
      const params = new URLSearchParams()
      const q = debouncedQuery.trim()
      if (q) params.set('q', q)
      params.set('channel', channel)
      params.set('level', level)
      params.set('hours', hours)
      params.set('page', String(page))
      params.set('pageSize', String(PAGE_SIZE))
      const res = await fetch(`/api/events?${params.toString()}`)
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as EventsResponse
      if (eventsSeq.current !== seq) return
      setEvents(data.events)
      setTotal(data.total)
      setError(false)
    } catch {
      if (eventsSeq.current !== seq) return
      // Background (auto) refreshes never hide already-loaded data.
      if (!silent || events.length === 0) setError(true)
    } finally {
      if (eventsSeq.current === seq) setLoading(false)
    }
  }, [debouncedQuery, channel, level, hours, page, events.length])

  // Debounce the search input
  useEffect(() => {
    const id = setTimeout(() => setDebouncedQuery(query), DEBOUNCE_MS)
    return () => clearTimeout(id)
  }, [query])

  // Any filter change restarts pagination
  useEffect(() => {
    setPage(1)
  }, [debouncedQuery, channel, level, hours])

  // Load on mount and whenever filters/pagination change
  useEffect(() => {
    void loadEvents()
  }, [loadEvents])

  // Auto-refresh loop (10s polling — no WebSocket in this view)
  useEffect(() => {
    if (!auto) return
    const id = setInterval(() => void loadEvents(true), AUTO_INTERVAL_MS)
    return () => clearInterval(id)
  }, [auto, loadEvents])

  // ── Collector controls ─────────────────────────────────────────────────
  const refreshCollector = useCallback(async () => {
    try {
      const res = await fetch('/api/collector')
      if (!res.ok) return
      const data = (await res.json()) as CollectorStatus
      setCollectorRunning(data.running)
    } catch { /* keep previous state */ }
  }, [])

  useEffect(() => {
    void refreshCollector()
  }, [refreshCollector])

  const setCollector = async (action: 'start' | 'stop') => {
    setCollectorBusy(action)
    try {
      const res = await fetch('/api/collector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      })
      if (res.ok) {
        const data = (await res.json()) as { running: boolean }
        setCollectorRunning(data.running)
      }
    } catch { /* keep previous state; button re-enables */ } finally {
      setCollectorBusy(null)
    }
  }

  const tickNow = async () => {
    setTicking(true)
    try {
      const res = await fetch('/api/collector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'tick' }),
      })
      if (!res.ok) throw new Error('bad status')
      const data = await res.json()
      // Notify the app shell so manual ticks feed the notification center too
      if (data?.run) {
        window.dispatchEvent(new CustomEvent('sentinel:tick', { detail: data.run }))
      }
      await Promise.all([loadEvents(true), refreshCollector()])
    } catch {
      if (events.length === 0) setError(true)
    } finally {
      setTicking(false)
    }
  }

  // ── Detail panel ───────────────────────────────────────────────────────
  const openDetail = useCallback(async (ev: EventRecord) => {
    const seq = ++detailSeq.current
    setSelected(ev)
    setDetail(null)
    setDetailError(false)
    setDetailLoading(true)
    try {
      const res = await fetch(`/api/events/${encodeURIComponent(ev.id)}`)
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as EventDetailResponse
      if (detailSeq.current !== seq) return
      setDetail(data)
    } catch {
      if (detailSeq.current !== seq) return
      setDetailError(true)
    } finally {
      if (detailSeq.current === seq) setDetailLoading(false)
    }
  }, [])

  const onRowKeyDown = (e: KeyboardEvent<HTMLTableRowElement>, ev: EventRecord) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      void openDetail(ev)
    }
  }

  // ── Derived values ─────────────────────────────────────────────────────
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const rangeStart = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const rangeEnd = Math.min(page * PAGE_SIZE, total)
  const detailEvent = detail?.event ?? selected
  const fieldRows = detailEvent ? buildFieldRows(detailEvent) : []

  // ── Initial loading skeleton (matches overview tone) ───────────────────
  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-[68px] w-full" />
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
          <Skeleton className="h-[480px]" />
          <Skeleton className="h-[480px]" />
        </div>
      </div>
    )
  }

  // ── Fatal error (nothing loaded at all) ────────────────────────────────
  if (error && events.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        title={t('common.error')}
        hint={t('common.errorBody')}
        action={<Button onClick={() => void loadEvents()} variant="outline" size="sm">{t('common.retry')}</Button>}
      />
    )
  }

  return (
    <div className="space-y-4">
      {/* ── Page heading ──────────────────────────────────────────────── */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{t('lm.title')}</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">{t('lm.subtitle')}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {collectorRunning ? (
              <Button
                size="sm"
                variant="outline"
                onClick={() => void setCollector('stop')}
                disabled={collectorBusy !== null}
              >
                {collectorBusy === 'stop'
                  ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
                  : <Pause className="mr-1.5 h-3.5 w-3.5" aria-hidden />}
                {t('lm.stop')}
              </Button>
            ) : (
              <Button
                size="sm"
                variant="outline"
                onClick={() => void setCollector('start')}
                disabled={collectorBusy !== null || collectorRunning === null}
              >
                {collectorBusy === 'start'
                  ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
                  : <Play className="mr-1.5 h-3.5 w-3.5" aria-hidden />}
                {t('lm.start')}
              </Button>
            )}
            <Button size="sm" onClick={() => void tickNow()} disabled={ticking}>
              {ticking
                ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
                : <Zap className="mr-1.5 h-3.5 w-3.5" aria-hidden />}
              {t('lm.tickNow')}
            </Button>
          </div>
        </div>
      </div>

      {/* ── Filter bar ────────────────────────────────────────────────── */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-3 p-5">
          <div className="min-w-[220px] flex-1">
            <label htmlFor="lm-search" className="sr-only">{t('lm.filter.query')}</label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <Input
                id="lm-search"
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('lm.filter.query')}
                className="pl-8"
                autoComplete="off"
              />
            </div>
          </div>

          <div>
            <label htmlFor="lm-channel" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {t('lm.filter.channel')}
            </label>
            <Select value={channel} onValueChange={(v) => setChannel(v)}>
              <SelectTrigger id="lm-channel" className="w-[190px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('common.all')}</SelectItem>
                {CHANNELS.map((c) => (
                  <SelectItem key={c} value={c}><Mono>{c}</Mono></SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <label htmlFor="lm-level" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {t('lm.filter.level')}
            </label>
            <Select value={level} onValueChange={(v) => setLevel(v)}>
              <SelectTrigger id="lm-level" className="w-[140px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('common.all')}</SelectItem>
                {LEVELS.map((l) => (
                  <SelectItem key={l} value={l}>{t(`lm.level.${l}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <label htmlFor="lm-range" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {t('rp.range')}
            </label>
            <Select value={hours} onValueChange={(v) => setHours(v)}>
              <SelectTrigger id="lm-range" className="w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="0">{t('common.all')}</SelectItem>
                <SelectItem value="24">{t('rp.range.24h')}</SelectItem>
                <SelectItem value="168">{t('rp.range.7d')}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="ml-auto flex items-center gap-2.5 pb-1">
            <Switch id="lm-auto" checked={auto} onCheckedChange={setAuto} aria-label={t('lm.auto')} />
            <label htmlFor="lm-auto" className="cursor-pointer select-none text-xs text-muted-foreground">
              {t('lm.auto')} <span className="font-mono text-foreground">10{t('common.sec')}</span>
            </label>
          </div>
        </CardContent>
      </Card>

      {/* ── Table + detail panel ──────────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
        <Card>
          <CardContent className="p-5">
            {events.length === 0 ? (
              <EmptyState
                title={hasActiveFilters ? t('lm.noEvents') : t('es.noEvents')}
                hint={hasActiveFilters ? undefined : t('lm.subtitle')}
              />
            ) : (
              <>
                <div className="scroll-slim max-h-[600px] overflow-y-auto rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="sticky top-0 z-10 border-b bg-card text-[10px] uppercase tracking-wider text-muted-foreground">{t('lm.col.time')}</TableHead>
                        <TableHead className="sticky top-0 z-10 border-b bg-card text-[10px] uppercase tracking-wider text-muted-foreground">{t('lm.col.channel')}</TableHead>
                        <TableHead className="sticky top-0 z-10 border-b bg-card text-[10px] uppercase tracking-wider text-muted-foreground">{t('lm.col.eventId')}</TableHead>
                        <TableHead className="sticky top-0 z-10 border-b bg-card text-[10px] uppercase tracking-wider text-muted-foreground">{t('lm.col.level')}</TableHead>
                        <TableHead className="sticky top-0 z-10 border-b bg-card text-[10px] uppercase tracking-wider text-muted-foreground">{t('lm.col.computer')}</TableHead>
                        <TableHead className="sticky top-0 z-10 border-b bg-card text-[10px] uppercase tracking-wider text-muted-foreground">{t('lm.col.user')}</TableHead>
                        <TableHead className="sticky top-0 z-10 border-b bg-card text-[10px] uppercase tracking-wider text-muted-foreground">{t('lm.col.process')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {events.map((ev) => {
                        const isSelected = selected?.id === ev.id
                        const user = ev.userName ?? ev.targetUserName ?? null
                        const proc = ev.processName ? basename(ev.processName) : null
                        return (
                          <TableRow
                            key={ev.id}
                            tabIndex={0}
                            aria-selected={isSelected}
                            onClick={() => void openDetail(ev)}
                            onKeyDown={(e) => onRowKeyDown(e, ev)}
                            className={cn(
                              'cursor-pointer py-2.5',
                              isSelected && 'bg-accent hover:bg-accent',
                            )}
                          >
                            <TableCell className="py-2.5">
                              <Mono className="tabular-nums">{fmtTime(ev.ts)}</Mono>
                            </TableCell>
                            <TableCell className="py-2.5">
                              <span className="block max-w-[160px] truncate" title={ev.channel}>
                                <Mono className="text-muted-foreground">{ev.channel}</Mono>
                              </span>
                            </TableCell>
                            <TableCell className="py-2.5">
                              <Mono className="tabular-nums">{ev.eventId}</Mono>
                            </TableCell>
                            <TableCell className="py-2.5">
                              <LevelBadge level={ev.level} />
                            </TableCell>
                            <TableCell className="py-2.5">
                              <span className="block max-w-[120px] truncate" title={ev.computer}>
                                <Mono className="text-muted-foreground">{ev.computer}</Mono>
                              </span>
                            </TableCell>
                            <TableCell className="py-2.5">
                              {user
                                ? <span className="block max-w-[120px] truncate" title={user}><Mono>{user}</Mono></span>
                                : <span className="text-muted-foreground">—</span>}
                            </TableCell>
                            <TableCell className="py-2.5">
                              {proc
                                ? <span className="block max-w-[140px] truncate" title={ev.processName ?? proc}><Mono>{proc}</Mono></span>
                                : <span className="text-muted-foreground">—</span>}
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>

                {/* Pagination */}
                <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t pt-3">
                  <p className="text-xs text-muted-foreground">
                    {total === 0
                      ? <>0 {t('common.of')} 0</>
                      : <>{t('common.showing')} <span className="font-mono tabular-nums">{rangeStart}–{rangeEnd}</span> {t('common.of')} <span className="font-mono tabular-nums">{total}</span></>}
                  </p>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={page <= 1}
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                    >
                      <ChevronLeft className="mr-1 h-3.5 w-3.5" aria-hidden />
                      {t('common.prev')}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={page >= totalPages}
                      onClick={() => setPage((p) => p + 1)}
                    >
                      {t('common.next')}
                      <ChevronRight className="ml-1 h-3.5 w-3.5" aria-hidden />
                    </Button>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* ── Detail panel ──────────────────────────────────────────────── */}
        <Card>
          <CardContent className="p-5">
            {!selected && !detailLoading && !detailError ? (
              <div className="flex min-h-[320px] items-center justify-center">
                <p className="max-w-[240px] text-center text-xs leading-relaxed text-muted-foreground">
                  {t('lm.detailEmpty')}
                </p>
              </div>
            ) : detailLoading ? (
              <div className="space-y-3" aria-busy>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-4 w-48" />
                <div className="pt-2" />
                {[...Array(7)].map((_, i) => <Skeleton key={i} className="h-4 w-full" />)}
              </div>
            ) : detailError && !detailEvent ? (
              <EmptyState
                icon={Activity}
                title={t('common.error')}
                hint={t('common.errorBody')}
                action={
                  <Button size="sm" variant="outline" onClick={() => selected && void openDetail(selected)}>
                    {t('common.retry')}
                  </Button>
                }
              />
            ) : detailEvent ? (
              <div className="space-y-5">
                {/* Header */}
                <div>
                  <SectionTitle title={t('lm.detail')} />
                  <div className="flex flex-wrap items-center gap-2">
                    <LevelBadge level={detailEvent.level} />
                    <Mono className="text-[13px] font-semibold">#{detailEvent.eventId}</Mono>
                  </div>
                  <p className="mt-1.5 text-xs text-muted-foreground">
                    <Mono className="text-muted-foreground">{detailEvent.channel}</Mono>
                    <span className="mx-1.5" aria-hidden>·</span>
                    <Mono className="text-muted-foreground">{detailEvent.provider}</Mono>
                  </p>
                </div>

                {/* Normalized fields */}
                {fieldRows.length > 0 && (
                  <dl className="grid grid-cols-[104px_minmax(0,1fr)] gap-x-3 gap-y-2">
                    {fieldRows.map((row) =>
                      row.wide ? (
                        <div key={row.label} className="col-span-2">
                          <dt className="break-all font-mono text-[10px] leading-4 text-muted-foreground">{row.label}</dt>
                          <dd>
                            <Mono className="mt-0.5 block break-all whitespace-pre-wrap text-[11.5px] leading-relaxed">{row.value}</Mono>
                          </dd>
                        </div>
                      ) : (
                        <Fragment key={row.label}>
                          <dt className="break-all font-mono text-[10px] leading-5 text-muted-foreground">{row.label}</dt>
                          <dd>
                            <Mono className="block break-all text-[11.5px] leading-5">{row.value}</Mono>
                          </dd>
                        </Fragment>
                      ),
                    )}
                  </dl>
                )}

                {/* Provenance */}
                <div className="border-t pt-4">
                  <SectionTitle title={t('lm.provenance')} />
                  <div className="space-y-2.5">
                    {detailEvent.synthetic && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge
                            variant="outline"
                            tabIndex={0}
                            className="sev-info cursor-help text-[10px] font-semibold tracking-wider"
                            aria-label={t('app.demoTooltip')}
                          >
                            {t('app.demo')}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-[260px]">
                          <p className="text-balance">{t('app.demoTooltip')}</p>
                        </TooltipContent>
                      </Tooltip>
                    )}
                    {detailEvent.sourceRef && (
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">sourceRef</p>
                        <Mono className="mt-0.5 block break-all text-[11px] leading-relaxed">{detailEvent.sourceRef}</Mono>
                      </div>
                    )}
                  </div>
                </div>

                {/* Related alerts */}
                {detail && detail.alerts.length > 0 && (
                  <div className="border-t pt-4">
                    <SectionTitle title={t('in.alerts')} />
                    <ul className="space-y-2">
                      {detail.alerts.map((a) => (
                        <li key={a.id} className="rounded-md border border-border/60 p-2.5">
                          <div className="flex items-center justify-between gap-2">
                            <Mono className="truncate text-[11px]">{a.ruleId}</Mono>
                            <SeverityBadge severity={a.severity} className="text-[10px]" />
                          </div>
                          {a.title && <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{a.title}</p>}
                          {a.incidentId && (
                            <p className="mt-1.5">
                              <Mono className="text-[10.5px] text-primary">{a.incidentId}</Mono>
                            </p>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Raw payload */}
                {detail?.raw != null && (
                  <div className="border-t pt-4">
                    <Collapsible>
                      <CollapsibleTrigger className="group flex w-full items-center justify-between rounded-md py-1 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
                        <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                          {t('lm.raw')}
                        </span>
                        <ChevronDown className="h-3.5 w-3.5 text-muted-foreground transition-transform group-data-[state=open]:rotate-180" aria-hidden />
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <pre className="scroll-slim mt-2 max-h-56 overflow-auto rounded border bg-muted/40 p-2 font-mono text-[10.5px]">
                          {JSON.stringify(detail.raw, null, 2)}
                        </pre>
                      </CollapsibleContent>
                    </Collapsible>
                  </div>
                )}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
