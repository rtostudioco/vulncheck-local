'use client'

// SENTINEL DESK 1.0 — MODULE 06: Incident Timeline
// Chronological reconstruction + relationship graph (incident → alerts →
// evidence events). Dashed links are INFERRED by correlation; solid links are
// directly observed evidence. The chronology list doubles as the accessible
// table alternative for the graph.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useApp } from '@/stores/app-store'
import type { IncidentRecord } from '@/types/soc'
import { SeverityBadge, IncidentStatusBadge, EmptyState, SectionTitle, Mono, LevelBadge } from '@/components/shared/ui-atoms'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { GitBranch, RefreshCw, Eye, Waypoints, Clock, StickyNote } from 'lucide-react'
import { cn } from '@/lib/utils'

const SEV_HEX: Record<string, string> = {
  critical: '#d24b42',
  high: '#e08844',
  medium: '#d9a441',
  low: '#5f8fbd',
  info: '#4db6c4',
}

const LEVEL_HEX: Record<string, string> = {
  Critical: '#d24b42',
  Error: '#e08844',
  Warning: '#d9a441',
  Information: '#4db6c4',
}

export function TimelineView() {
  const t = useApp((s) => s.t)
  const focusId = useApp((s) => s.focusIncidentId)
  const clearFocus = useApp((s) => s.setFocusIncidentId)

  const [incidents, setIncidents] = useState<IncidentRecord[] | null>(null)
  const [error, setError] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)

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
  }, [load])

  useEffect(() => {
    if (focusId) {
      setSelectedId(focusId)
      clearFocus(null)
    }
  }, [focusId, clearFocus])

  const selected = (incidents ?? []).find((i) => i.id === selectedId) ?? null

  if (error) {
    return (
      <EmptyState
        icon={GitBranch}
        title={t('common.error')}
        hint={t('common.errorBody')}
        action={<Button onClick={load} variant="outline" size="sm">{t('common.retry')}</Button>}
      />
    )
  }

  return (
    <div className="space-y-5">
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{t('tl.title')}</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">{t('tl.subtitle')}</p>
          </div>
          <div className="flex items-center gap-2">
            <Select
              value={selectedId ?? ''}
              onValueChange={setSelectedId}
              disabled={!incidents || incidents.length === 0}
            >
              <SelectTrigger className="h-9 w-72" aria-label={t('ai.pickIncident')}>
                <SelectValue placeholder={t('ai.pickIncident')} />
              </SelectTrigger>
              <SelectContent>
                {(incidents ?? []).map((i) => (
                  <SelectItem key={i.id} value={i.id}>
                    {i.code} — {i.title.slice(0, 46)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button size="sm" variant="outline" onClick={load}><RefreshCw className="mr-1.5 h-3.5 w-3.5" />{t('common.refresh')}</Button>
          </div>
        </div>
      </div>

      {incidents === null ? (
        <div className="space-y-4">
          <Skeleton className="h-64" />
          <Skeleton className="h-72" />
        </div>
      ) : incidents.length === 0 || !selected ? (
        <EmptyState icon={GitBranch} title={t('tl.pick')} hint={t('in.empty')} />
      ) : (
        <TimelineContent incident={selected} />
      )}
    </div>
  )
}

// ─── Content ────────────────────────────────────────────────────────────────

function TimelineContent({ incident }: { incident: IncidentRecord }) {
  const t = useApp((s) => s.t)

  // Deduplicated evidence events across all alerts, chronological
  const events = useMemo(() => {
    const byId = new Map<string, { eventId: string; event: NonNullable<IncidentRecord['alerts']>[number]['evidence'][number]; ts: string; alerts: string[] }>()
    for (const a of incident.alerts ?? []) {
      for (const ev of a.evidence) {
        const existing = byId.get(ev.eventId)
        if (existing) {
          if (!existing.alerts.includes(a.ruleId)) existing.alerts.push(a.ruleId)
        } else {
          byId.set(ev.eventId, { eventId: ev.eventId, event: ev, ts: '', alerts: [a.ruleId] })
        }
      }
    }
    return [...byId.values()]
  }, [incident])

  // Full event rows need the event details — alerts carry evidence refs with
  // matched fields only; fetch the incident detail events via API per event.
  const [eventDetails, setEventDetails] = useState<Map<string, DetailRow>>(new Map())
  const [loadingDetail, setLoadingDetail] = useState(false)

  const loadDetails = useCallback(async () => {
    setLoadingDetail(true)
    try {
      const ids = events.map((e) => e.eventId)
      const next = new Map<string, DetailRow>()
      await Promise.all(ids.map(async (id) => {
        try {
          const res = await fetch(`/api/events/${id}`)
          if (!res.ok) return
          const data = await res.json()
          next.set(id, {
            ts: data.event.ts as string,
            channel: data.event.channel as string,
            eventIdNum: data.event.eventId as number,
            level: data.event.level as string,
            computer: data.event.computer as string,
            summary: (data.event.summary ?? '') as string,
            userName: (data.event.userName ?? data.event.targetUserName ?? null) as string | null,
            processName: (data.event.processName ?? null) as string | null,
            commandLine: (data.event.commandLine ?? null) as string | null,
            ipAddress: (data.event.ipAddress ?? null) as string | null,
          })
        } catch { /* skip missing event */ }
      }))
      setEventDetails(next)
    } finally {
      setLoadingDetail(false)
    }
  }, [events])

  useEffect(() => {
    loadDetails()
  }, [loadDetails])

  const chronology = useMemo(() => {
    type Row = {
      kind: 'event' | 'note'
      id: string
      ts: string
      event?: DetailRow
      rules?: string[]
      note?: { author: string; body: string }
    }
    const rows: Row[] = []
    for (const e of events) {
      const d = eventDetails.get(e.eventId)
      if (d) rows.push({ kind: 'event', id: e.eventId, ts: d.ts, event: d, rules: e.alerts })
    }
    for (const n of incident.notes ?? []) {
      rows.push({ kind: 'note', id: n.id, ts: n.createdAt, note: { author: n.author, body: n.body } })
    }
    return rows.sort((a, b) => a.ts.localeCompare(b.ts))
  }, [events, eventDetails, incident.notes])

  return (
    <div className="space-y-4">
      {/* Incident summary strip */}
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <Mono className="text-sm font-semibold text-primary">{incident.code}</Mono>
            <span className="text-sm font-medium">{incident.title}</span>
            <SeverityBadge severity={incident.severity} />
            <IncidentStatusBadge status={incident.status} />
          </div>
          <Mono className="text-[11px] text-muted-foreground">
            {(incident.alerts ?? []).length} {t('common.alerts')} · {events.length} {t('common.events')}
          </Mono>
        </CardContent>
      </Card>

      {/* Relationship graph */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle
            title={t('tl.graph')}
            sub={t('in.graphHint')}
            right={<Waypoints className="h-4 w-4 text-muted-foreground" aria-hidden />}
          />
          <RelationshipGraph incident={incident} eventCount={events.length} eventIds={events.map((e) => e.eventId)} details={eventDetails} />
          {/* Legend */}
          <div className="mt-3 flex flex-wrap items-center gap-4 border-t pt-3 text-[11px] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <svg width="26" height="8" aria-hidden><line x1="0" y1="4" x2="26" y2="4" stroke="#3ba97c" strokeWidth="1.5" /></svg>
              <Eye className="h-3 w-3" aria-hidden /> {t('tl.legendObserved')}
            </span>
            <span className="flex items-center gap-1.5">
              <svg width="26" height="8" aria-hidden><line x1="0" y1="4" x2="26" y2="4" stroke="#8b98a5" strokeWidth="1.5" strokeDasharray="4 3" /></svg>
              {t('tl.legendInferred')}
            </span>
            <span className="flex items-center gap-1.5">
              <ShieldDot /> {t('tl.legendRule')}
            </span>
          </div>
          {/* Accessible alternative */}
          <details className="mt-3">
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-foreground">
              {t('tl.chronology')} — accessible list view
            </summary>
            <ul className="mt-2 space-y-1">
              {chronology.map((r) => (
                <li key={r.id} className="rounded border border-border/50 px-2 py-1 font-mono text-[10.5px] text-muted-foreground">
                  {new Date(r.ts).toLocaleString()} — {r.kind === 'event' ? `EID ${r.event?.eventIdNum} ${r.event?.channel}` : `note (${r.note?.author})`}
                </li>
              ))}
            </ul>
          </details>
        </CardContent>
      </Card>

      {/* Chronology */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle
            title={t('tl.chronology')}
            sub={`${chronology.length} ${t('common.events')}`}
            right={<Clock className="h-4 w-4 text-muted-foreground" aria-hidden />}
          />
          {loadingDetail && chronology.length === 0 ? (
            <div className="space-y-3">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-14" />)}</div>
          ) : (
            <ol className="relative space-y-0">
              {chronology.map((row, idx) => (
                <li key={row.id} className="relative flex gap-4 pb-1">
                  {/* Rail */}
                  <div className="relative flex w-5 shrink-0 flex-col items-center">
                    {idx > 0 && <span className="absolute top-0 h-[calc(50%-8px)] w-px bg-border" aria-hidden />}
                    {idx < chronology.length - 1 && <span className="absolute bottom-0 top-[calc(50%+8px)] w-px bg-border" aria-hidden />}
                    {row.kind === 'event' ? (
                      <span
                        className="z-10 mt-3 h-3 w-3 rounded-full border-2 border-background"
                        style={{ background: LEVEL_HEX[row.event?.level ?? 'Information'] ?? '#4db6c4' }}
                        aria-hidden
                      />
                    ) : (
                      <span className="z-10 mt-3 flex h-3 w-3 items-center justify-center rounded-full bg-muted-foreground/60" aria-hidden />
                    )}
                  </div>
                  {/* Content */}
                  <div className="min-w-0 flex-1 pb-4">
                    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <Mono className="text-[11px] text-muted-foreground">
                        {new Date(row.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </Mono>
                      {row.kind === 'event' && row.event && (
                        <>
                          <Mono className="text-[11px]">EID {row.event.eventIdNum}</Mono>
                          <Badge variant="outline" className="font-mono text-[9.5px] text-muted-foreground">{row.event.channel}</Badge>
                          {row.event.level !== 'Information' && <LevelBadge level={row.event.level} className="text-[9.5px]" />}
                          {(row.rules ?? []).map((r) => (
                            <Badge key={r} variant="outline" className="border-primary/40 font-mono text-[9.5px] text-primary">{r}</Badge>
                          ))}
                        </>
                      )}
                      {row.kind === 'note' && (
                        <Badge variant="outline" className={cn('text-[9.5px]', row.note?.author === 'ai' ? 'sev-medium' : 'sev-info')}>
                          <StickyNote className="mr-1 h-2.5 w-2.5" aria-hidden />
                          {row.note?.author}
                        </Badge>
                      )}
                    </div>
                    {row.kind === 'event' && row.event && (
                      <p className="mt-1 text-xs leading-relaxed text-foreground/90">{row.event.summary}</p>
                    )}
                    {row.kind === 'event' && row.event && (
                      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[10px] text-muted-foreground/80">
                        {row.event.computer && <span>{row.event.computer}</span>}
                        {row.event.userName && <span>user: {row.event.userName}</span>}
                        {row.event.ipAddress && <span>ip: {row.event.ipAddress}</span>}
                      </div>
                    )}
                    {row.kind === 'event' && row.event?.commandLine && (
                      <pre className="scroll-slim mt-1.5 max-h-20 max-w-full overflow-auto whitespace-pre-wrap rounded border border-border/50 bg-muted/30 px-2 py-1 font-mono text-[10px] text-muted-foreground">
                        {row.event.commandLine}
                      </pre>
                    )}
                    {row.kind === 'note' && row.note && (
                      <p className="mt-1 whitespace-pre-wrap rounded-md border border-border/50 bg-muted/30 px-3 py-2 text-xs leading-relaxed text-muted-foreground">
                        {row.note.body}
                      </p>
                    )}
                  </div>
                </li>
              ))}
              {chronology.length === 0 && (
                <p className="py-6 text-center text-xs text-muted-foreground">{t('common.loading')}</p>
              )}
            </ol>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

interface DetailRow {
  ts: string
  channel: string
  eventIdNum: number
  level: string
  computer: string
  summary: string
  userName: string | null
  processName: string | null
  commandLine: string | null
  ipAddress: string | null
}

// ─── Relationship graph (deterministic layered SVG) ─────────────────────────

function ShieldDot() {
  return <span className="inline-block h-2.5 w-2.5 rounded-sm border border-primary/60 bg-primary/30" aria-hidden />
}

function RelationshipGraph({
  incident, eventIds, details,
}: {
  incident: IncidentRecord
  eventCount: number
  eventIds: string[]
  details: Map<string, DetailRow>
}) {
  const W = 820
  const alerts = incident.alerts ?? []
  // Cap rendered event nodes for readability
  const MAX_EVENTS = 18
  const shownEvents = eventIds.slice(0, MAX_EVENTS)
  const overflow = eventIds.length - shownEvents.length

  const alertY = 150
  const eventY = 320
  const H = 410

  const alertX = (i: number) => {
    const n = alerts.length
    if (n === 1) return W / 2
    return 90 + (i * (W - 180)) / (n - 1)
  }
  const eventX = (i: number) => {
    const n = shownEvents.length
    if (n === 1) return W / 2
    return 60 + (i * (W - 120)) / (n - 1)
  }

  if (alerts.length === 0) {
    return <p className="py-10 text-center text-xs text-muted-foreground">{t_es_noAlertsFallback()}</p>
  }

  return (
    <div className="overflow-x-auto scroll-slim">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full min-w-[640px]"
        role="img"
        aria-label={`Relationship graph: ${alerts.length} alerts linked to ${eventIds.length} events`}
      >
        {/* inferred edges: incident → alerts (dashed) */}
        {alerts.map((a, i) => (
          <line
            key={`inf-${a.id}`}
            x1={W / 2} y1={78}
            x2={alertX(i)} y2={alertY - 22}
            stroke="#8b98a5" strokeWidth="1.3" strokeDasharray="5 4"
          >
            <title>Inferred correlation link</title>
          </line>
        ))}
        {/* observed edges: alert → its evidence events (solid) */}
        {alerts.map((a) =>
          a.evidence.slice(0, MAX_EVENTS).map((ev) => {
            const idx = shownEvents.indexOf(ev.eventId)
            if (idx === -1) return null
            const ai = alerts.findIndex((x) => x.id === a.id)
            return (
              <line
                key={`obs-${a.id}-${ev.eventId}`}
                x1={alertX(ai)} y1={alertY + 18}
                x2={eventX(idx)} y2={eventY - 16}
                stroke="#3ba97c" strokeWidth="1.1" strokeOpacity={0.55}
              >
                <title>Observed evidence</title>
              </line>
            )
          }),
        )}

        {/* incident node */}
        <g>
          <rect x={W / 2 - 110} y={30} width={220} height={48} rx={8} fill="#12241a" stroke="#3ba97c" strokeWidth={1.4} />
          <text x={W / 2} y={50} textAnchor="middle" fill="#3ba97c" fontSize={12} fontWeight={600} fontFamily="monospace">
            {incident.code}
          </text>
          <text x={W / 2} y={66} textAnchor="middle" fill="#e8ecf0" fontSize={10.5}>
            {incident.title.slice(0, 34)}{incident.title.length > 34 ? '…' : ''}
          </text>
        </g>

        {/* alert nodes */}
        {alerts.map((a, i) => {
          const x = alertX(i)
          const color = SEV_HEX[a.severity] ?? '#4db6c4'
          const label = a.ruleId
          return (
            <g key={a.id}>
              <rect x={x - 46} y={alertY - 22} width={92} height={40} rx={6} fill="#12161b" stroke={color} strokeWidth={1.2} />
              <text x={x} y={alertY - 5} textAnchor="middle" fill={color} fontSize={10.5} fontWeight={600} fontFamily="monospace">{label}</text>
              <text x={x} y={alertY + 9} textAnchor="middle" fill="#8b98a5" fontSize={9}>
                {a.severity} · {a.evidence.length}ev
              </text>
            </g>
          )
        })}

        {/* event nodes */}
        {shownEvents.map((id, i) => {
          const x = eventX(i)
          const d = details.get(id)
          const levelColor = LEVEL_HEX[d?.level ?? 'Information'] ?? '#4db6c4'
          return (
            <g key={id}>
              <rect x={x - 34} y={eventY - 16} width={68} height={34} rx={5} fill="#151a20" stroke="#2a333c" strokeWidth={1} />
              <circle cx={x - 22} cy={eventY - 4} r={3} fill={levelColor} />
              <text x={x + 4} y={eventY - 1} textAnchor="middle" fill="#cdd6de" fontSize={9.5} fontFamily="monospace">
                {d ? String(d.eventIdNum) : id.slice(-6)}
              </text>
              <text x={x} y={eventY + 12} textAnchor="middle" fill="#8b98a5" fontSize={8} fontFamily="monospace">
                {(d?.channel ?? 'event').replace('/Operational', '/*').slice(0, 12)}
              </text>
              <title>{d?.summary ?? id}</title>
            </g>
          )
        })}
        {overflow > 0 && (
          <text x={W - 24} y={eventY + 4} textAnchor="end" fill="#8b98a5" fontSize={10} fontFamily="monospace">
            +{overflow} more
          </text>
        )}
      </svg>
    </div>
  )
}

function t_es_noAlertsFallback(): string {
  // Graph has nothing to draw without alerts; incidents always have ≥1 alert,
  // so this is a defensive fallback rather than user-facing copy.
  return 'No alerts linked to this incident.'
}
