'use client'

// SENTINEL DESK 1.0 — MODULE 01: Security Overview
// Reference implementation for view structure, data fetching and design system usage.

import { useCallback, useEffect, useState } from 'react'
import { useApp } from '@/stores/app-store'
import type { OverviewPayload } from '@/types/soc'
import { StatCard, SeverityBadge, SourceStatusBadge, EmptyState, SectionTitle, Mono } from '@/components/shared/ui-atoms'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import {
  Activity, BellRing, FolderSearch, ShieldCheck, RefreshCw, Play, Clock,
  Database, Cpu, ArrowRight, Server,
} from 'lucide-react'

const SEV_COLORS: Record<string, string> = {
  critical: '#d24b42',
  high: '#e08844',
  medium: '#d9a441',
  low: '#5f8fbd',
  info: '#4db6c4',
}

export function OverviewView() {
  const t = useApp((s) => s.t)
  const setView = useApp((s) => s.setView)
  const [data, setData] = useState<OverviewPayload | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [ticking, setTicking] = useState(false)

  const load = useCallback(async () => {
    try {
      setError(false)
      const res = await fetch('/api/overview')
      if (!res.ok) throw new Error('bad status')
      setData(await res.json())
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

  const manualTick = async () => {
    setTicking(true)
    try {
      await fetch('/api/collector', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'tick' }) })
      await load()
    } finally {
      setTicking(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-72" />
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-64" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <EmptyState
        icon={Activity}
        title={t('common.error')}
        hint={t('common.errorBody')}
        action={<Button onClick={load} variant="outline" size="sm">{t('common.retry')}</Button>}
      />
    )
  }

  const trend = data.eventsTrend.map((b) => ({
    time: new Date(b.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    events: b.events,
    alerts: b.alerts,
  }))
  const sevData = data.severity.filter((s) => s.alerts > 0)

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{t('ov.title')}</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">{t('ov.subtitle')}</p>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={load}>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> {t('common.refresh')}
            </Button>
            <Button size="sm" onClick={manualTick} disabled={ticking}>
              <Play className="mr-1.5 h-3.5 w-3.5" /> {ticking ? t('common.loading') : t('lm.tickNow')}
            </Button>
          </div>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label={t('ov.events24h')} value={data.counts.events24h} icon={Database} sub={`${data.counts.eventsTotal} total`} />
        <StatCard label={t('ov.alertsOpen')} value={data.counts.alertsOpen} icon={BellRing} tone="high" />
        <StatCard label={t('ov.activeIncidents')} value={data.counts.incidentsActive} icon={FolderSearch} tone="critical" />
        <StatCard
          label={t('ov.rulesEnabled')}
          value={`${data.counts.rulesEnabled}/${data.counts.rulesTotal}`}
          icon={ShieldCheck}
          tone="success"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Trend */}
        <Card className="lg:col-span-2">
          <CardContent className="p-5">
            <SectionTitle title={t('ov.trend')} />
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trend} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#3ba97c" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#3ba97c" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="gAlerts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#d9a441" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#d9a441" stopOpacity={0.03} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#222a32" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="time" tick={{ fill: '#8b98a5', fontSize: 10 }} tickLine={false} axisLine={{ stroke: '#222a32' }} interval={3} />
                  <YAxis tick={{ fill: '#8b98a5', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip
                    contentStyle={{ background: '#151a20', border: '1px solid #222a32', borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: '#8b98a5' }}
                  />
                  <Area type="monotone" dataKey="events" stroke="#3ba97c" fill="url(#gEvents)" strokeWidth={1.5} name={t('common.events')} />
                  <Area type="monotone" dataKey="alerts" stroke="#d9a441" fill="url(#gAlerts)" strokeWidth={1.5} name={t('common.alerts')} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Severity distribution */}
        <Card>
          <CardContent className="p-5">
            <SectionTitle title={t('ov.sevDist')} />
            {sevData.length === 0 ? (
              <p className="py-12 text-center text-xs text-muted-foreground">{t('es.noAlerts')}</p>
            ) : (
              <>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={sevData} margin={{ top: 4, right: 8, left: -22, bottom: 0 }}>
                      <CartesianGrid stroke="#222a32" strokeDasharray="3 3" vertical={false} />
                      <XAxis dataKey="severity" tick={{ fill: '#8b98a5', fontSize: 10 }} tickLine={false} axisLine={{ stroke: '#222a32' }} />
                      <YAxis tick={{ fill: '#8b98a5', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
                      <ChartTooltip
                        cursor={{ fill: 'rgba(59,169,124,0.06)' }}
                        contentStyle={{ background: '#151a20', border: '1px solid #222a32', borderRadius: 8, fontSize: 12 }}
                      />
                      <Bar dataKey="alerts" radius={[3, 3, 0, 0]} name={t('common.alerts')}>
                        {sevData.map((s) => <Cell key={s.severity} fill={SEV_COLORS[s.severity]} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <ul className="mt-3 space-y-1.5">
                  {sevData.map((s) => (
                    <li key={s.severity} className="flex items-center justify-between text-xs">
                      <SeverityBadge severity={s.severity} className="text-[10px]" />
                      <span className="font-mono text-muted-foreground">{s.alerts} · {s.incidents} {t('common.incidents')}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Collector + pipeline health */}
        <Card>
          <CardContent className="p-5">
            <SectionTitle title={t('ov.collectorHealth')} />
            <div className="flex items-center gap-2.5">
              <span className={`h-2 w-2 rounded-full ${data.collector.running ? 'bg-primary pulse-dot' : 'bg-muted-foreground/50'}`} aria-hidden />
              <p className="text-sm font-medium">
                {data.collector.running ? t('ov.collectorRunning') : t('ov.collectorPaused')}
              </p>
            </div>
            <p className="mt-1.5 flex items-center gap-1.5 text-xs text-muted-foreground">
              <Clock className="h-3 w-3" aria-hidden />
              {t('ov.lastCollection')}: {data.collector.lastTickAt ? new Date(data.collector.lastTickAt).toLocaleTimeString() : t('common.never')}
            </p>

            <div className="mt-4 border-t pt-3">
              <div className="mb-2 flex items-center gap-2">
                <Cpu className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                <p className="text-xs font-semibold">{t('ov.pipeline')}</p>
              </div>
              {!data.collector.lastRun ? (
                <p className="text-xs leading-relaxed text-muted-foreground">{t('ov.pipelineNone')}</p>
              ) : (
                <div className="space-y-1.5">
                  <div className="flex justify-between font-mono text-[11px] text-muted-foreground">
                    <span>{t('common.events')}: {data.collector.lastRun.eventsIn} · {t('common.alerts')}: {data.collector.lastRun.alertsOut} · {t('common.incidents')}: {data.collector.lastRun.incidentsOut}</span>
                    <span>{data.collector.lastRun.durationMs}ms</span>
                  </div>
                  <ul className="space-y-1">
                    {data.collector.lastRun.stages.map((st) => (
                      <li key={st.stage} className="flex items-center justify-between rounded border border-border/60 px-2 py-1 font-mono text-[10.5px]">
                        <span className="flex items-center gap-1.5">
                          <span className={`h-1.5 w-1.5 rounded-full ${st.status === 'ok' ? 'bg-primary' : 'bg-[#d24b42]'}`} aria-hidden />
                          {st.stage}
                        </span>
                        <span className="text-muted-foreground">{st.input}→{st.output} · {st.durationMs}ms{st.errors.length ? ` · ${st.errors.length}err` : ''}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="mt-4 border-t pt-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold">{t('ov.aiStatus')}</p>
                <Mono className={data.ai.available ? 'text-primary' : 'text-muted-foreground'}>
                  {data.ai.available ? t('ov.aiReady', { mode: data.ai.mode }) : t('ov.aiOff')}
                </Mono>
              </div>
              <div className="mt-2 flex items-center justify-between">
                <p className="text-xs font-semibold">{t('ov.engineStatus')}</p>
                <Mono className="text-muted-foreground">
                  {t('ov.rulesActive', { n: data.counts.rulesEnabled, total: data.counts.rulesTotal })}
                </Mono>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Sources */}
        <Card>
          <CardContent className="p-5">
            <SectionTitle title={t('ov.sources')} />
            <ul className="space-y-2">
              {data.sources.map((s) => (
                <li key={s.id} className="rounded-md border border-border/60 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <Mono className="truncate text-foreground">{s.displayName}</Mono>
                    <SourceStatusBadge status={s.status} className="text-[10px]" />
                  </div>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    {s.eventsCollected} {t('common.events')} · {s.lastCollectAt ? new Date(s.lastCollectAt).toLocaleTimeString() : t('common.never')}
                  </p>
                  {s.note && <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-muted-foreground/70">{s.note}</p>}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        {/* Recent alerts + incidents */}
        <div className="space-y-4">
          <Card>
            <CardContent className="p-5">
              <SectionTitle
                title={t('ov.recentAlerts')}
                right={
                  <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setView('incidents')}>
                    {t('ov.viewAll')} <ArrowRight className="ml-1 h-3 w-3" />
                  </Button>
                }
              />
              {data.recentAlerts.length === 0 ? (
                <p className="py-4 text-center text-xs text-muted-foreground">{t('es.noAlerts')}</p>
              ) : (
                <ul className="space-y-2">
                  {data.recentAlerts.slice(0, 5).map((a) => (
                    <li key={a.id} className="rounded-md border border-border/60 p-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <Mono className="truncate text-[11px] text-foreground">{a.ruleId}</Mono>
                        <SeverityBadge severity={a.severity} className="text-[10px]" />
                      </div>
                      <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{a.summary}</p>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-5">
              <SectionTitle
                title={t('ov.recentIncidents')}
                right={
                  <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setView('incidents')}>
                    {t('ov.viewAll')} <ArrowRight className="ml-1 h-3 w-3" />
                  </Button>
                }
              />
              {data.recentIncidents.length === 0 ? (
                <p className="py-4 text-center text-xs text-muted-foreground">{t('es.noIncidents')}</p>
              ) : (
                <ul className="space-y-2">
                  {data.recentIncidents.slice(0, 4).map((i) => (
                    <li key={i.id} className="rounded-md border border-border/60 p-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <Mono className="text-[11px] text-primary">{i.code}</Mono>
                        <SeverityBadge severity={i.severity} className="text-[10px]" />
                      </div>
                      <p className="mt-1 truncate text-[11px] text-muted-foreground">{i.title}</p>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
