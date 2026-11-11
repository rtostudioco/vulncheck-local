'use client'

// SENTINEL DESK 1.0 — Application shell
// Single-page desktop-style layout: persistent sidebar + header + view router.
// The collector loop lives here so notifications reach the global center.

import { useEffect, useRef, type ComponentType } from 'react'
import { toast } from 'sonner'
import { useApp, type ViewId } from '@/stores/app-store'
import { Sidebar } from '@/components/layout/sidebar'
import { Header } from '@/components/layout/header'
import { OverviewView } from '@/components/views/overview'
import { LiveMonitorView } from '@/components/views/live-monitor'
import { DetectionsView } from '@/components/views/detections'
import { IncidentsView } from '@/components/views/incidents'
import { TimelineView } from '@/components/views/timeline'
import { IntelView } from '@/components/views/intel'
import { AiAnalystView } from '@/components/views/ai-analyst'
import { ResponseView } from '@/components/views/response'
import { ReportsView } from '@/components/views/reports'
import { SettingsView } from '@/components/views/settings'
import { Toaster } from '@/components/ui/sonner'
import { Download, Shield } from 'lucide-react'

const VIEWS: Record<ViewId, ComponentType> = {
  overview: OverviewView,
  monitor: LiveMonitorView,
  detections: DetectionsView,
  incidents: IncidentsView,
  timeline: TimelineView,
  intel: IntelView,
  ai: AiAnalystView,
  response: ResponseView,
  reports: ReportsView,
  settings: SettingsView,
}

export default function Page() {
  const view = useApp((s) => s.view)
  const t = useApp((s) => s.t)
  const setLang = useApp((s) => s.setLang)
  const pushNotifications = useApp((s) => s.pushNotifications)
  const seen = useRef<Set<string>>(new Set())
  const bootstrapped = useRef(false)

  // ── Collector loop + notification center feed ──────────────────────────
  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout> | null = null

    const notify = (run: {
      newAlerts?: { alertId: string; ruleId: string; title: string; severity: string; summary: string }[]
      newIncidents?: { id: string; code: string; title: string; severity: string }[]
    }) => {
      const items = [] as Parameters<typeof pushNotifications>[0]
      for (const a of run.newAlerts ?? []) {
        if (seen.current.has(a.alertId)) continue
        seen.current.add(a.alertId)
        items.push({
          id: a.alertId, kind: 'alert', severity: a.severity,
          title: t('tn.alertNew', { rule: a.ruleId, title: a.title }),
          body: a.summary, at: new Date().toISOString(), target: 'detections',
        })
        if (a.severity === 'critical' || a.severity === 'high') {
          toast.warning(t('tn.alertNew', { rule: a.ruleId, title: a.title }), { description: a.summary })
        }
      }
      for (const i of run.newIncidents ?? []) {
        if (seen.current.has(i.id)) continue
        seen.current.add(i.id)
        items.push({
          id: i.id, kind: 'incident', severity: i.severity,
          title: t('tn.incidentNew', { code: i.code, title: i.title }),
          body: i.title, at: new Date().toISOString(), target: 'incidents',
        })
        toast(t('tn.incidentNew', { code: i.code, title: i.title }))
      }
      if (items.length) pushNotifications(items)
    }

    const loop = async () => {
      if (!alive) return
      try {
        const sres = await fetch('/api/settings')
        const sdata = await sres.json()
        const s = sdata.settings ?? {}
        if (!bootstrapped.current) {
          bootstrapped.current = true
          if (s.language === 'es' || s.language === 'en') setLang(s.language)
          // Seed initial seen-set so a page reload doesn't replay old notifications
          try {
            const ores = await fetch('/api/overview')
            const o = await ores.json()
            for (const a of o.recentAlerts ?? []) seen.current.add(a.id)
            for (const i of o.recentIncidents ?? []) seen.current.add(i.id)
          } catch { /* non-fatal */ }
        }

        if (s.collectorEnabled) {
          const res = await fetch('/api/collector', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'tick' }),
          })
          const data = await res.json()
          if (alive && data?.ok && data.run) notify(data.run)
          timer = setTimeout(loop, Math.max(5, Number(s.collectorIntervalSec ?? 20)) * 1000)
        } else {
          timer = setTimeout(loop, 6000)
        }
      } catch {
        timer = setTimeout(loop, 12000)
      }
    }

    // Manual ticks from views (Live Monitor "Collect now") feed notifications too
    const onManualTick = (e: Event) => {
      const detail = (e as CustomEvent).detail
      if (detail) notify(detail)
    }
    window.addEventListener('sentinel:tick', onManualTick)

    loop()
    return () => {
      alive = false
      if (timer) clearTimeout(timer)
      window.removeEventListener('sentinel:tick', onManualTick)
    }
  }, [])

  const ActiveView = VIEWS[view] ?? OverviewView

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-background">
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Header />
          <main className="scroll-slim flex-1 overflow-y-auto p-5" role="main">
            <ActiveView />
          </main>
          {/* Status footer — always visible in the desktop shell */}
          <footer className="flex h-8 shrink-0 items-center justify-between gap-3 border-t border-border bg-sidebar px-4" role="contentinfo">
            <p className="flex min-w-0 items-center gap-2 text-[10.5px] text-muted-foreground">
              <Shield className="h-3 w-3 shrink-0 text-primary/70" aria-hidden />
              <span className="shrink-0 font-medium">{t('app.name')}</span>
              <span className="shrink-0 font-mono">{t('app.version')}</span>
              <span className="hidden shrink-0 text-muted-foreground/50 sm:inline">·</span>
              <span className="hidden truncate sm:inline">{t('app.tagline')}</span>
            </p>
            <p className="flex shrink-0 items-center gap-2 text-[10.5px] text-muted-foreground">
              <a
                href="/sentinel-desk-github.zip"
                download
                className="flex items-center gap-1 rounded border border-border px-1.5 py-0.5 font-medium text-foreground/80 transition-colors hover:border-primary/50 hover:text-primary"
              >
                <Download className="h-3 w-3" aria-hidden />
                {t('app.sourceZipShort')}
              </a>
              <span className="hidden items-center gap-1.5 md:flex">
                <span className="rounded border border-[#1d454e] bg-[#0e272c] px-1.5 py-0.5 font-semibold tracking-wider text-[#5cbecd]">
                  {t('app.demo')}
                </span>
                <span className="hidden xl:inline">Synthetic telemetry only — no real system is monitored</span>
                <span className="hidden text-muted-foreground/50 2xl:inline">·</span>
                <span className="hidden 2xl:inline">{t('app.author')}</span>
              </span>
              <span className="hidden font-medium text-foreground/80 lg:inline 2xl:hidden">{t('app.author')}</span>
            </p>
          </footer>
        </div>
      </div>
      <Toaster position="bottom-right" richColors />
    </div>
  )
}
