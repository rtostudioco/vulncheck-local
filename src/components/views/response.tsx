'use client'

// SENTINEL DESK 1.0 — MODULE 09: Response Center
// ADVISORY ONLY. This view generates a deterministic, client-side checklist of
// HUMAN actions. It never executes, modifies, deletes or remediates anything.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useApp } from '@/stores/app-store'
import type { IncidentRecord } from '@/types/soc'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, IncidentStatusBadge, Mono, SectionTitle, SeverityBadge } from '@/components/shared/ui-atoms'
import { cn } from '@/lib/utils'
import { toast } from 'sonner'
import { Activity, ClipboardList, Download, ShieldCheck } from 'lucide-react'

// ─── Checklist model (client-side, deterministic, no API) ───────────────────
// NOTE: step titles/details are intentionally English-only — no rs.* i18n keys
// exist for them yet (known i18n gap, reported to the lead). Evidence refs and
// all surrounding chrome remain fully localized.

interface ResponseStep {
  title: string
  detail: string
  priority: 1 | 2 | 3
  evidenceRef: string
}

const ACTIVE_STATUSES = new Set(['new', 'investigating', 'monitoring'])

const PRIORITY_CLASS: Record<1 | 2 | 3, string> = {
  1: 'sev-critical',
  2: 'sev-medium',
  3: 'sev-info',
}

function buildChecklist(inc: IncidentRecord): ResponseStep[] {
  const highProfile = inc.severity === 'critical' || inc.severity === 'high'
  const base: 1 | 2 = highProfile ? 1 : 2

  const steps: ResponseStep[] = [
    {
      title: 'Review the evidence in the incident timeline',
      detail:
        'Open the incident timeline and read each correlated alert together with its supporting events. Confirm that what the detection rule describes actually matches the recorded activity before taking any action.',
      priority: base,
      evidenceRef: 'general',
    },
    {
      title: 'Validate observed activity with the system owner',
      detail:
        'Contact the owner of the affected system and confirm whether the observed processes, scheduled tasks and account activity are authorized and expected on that host.',
      priority: base,
      evidenceRef: 'general',
    },
  ]

  const ruleIds = [...new Set((inc.alerts ?? []).map((a) => a.ruleId))]
  for (const rid of ruleIds) {
    switch (rid) {
      case 'SD-001':
      case 'SD-002':
        steps.push({
          title: "Verify the account's recent logons and reset credentials if unconfirmed",
          detail:
            'Review the account\'s recent logon activity with the user (logon type, time and source). If the logons cannot be confirmed as legitimate, reset the account credentials and invalidate active sessions.',
          priority: base,
          evidenceRef: rid,
        })
        break
      case 'SD-003':
        steps.push({
          title: 'Review the full PowerShell script-block content and the parent process',
          detail:
            'Export the complete script-block text (Event ID 4104) and inspect the parent process chain. Determine who launched the script, what it does and whether the code is known, signed and approved.',
          priority: base,
          evidenceRef: rid,
        })
        break
      case 'SD-004':
      case 'SD-005':
        steps.push({
          title: 'Export and inspect the scheduled task or service definition and binary path',
          detail:
            'Export the scheduled task XML or the service configuration, verify the registered binary path and arguments, and inspect the referenced binary for legitimacy before considering removal.',
          priority: base,
          evidenceRef: rid,
        })
        break
      case 'SD-006':
        steps.push({
          title: 'Confirm who made the audit or account change via change management records',
          detail:
            'Cross-check change management records and directory audit events to identify who performed the change and whether it corresponds to an approved request or ticket.',
          priority: base,
          evidenceRef: rid,
        })
        break
      case 'SD-007':
        steps.push({
          title: 'Quarantine-check the binary in the user-writable path manually (do not delete)',
          detail:
            'Manually inspect the binary found in the user-writable location. Do not delete it: copy it to a quarantine folder, compute and record its hash, and preserve the original path as evidence.',
          priority: base,
          evidenceRef: rid,
        })
        break
      case 'SD-008':
        steps.push({
          title: 'Check the destination IP against threat intel and egress logs',
          detail:
            'Analyze the destination IP in the Threat Intel view and review firewall/proxy egress logs to determine whether other hosts contacted the same address in the same window.',
          priority: base,
          evidenceRef: rid,
        })
        break
      case 'SD-009':
      case 'SD-010':
        steps.push({
          title: 'Priority: verify each chained signal independently before concluding',
          detail:
            'This detection chains multiple signals. Treat it as a priority: validate every chained signal on its own evidence — a single weak link can invalidate the whole correlation.',
          priority: 1,
          evidenceRef: rid,
        })
        break
      default:
        steps.push({
          title: `Verify the evidence of detection rule ${rid}`,
          detail:
            'Open the rule\'s evidence events and confirm the detection logic matches what actually happened on the system. Record your finding as an investigation note.',
          priority: base,
          evidenceRef: rid,
        })
    }
  }

  return steps
}

// ─── View ────────────────────────────────────────────────────────────────────

export function ResponseView() {
  const t = useApp((s) => s.t)
  const setView = useApp((s) => s.setView)

  const [incidents, setIncidents] = useState<IncidentRecord[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setError(false)
      const res = await fetch('/api/incidents')
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as { incidents: IncidentRecord[] }
      setIncidents(data.incidents)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    const id = setInterval(() => void load(), 30000)
    return () => clearInterval(id)
  }, [load])

  const active = useMemo(
    () => (incidents ?? []).filter((i) => ACTIVE_STATUSES.has(i.status)),
    [incidents],
  )

  // Keep a valid selection: auto-select the first active incident.
  const selected = useMemo(
    () => active.find((i) => i.id === selectedId) ?? null,
    [active, selectedId],
  )

  useEffect(() => {
    if (!loading && !error && selected === null && selectedId !== null) {
      setSelectedId(active[0]?.id ?? null)
    } else if (!loading && !error && selectedId === null && active.length > 0) {
      setSelectedId(active[0].id)
    }
  }, [loading, error, selected, selectedId, active])

  const checklist = useMemo(() => (selected ? buildChecklist(selected) : []), [selected])

  const exportJson = () => {
    if (!selected) return
    const payload = {
      incident: selected.code,
      title: selected.title,
      severity: selected.severity,
      generatedAt: new Date().toISOString(),
      advisoryOnly: true,
      steps: checklist,
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentinel-response-${selected.code}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    toast.success(t('rs.exportJson'))
  }

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <h1 className="text-lg font-semibold tracking-tight">{t('rs.title')}</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">{t('rs.subtitle')}</p>
      </div>

      {/* Advisory-only disclaimer */}
      <div className="sev-success flex items-start gap-3 rounded-lg border px-5 py-4">
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
        <p className="text-sm leading-relaxed">{t('rs.disclaimer')}</p>
      </div>

      {/* Loading skeleton */}
      {loading ? (
        <div className="grid gap-4 lg:grid-cols-5">
          <Skeleton className="h-80 lg:col-span-2" />
          <Skeleton className="h-80 lg:col-span-3" />
        </div>
      ) : error ? (
        <EmptyState
          icon={Activity}
          title={t('common.error')}
          hint={t('common.errorBody')}
          action={
            <Button onClick={() => void load()} variant="outline" size="sm">
              {t('common.retry')}
            </Button>
          }
        />
      ) : active.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title={t('rs.checklistEmpty')}
          action={
            <Button variant="outline" size="sm" onClick={() => setView('incidents')}>
              {t('nav.incidents')}
            </Button>
          }
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-5">
          {/* Active incident list */}
          <Card className="lg:col-span-2">
            <CardContent className="p-5">
              <SectionTitle title={t('common.incidents')} sub={t('rs.pick')} />
              <ul className="scroll-slim max-h-[32rem] space-y-2 overflow-y-auto pr-0.5">
                {active.map((inc) => {
                  const isSelected = selected?.id === inc.id
                  return (
                    <li key={inc.id}>
                      <button
                        type="button"
                        onClick={() => setSelectedId(inc.id)}
                        aria-pressed={isSelected}
                        className={cn(
                          'w-full rounded-md border p-3 text-left transition-colors',
                          isSelected
                            ? 'border-primary/60 bg-accent/50'
                            : 'border-border/60 hover:border-border hover:bg-accent/30',
                        )}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <Mono className="text-xs font-semibold text-primary">{inc.code}</Mono>
                          <SeverityBadge severity={inc.severity} className="text-[10px]" />
                        </div>
                        <p className="mt-1 truncate text-xs text-foreground">{inc.title}</p>
                        <div className="mt-1.5">
                          <IncidentStatusBadge status={inc.status} className="text-[10px]" />
                        </div>
                      </button>
                    </li>
                  )
                })}
              </ul>
            </CardContent>
          </Card>

          {/* Checklist */}
          <Card className="lg:col-span-3">
            <CardContent className="p-5">
              <SectionTitle
                title={t('rs.checklist')}
                right={
                  <Button size="sm" variant="outline" onClick={exportJson} disabled={!selected} className="min-h-[44px] sm:min-h-0">
                    <Download className="mr-1.5 h-3.5 w-3.5" /> {t('rs.exportJson')}
                  </Button>
                }
              />
              {!selected ? (
                <p className="py-10 text-center text-sm text-muted-foreground">{t('rs.pick')}</p>
              ) : (
                <>
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <p className="text-xs text-muted-foreground">
                      {selected.code} · {t('rs.stepsCount', { n: checklist.length })}
                    </p>
                    <Badge variant="outline" className="text-[10px]">
                      {t('rs.notAllowed')}
                    </Badge>
                  </div>
                  <ol className="space-y-2.5">
                    {checklist.map((step, idx) => (
                      <li key={`${step.evidenceRef}-${idx}`} className="rounded-md border border-border/60 p-4">
                        <div className="flex items-center gap-2">
                          <Mono className="text-[11px] text-muted-foreground">{String(idx + 1).padStart(2, '0')}</Mono>
                          <Badge variant="outline" className={cn('text-[10px] font-semibold', PRIORITY_CLASS[step.priority])}>
                            P{step.priority}
                          </Badge>
                          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                            {t('rs.priority')}
                          </span>
                        </div>
                        <p className="mt-2 text-sm font-medium leading-relaxed">{step.title}</p>
                        <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{step.detail}</p>
                        <div className="mt-2.5 flex items-center gap-2 border-t pt-2.5">
                          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                            {t('rs.evidenceRef')}
                          </span>
                          <Badge variant="outline" className="gap-1 font-mono text-[10px]">
                            <ClipboardList className="h-3 w-3" aria-hidden />
                            {step.evidenceRef}
                          </Badge>
                        </div>
                      </li>
                    ))}
                  </ol>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
