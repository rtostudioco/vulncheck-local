'use client'

// SENTINEL DESK 1.0 — MODULE 10: SOC Reports
// Structured exports with integrity metadata. Incomplete collection is never
// represented as complete coverage — limitations are always printed.

import { useCallback, useEffect, useState } from 'react'
import { useApp } from '@/stores/app-store'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, Mono, SectionTitle, SeverityBadge, SourceStatusBadge, StatCard } from '@/components/shared/ui-atoms'
import { cn } from '@/lib/utils'
import { toast } from 'sonner'
import { Activity, Database, Download, BellRing, FileText, FolderSearch, Printer } from 'lucide-react'

// ─── API contract types ─────────────────────────────────────────────────────

type ReportRange = '24h' | '7d' | '30d' | 'all'

interface ReportSource {
  channel: string
  status: string
  available: boolean
  requiresAdmin: boolean
  eventsCollected: number
  lastCollectAt: string | null
}

interface ReportIncident {
  id: string
  code: string
  title: string
  severity: string
  status: string
  createdAt: string
  updatedAt: string
}

interface ReportDoc {
  report: {
    product: string
    version: string
    generatedAt: string
    range: { from: string; to: string; label: string }
    collectionLimitations: {
      statement: string
      sourceType?: string
      adminRequiredChannels?: string[]
      unavailableChannels?: string[]
    }
    sources: ReportSource[]
    summary: {
      eventsInReport: number
      alertsInReport: number
      incidentsInReport: number
      bySeverity: { severity: string; alerts: number; incidents: number }[]
    }
    incidents: ReportIncident[]
  }
  integrity: { algorithm: string; digest: string; covers: string }
}

const RANGES: ReportRange[] = ['24h', '7d', '30d', 'all']
const RANGE_KEY: Record<ReportRange, string> = {
  '24h': 'rp.range.24h',
  '7d': 'rp.range.7d',
  '30d': 'rp.range.30d',
  all: 'rp.range.all',
}

const INCIDENT_STATUSES = ['new', 'investigating', 'monitoring', 'resolved', 'false_positive']

function statusKey(status: string): string {
  return INCIDENT_STATUSES.includes(status) ? `in.st.${status}` : 'common.unknown'
}

type DownloadKind = 'json' | 'events' | 'alerts'

function downloadUrl(kind: DownloadKind, range: ReportRange): string {
  if (kind === 'json') return `/api/reports?format=json&range=${range}`
  return `/api/reports?format=csv&scope=${kind}&range=${range}`
}

function downloadName(kind: DownloadKind, range: ReportRange): string {
  if (kind === 'json') return `sentinel-report-${range}.json`
  return `sentinel-${kind}-${range}.csv`
}

function triggerBlobDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// ─── View ────────────────────────────────────────────────────────────────────

export function ReportsView() {
  const t = useApp((s) => s.t)
  const lang = useApp((s) => s.lang)
  const locale = lang === 'es' ? 'es-ES' : 'en-US'

  const [range, setRange] = useState<ReportRange>('7d')
  const [doc, setDoc] = useState<ReportDoc | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [busy, setBusy] = useState<DownloadKind | null>(null)

  const load = useCallback(
    async (r: ReportRange) => {
      try {
        setError(false)
        setLoading(true)
        const res = await fetch(`/api/reports?format=json&range=${r}`)
        if (!res.ok) throw new Error('bad status')
        const data = (await res.json()) as ReportDoc
        setDoc(data)
      } catch {
        setError(true)
        setDoc(null)
      } finally {
        setLoading(false)
      }
    },
    [],
  )

  // Auto-generate the preview for the selected range.
  useEffect(() => {
    void load(range)
  }, [load, range])

  const download = async (kind: DownloadKind) => {
    if (busy) return
    setBusy(kind)
    try {
      const res = await fetch(downloadUrl(kind, range))
      if (!res.ok) throw new Error('bad status')
      const blob = await res.blob()
      triggerBlobDownload(blob, downloadName(kind, range))
    } catch {
      toast.error(t('common.error'), { description: t('common.errorBody') })
    } finally {
      setBusy(null)
    }
  }

  const print = () => window.print()

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4 no-print">
        <h1 className="text-lg font-semibold tracking-tight">{t('rp.title')}</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">{t('rp.subtitle')}</p>
      </div>

      {/* Controls (never printed) */}
      <Card className="no-print">
        <CardContent className="p-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="space-y-1.5">
              <Label htmlFor="rp-range" className="text-xs text-muted-foreground">
                {t('rp.range')}
              </Label>
              <Select value={range} onValueChange={(v) => setRange(v as ReportRange)}>
                <SelectTrigger id="rp-range" className="min-h-[44px] w-full sm:w-56">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RANGES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {t(RANGE_KEY[r])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={() => void load(range)} disabled={loading} className="min-h-[44px] sm:min-h-0">
                <FileText className="mr-1.5 h-3.5 w-3.5" /> {t('rp.generate')}
              </Button>
              <Button
                variant="outline"
                onClick={() => void download('json')}
                disabled={busy !== null}
                className="min-h-[44px] sm:min-h-0"
              >
                <Download className="mr-1.5 h-3.5 w-3.5" /> {t('rp.json')}
              </Button>
              <Button
                variant="outline"
                onClick={() => void download('events')}
                disabled={busy !== null}
                className="min-h-[44px] sm:min-h-0"
              >
                <Download className="mr-1.5 h-3.5 w-3.5" /> {t('rp.csvEvents')}
              </Button>
              <Button
                variant="outline"
                onClick={() => void download('alerts')}
                disabled={busy !== null}
                className="min-h-[44px] sm:min-h-0"
              >
                <Download className="mr-1.5 h-3.5 w-3.5" /> {t('rp.csvAlerts')}
              </Button>
              <Button
                variant="outline"
                onClick={print}
                disabled={!doc}
                className="min-h-[44px] sm:min-h-0"
              >
                <Printer className="mr-1.5 h-3.5 w-3.5" /> {t('rp.print')}
              </Button>
            </div>
          </div>
          <p className="mt-3 text-xs text-muted-foreground">{t('rp.printNote')}</p>
        </CardContent>
      </Card>

      {/* Preview */}
      {loading ? (
        <div className="space-y-4">
          <Skeleton className="h-10 w-full" />
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {[...Array(3)].map((_, i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
          <Skeleton className="h-64" />
        </div>
      ) : error || !doc ? (
        <EmptyState
          icon={Activity}
          title={t('common.error')}
          hint={t('common.errorBody')}
          action={
            <Button onClick={() => void load(range)} variant="outline" size="sm">
              {t('common.retry')}
            </Button>
          }
        />
      ) : (
        <div className="print-plain space-y-5 rounded-lg border bg-card p-5">
          {/* Printable header — self-describing PDF */}
          <div className="flex flex-wrap items-start justify-between gap-2 border-b pb-3">
            <div>
              <p className="text-sm font-semibold">
                {doc.report.product} <span className="font-normal text-muted-foreground">{doc.report.version}</span>
              </p>
              <p className="mt-0.5 text-xs text-muted-foreground">{t('rp.title')}</p>
            </div>
            <Mono className="text-[11px] text-muted-foreground">
              {t('rp.md.generated')}: {new Date(doc.report.generatedAt).toLocaleString(locale)}
            </Mono>
          </div>

          <SectionTitle title={t('rp.preview')} />

          {/* Metadata grid */}
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-border/60 p-3">
              <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {t('rp.md.appVersion')}
              </p>
              <Mono className="mt-1 block text-sm text-foreground">{doc.report.version}</Mono>
            </div>
            <div className="rounded-md border border-border/60 p-3">
              <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {t('rp.md.generated')}
              </p>
              <Mono className="mt-1 block text-sm text-foreground">
                {new Date(doc.report.generatedAt).toLocaleString(locale)}
              </Mono>
            </div>
            <div className="rounded-md border border-border/60 p-3">
              <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{t('rp.md.range')}</p>
              <Mono className="mt-1 block break-all text-sm text-foreground">
                {new Date(doc.report.range.from).toLocaleString(locale)} –{' '}
                {new Date(doc.report.range.to).toLocaleString(locale)}
              </Mono>
            </div>
            <div className="rounded-md border border-border/60 p-3">
              <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {t('rp.md.sources')}
              </p>
              <ul className="mt-1.5 space-y-1">
                {doc.report.sources.map((s) => (
                  <li key={s.channel} className="flex items-center justify-between gap-2 text-xs">
                    <Mono className="min-w-0 truncate text-foreground">{s.channel}</Mono>
                    <SourceStatusBadge status={s.status} className="text-[10px]" />
                  </li>
                ))}
              </ul>
            </div>
            <div className="rounded-md border border-border/60 p-3 sm:col-span-2">
              <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {t('rp.md.limitations')}
              </p>
              <div className="sev-info mt-1.5 rounded-md border px-3 py-2">
                <p className="text-xs leading-relaxed">{t('rp.md.limitationsVal')}</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{doc.report.collectionLimitations.statement}</p>
              </div>
            </div>
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <StatCard label={t('rp.eventsCount')} value={doc.report.summary.eventsInReport} icon={Database} />
            <StatCard label={t('rp.alertsCount')} value={doc.report.summary.alertsInReport} icon={BellRing} tone="high" />
            <StatCard
              label={t('rp.incidentsCount')}
              value={doc.report.summary.incidentsInReport}
              icon={FolderSearch}
              tone="critical"
            />
          </div>

          {/* Severity distribution table */}
          <div className="rounded-md border border-border/60">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-1/3">{t('rp.alertsCount')}</TableHead>
                  <TableHead className="text-right">{t('common.alerts')}</TableHead>
                  <TableHead className="text-right">{t('common.incidents')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {doc.report.summary.bySeverity.map((row) => (
                  <TableRow key={row.severity}>
                    <TableCell>
                      <SeverityBadge severity={row.severity} className="text-[10px]" />
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{row.alerts}</TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{row.incidents}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {/* Integrity metadata */}
          <div className="rounded-md border border-border/60 p-3">
            <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
              {t('rp.md.integrity')}
            </p>
            <Mono className="mt-1 block break-all text-xs text-foreground">
              {doc.integrity.algorithm} · {doc.integrity.digest.slice(0, 32)}…
            </Mono>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{t('rp.md.ai')}</p>
          </div>

          <SectionTitle title={t('rp.contents')} />

          {/* Incidents */}
          {doc.report.incidents.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">{t('in.empty')}</p>
          ) : (
            <>
              <ul className="space-y-2">
                {doc.report.incidents.slice(0, 10).map((i) => (
                  <li key={i.id} className="rounded-md border border-border/60 px-3 py-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <Mono className="text-xs font-semibold text-primary">{i.code}</Mono>
                        <span className="min-w-0 truncate text-xs text-foreground">{i.title}</span>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <SeverityBadge severity={i.severity} className="text-[10px]" />
                        <Badge variant="outline" className={cn('text-[10px]')}>
                          {t(statusKey(i.status))}
                        </Badge>
                      </div>
                    </div>
                    <p className="mt-1 text-[10.5px] text-muted-foreground">
                      {t('in.created')}: {new Date(i.createdAt).toLocaleString(locale)}
                    </p>
                  </li>
                ))}
              </ul>
              {doc.report.incidents.length > 10 && (
                <p className="text-xs text-muted-foreground">
                  {t('common.showing')} {10} {t('common.of')} {doc.report.incidents.length}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
