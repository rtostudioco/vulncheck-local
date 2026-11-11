'use client'

// SENTINEL DESK 1.0 — MODULE: Settings & local audit
// General (language), collector, AI analyst, threat-intel consent, destructive
// data management (purge events / factory reset) and the local audit log.
// Every change is saved immediately via PATCH and audited locally by the API.

import { useCallback, useEffect, useState } from 'react'
import { useApp } from '@/stores/app-store'
import type { SettingsPayload, AiMode } from '@/types/soc'
import type { Lang } from '@/lib/i18n'
import { EmptyState, SectionTitle, Mono } from '@/components/shared/ui-atoms'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { toast } from 'sonner'
import { Activity, Download, FileText, Loader2, RefreshCw, RotateCcw, Trash2 } from 'lucide-react'

// ── Types & constants ────────────────────────────────────────────────────────

interface AuditEntry {
  id: string
  actor: string
  action: string
  target: string
  detail: string
  createdAt: string
}

interface SettingsResponse {
  settings: SettingsPayload
  audit: AuditEntry[]
}

const AI_MODES: AiMode[] = ['off', 'sandbox', 'local', 'remote']
const INTERVAL_MIN = 5
const INTERVAL_MAX = 600
const RETENTION_MIN = 1
const RETENTION_MAX = 365

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

// ── View ─────────────────────────────────────────────────────────────────────

export function SettingsView() {
  const t = useApp((s) => s.t)
  const setLang = useApp((s) => s.setLang)
  const [settings, setSettings] = useState<SettingsPayload | null>(null)
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [busy, setBusy] = useState<'purge' | 'reset' | null>(null)
  /** editable drafts for the two numeric inputs (committed on valid change) */
  const [intervalDraft, setIntervalDraft] = useState('')
  const [retentionDraft, setRetentionDraft] = useState('')

  const load = useCallback(async () => {
    try {
      setError(false)
      const res = await fetch('/api/settings')
      if (!res.ok) throw new Error('bad status')
      const data = (await res.json()) as SettingsResponse
      setSettings(data.settings)
      setAudit(Array.isArray(data.audit) ? data.audit : [])
      setIntervalDraft(String(data.settings.collectorIntervalSec))
      setRetentionDraft(String(data.settings.retentionDays))
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const save = useCallback(
    async (partial: Partial<SettingsPayload>) => {
      try {
        const res = await fetch('/api/settings', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(partial),
        })
        if (!res.ok) throw new Error('bad status')
        const data = (await res.json()) as { settings: SettingsPayload }
        setSettings(data.settings)
        setIntervalDraft(String(data.settings.collectorIntervalSec))
        setRetentionDraft(String(data.settings.retentionDays))
        toast.success(t('st.saved'))
      } catch {
        toast.error(t('common.error'))
      }
    },
    [t],
  )

  const changeLanguage = (lang: Lang) => {
    setLang(lang)
    void save({ language: lang })
  }

  const commitInterval = (raw: string) => {
    const n = Number(raw)
    if (raw.trim() === '' || !Number.isFinite(n)) return
    void save({ collectorIntervalSec: Math.min(INTERVAL_MAX, Math.max(INTERVAL_MIN, Math.round(n))) })
  }

  const commitRetention = (raw: string) => {
    const n = Number(raw)
    if (raw.trim() === '' || !Number.isFinite(n)) return
    void save({ retentionDays: Math.min(RETENTION_MAX, Math.max(RETENTION_MIN, Math.round(n))) })
  }

  const purgeEvents = async () => {
    setBusy('purge')
    try {
      const res = await fetch('/api/events', { method: 'DELETE' })
      if (!res.ok) throw new Error('bad status')
      toast.success(t('st.purged'))
      await load()
    } catch {
      toast.error(t('common.error'))
    } finally {
      setBusy(null)
    }
  }

  const resetAll = async () => {
    setBusy('reset')
    try {
      const res = await fetch('/api/settings', { method: 'DELETE' })
      if (!res.ok) throw new Error('bad status')
      toast.success(t('st.resetDone'))
      await load()
    } catch {
      toast.error(t('common.error'))
    } finally {
      setBusy(null)
    }
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-72" />
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-36" />
        ))}
      </div>
    )
  }

  if (error || !settings) {
    return (
      <EmptyState
        icon={Activity}
        title={t('common.error')}
        hint={t('common.errorBody')}
        action={<Button onClick={() => void load()} variant="outline" size="sm">{t('common.retry')}</Button>}
      />
    )
  }

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <div className="grid-texture rounded-lg border bg-card/60 px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{t('st.title')}</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">{t('st.subtitle')}</p>
          </div>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> {t('common.refresh')}
          </Button>
        </div>
      </div>

      {/* General */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle title={t('st.general')} />
          <div className="flex flex-wrap items-center justify-between gap-4">
            <Label htmlFor="setting-language" className="text-sm">{t('st.language')}</Label>
            <Select value={settings.language} onValueChange={(v) => changeLanguage(v as Lang)}>
              <SelectTrigger id="setting-language" className="w-full max-w-sm min-h-11">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="en">English</SelectItem>
                <SelectItem value="es">Español</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Collector */}
      <Card>
        <CardContent className="space-y-5 p-5">
          <SectionTitle title={t('st.collector')} />
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <Label htmlFor="setting-collector" className="text-sm">{t('st.autoCollect')}</Label>
              <p className="mt-0.5 text-xs text-muted-foreground">
                {settings.collectorEnabled ? t('st.autoCollectOn') : t('st.autoCollectOff')}
              </p>
            </div>
            <Switch
              id="setting-collector"
              checked={settings.collectorEnabled}
              onCheckedChange={(v) => void save({ collectorEnabled: v })}
              className="h-6 w-11"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4">
            <Label htmlFor="setting-interval" className="text-sm">{t('st.interval')}</Label>
            <div className="flex w-full max-w-sm items-center gap-2">
              <Input
                id="setting-interval"
                type="number"
                inputMode="numeric"
                min={INTERVAL_MIN}
                max={INTERVAL_MAX}
                value={intervalDraft}
                onChange={(e) => setIntervalDraft(e.target.value)}
                onBlur={(e) => commitInterval(e.target.value)}
                className="min-h-11"
              />
              <Mono className="shrink-0 text-xs text-muted-foreground">{t('common.sec')}</Mono>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <Label htmlFor="setting-retention" className="text-sm">{t('st.retention')}</Label>
              <p className="mt-0.5 max-w-md text-xs text-muted-foreground">{t('st.retentionNote')}</p>
            </div>
            <div className="flex w-full max-w-sm items-center gap-2">
              <Input
                id="setting-retention"
                type="number"
                inputMode="numeric"
                min={RETENTION_MIN}
                max={RETENTION_MAX}
                value={retentionDraft}
                onChange={(e) => setRetentionDraft(e.target.value)}
                onBlur={(e) => commitRetention(e.target.value)}
                className="min-h-11"
              />
              <Mono className="shrink-0 text-xs text-muted-foreground">d</Mono>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* AI analyst */}
      <Card>
        <CardContent className="space-y-5 p-5">
          <SectionTitle title={t('st.ai')} />
          <div className="flex flex-wrap items-center justify-between gap-4">
            <Label htmlFor="setting-ai-mode" className="text-sm">{t('st.aiMode')}</Label>
            <Select
              value={settings.aiMode}
              onValueChange={(v) => void save({ aiMode: v as AiMode })}
            >
              <SelectTrigger id="setting-ai-mode" className="w-full max-w-sm min-h-11">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AI_MODES.map((m) => (
                  <SelectItem key={m} value={m}>{t(`ai.mode.${m}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <Label htmlFor="setting-redaction" className="text-sm">{t('st.redaction')}</Label>
              <p className="mt-0.5 max-w-md text-xs text-muted-foreground">{t('st.redactionNote')}</p>
            </div>
            <Switch
              id="setting-redaction"
              checked={settings.aiRedaction}
              onCheckedChange={(v) => void save({ aiRedaction: v })}
              className="h-6 w-11"
            />
          </div>
        </CardContent>
      </Card>

      {/* Threat intelligence */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle title={t('st.ti')} />
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <Label htmlFor="setting-ti-consent" className="text-sm">{t('st.tiConsent')}</Label>
            </div>
            <Switch
              id="setting-ti-consent"
              checked={settings.tiExternalConsent}
              onCheckedChange={(v) => void save({ tiExternalConsent: v })}
              className="h-6 w-11"
            />
          </div>
        </CardContent>
      </Card>

      {/* Data management */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle title={t('st.data')} />
          <div className="flex flex-wrap items-center gap-3">
            {/* Purge events/alerts/incidents — rules are kept */}
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" className="min-h-11 gap-2" disabled={busy !== null}>
                  <Trash2 className="h-4 w-4" aria-hidden />
                  {t('st.purgeEvents')}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>{t('st.purgeEvents')}</AlertDialogTitle>
                  <AlertDialogDescription>{t('st.purgeConfirm')}</AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => void purgeEvents()}
                    disabled={busy !== null}
                    className="bg-destructive text-white hover:bg-destructive/90"
                  >
                    {busy === 'purge' && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />}
                    {t('st.purgeEvents')}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>

            {/* Factory reset — everything, including settings */}
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive" className="min-h-11 gap-2" disabled={busy !== null}>
                  <RotateCcw className="h-4 w-4" aria-hidden />
                  {t('st.resetAll')}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>{t('st.resetAll')}</AlertDialogTitle>
                  <AlertDialogDescription>{t('st.resetConfirm')}</AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => void resetAll()}
                    disabled={busy !== null}
                    className="bg-destructive text-white hover:bg-destructive/90"
                  >
                    {busy === 'reset' && <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />}
                    {t('st.resetAll')}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </CardContent>
      </Card>

      {/* Local audit log */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle title={t('st.audit')} />
          {audit.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">{t('st.auditEmpty')}</p>
          ) : (
            <ul className="scroll-slim max-h-64 space-y-1.5 overflow-y-auto pr-1">
              {audit.map((e) => (
                <li
                  key={e.id}
                  className="flex flex-wrap items-center gap-x-3 gap-y-0.5 rounded-md border border-border/60 px-3 py-2"
                >
                  <Mono className="shrink-0 text-[10.5px] text-muted-foreground">{formatTimestamp(e.createdAt)}</Mono>
                  <Mono className="shrink-0 text-[11px] font-semibold text-primary">{e.action}</Mono>
                  <Mono className="shrink-0 text-[11px] text-foreground">{e.target}</Mono>
                  <span className="min-w-0 flex-1 truncate text-[11px] text-muted-foreground" title={e.detail}>
                    {e.detail}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Source download */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle title={t('st.sourceTitle')} />
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{t('st.sourceBody')}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Button asChild className="min-h-11 gap-2">
              <a href="/sentinel-desk-github.zip" download>
                <Download className="h-4 w-4" aria-hidden="true" />
                {t('st.sourceZip')}
              </a>
            </Button>
            <Button asChild variant="outline" className="min-h-11 gap-2">
              <a href="/GUIA-GITHUB-ES.md" download>
                <FileText className="h-4 w-4" aria-hidden="true" />
                {t('st.sourceGuide')}
              </a>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* About */}
      <Card>
        <CardContent className="p-5">
          <SectionTitle title={t('st.about')} />
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{t('st.aboutBody')}</p>
          <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1">
            <Mono className="text-sm font-semibold text-foreground">{t('app.name')}</Mono>
            <Mono className="text-xs text-primary">{t('app.version')}</Mono>
            <Mono className="text-xs text-muted-foreground">{t('app.tagline')}</Mono>
          </div>
          <p className="mt-1 text-xs text-muted-foreground/80">{t('app.author')}</p>
        </CardContent>
      </Card>
    </div>
  )
}
