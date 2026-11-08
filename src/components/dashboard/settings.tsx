"use client";

/**
 * VulnCheck Local — Settings section: language, AI consent switch, retention
 * days, creator/about card and the destructive "delete all audit history" zone.
 * All user-visible strings come from the i18n dictionaries (settings.*).
 */

import { useEffect, useState } from "react";
import {
  AlertOctagon,
  BadgeCheck,
  Database,
  Download,
  Gauge,
  Languages,
  Loader2,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import {
} from "@/lib/vulncheck/core/types";
import { AVAILABLE_LOCALES, useI18n } from "@/lib/i18n";
import type { Locale } from "@/lib/i18n";
import { useDashboardStore } from "@/lib/client/store";
import { ApiError } from "@/lib/client/api";
import { toast } from "@/hooks/use-toast";
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
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { SectionCard } from "./section-card";

const RETENTION_MIN = 7;
const RETENTION_MAX = 365;

export function SettingsSection() {
  const { locale, setLocale, t } = useI18n();
  const meta = useDashboardStore((s) => s.meta);
  const updateSettings = useDashboardStore((s) => s.updateSettings);
  const removeAllSessions = useDashboardStore((s) => s.removeAllSessions);
  const sessionsCount = useDashboardStore((s) => s.sessions.length);

  const [aiPending, setAiPending] = useState(false);
  const [retentionValue, setRetentionValue] = useState<string>("");
  const [retentionPending, setRetentionPending] = useState(false);

  useEffect(() => {
    if (meta) setRetentionValue(String(meta.retentionDays));
  }, [meta]);

  const handleAiToggle = async (checked: boolean) => {
    setAiPending(true);
    try {
      await updateSettings({ aiConsentEnabled: checked });
      toast({
        title: checked ? t("settings.toast.aiOn.title") : t("settings.toast.aiOff.title"),
        description: checked ? t("settings.toast.aiOn.desc") : t("settings.toast.aiOff.desc"),
      });
    } catch (err) {
      toast({
        title: t("settings.toast.aiFailed.title"),
        description:
          err instanceof Error && err.message ? err.message : t("settings.toast.saveFailed.desc"),
        variant: "destructive",
      });
    } finally {
      setAiPending(false);
    }
  };

  const handleRetentionSave = async () => {
    const parsed = Number.parseInt(retentionValue, 10);
    if (!Number.isFinite(parsed) || parsed < RETENTION_MIN || parsed > RETENTION_MAX) {
      toast({
        title: t("settings.toast.invalidRetention.title"),
        description: t("settings.toast.invalidRetention.desc", {
          min: RETENTION_MIN,
          max: RETENTION_MAX,
        }),
        variant: "destructive",
      });
      return;
    }
    setRetentionPending(true);
    try {
      await updateSettings({ retentionDays: parsed });
      toast({
        title: t("settings.toast.retentionSaved.title"),
        description: t("settings.toast.retentionSaved.desc", { count: parsed }),
      });
    } catch (err) {
      toast({
        title: t("settings.toast.retentionFailed.title"),
        description:
          err instanceof Error && err.message ? err.message : t("settings.toast.saveFailed.desc"),
        variant: "destructive",
      });
    } finally {
      setRetentionPending(false);
    }
  };

  const handleDeleteAll = async () => {
    await removeAllSessions();
  };

  if (!meta) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-56 w-full rounded-xl" />
        <Skeleton className="h-44 w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Language */}
      <SectionCard
        title={t("common.lang.label")}
        description={t("settings.language.desc")}
        icon={Languages}
      >
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="w-full max-w-56">
            <Label htmlFor="language-select" className="text-sm font-medium">
              {t("common.lang.label")}
            </Label>
            <Select value={locale} onValueChange={(value) => setLocale(value as Locale)}>
              <SelectTrigger id="language-select" className="mt-1.5 w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AVAILABLE_LOCALES.map((l) => (
                  <SelectItem key={l.value} value={l.value}>
                    {l.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </SectionCard>

      {/* AI consent */}
      <SectionCard title={t("settings.ai.title")} description={t("settings.ai.subtitle")} icon={Sparkles}>
        <div className="flex items-start justify-between gap-6 rounded-lg border bg-card p-4">
          <div className="min-w-0">
            <Label htmlFor="ai-consent" className="text-sm font-medium">
              {t("settings.ai.allow")}
            </Label>
            <p className="mt-1 text-xs text-muted-foreground">{t("settings.ai.hint")}</p>
          </div>
          <Switch
            id="ai-consent"
            checked={meta.aiConsentEnabled}
            onCheckedChange={(checked) => void handleAiToggle(checked)}
            disabled={aiPending}
            aria-label={t("settings.ai.switchAria")}
          />
        </div>
        <p className="mt-4 text-sm leading-relaxed text-muted-foreground text-pretty">
          {t("settings.ai.consentText")}
        </p>
      </SectionCard>

      {/* Retention */}
      <SectionCard
        title={t("settings.retention.title")}
        description={t("settings.retention.subtitle")}
        icon={Database}
      >
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="w-full max-w-56">
            <Label htmlFor="retention-days" className="text-sm font-medium">
              {t("settings.retention.label")}
            </Label>
            <Input
              id="retention-days"
              type="number"
              min={RETENTION_MIN}
              max={RETENTION_MAX}
              step={1}
              value={retentionValue}
              onChange={(e) => setRetentionValue(e.target.value)}
              className="mt-1.5"
            />
          </div>
          <Button className="h-11 sm:h-9" onClick={() => void handleRetentionSave()} disabled={retentionPending}>
            {retentionPending ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : null}
            {t("settings.retention.save")}
          </Button>
        </div>
        <p className="mt-3 text-xs text-muted-foreground">
          {t("settings.retention.range", { min: RETENTION_MIN, max: RETENTION_MAX })}
        </p>
      </SectionCard>

      {/* About */}
      <SectionCard
        title={t("settings.about.title")}
        description={t("settings.about.subtitle")}
        icon={Gauge}
      >
        <div className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
          <BadgeCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-emerald-500" />
          <div className="min-w-0">
            <p className="text-sm font-semibold">{t("settings.createdBy")}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{t("settings.studio")}</p>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <span className="inline-flex items-center gap-2 rounded-md border bg-card px-3 py-1.5 text-xs">
            <span className="text-muted-foreground">{t("settings.about.engineVersion")}</span>
            <span className="font-mono font-medium">{meta.engineVersion}</span>
          </span>
          <span className="inline-flex items-center gap-2 rounded-md border bg-card px-3 py-1.5 text-xs">
            <span className="text-muted-foreground">{t("settings.about.rules")}</span>
            <span className="font-mono font-medium tabular-nums">{meta.ruleCount}</span>
          </span>
          <span className="inline-flex items-center gap-2 rounded-md border bg-card px-3 py-1.5 text-xs">
            <span className="text-muted-foreground">{t("settings.about.platform")}</span>
            <span className="font-mono font-medium">{meta.platform}</span>
          </span>
        </div>
        <p className="mt-4 text-sm leading-relaxed text-muted-foreground text-pretty">
          {t("settings.about.methodologyText")}
        </p>
        <ul className="mt-4 list-disc space-y-1.5 pl-4 text-sm text-muted-foreground">
          {[1, 2, 3, 4].map((i) => (
            <li key={i}>{t(`settings.about.disclaimer.${i}`)}</li>
          ))}
        </ul>
        <p className="mt-4 flex items-start gap-2 rounded-md border border-primary/40 bg-primary/10 p-3 text-sm text-primary">
          <ShieldCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          {t("settings.about.readOnly")}
        </p>
      </SectionCard>

      {/* Project package download */}
      <SectionCard
        title={t("settings.download.title")}
        description={t("settings.download.subtitle")}
        icon={Download}
      >
        <div className="flex flex-col justify-between gap-4 rounded-lg border bg-card p-4 sm:flex-row sm:items-center">
          <p className="min-w-0 text-xs leading-relaxed text-muted-foreground">
            {t("settings.download.desc")}
          </p>
          <Button asChild className="h-11 shrink-0 sm:h-9">
            <a href="/api/download" download aria-label={t("settings.download.btnAria")}>
              <Download aria-hidden="true" className="size-4" />
              {t("settings.download.btn")}
            </a>
          </Button>
        </div>
      </SectionCard>

      {/* Danger zone */}
      <SectionCard
        title={t("settings.danger.title")}
        description={t("settings.danger.subtitle")}
        icon={AlertOctagon}
        className="border-destructive/50 [&_[data-slot=card-title]]:text-destructive"
      >
        <div className="flex flex-col justify-between gap-4 rounded-lg border border-destructive/50 p-4 sm:flex-row sm:items-center">
          <div>
            <p className="text-sm font-medium">{t("settings.danger.deleteAll")}</p>
            <p className="mt-1 text-xs text-muted-foreground">
              {sessionsCount === 1
                ? t("settings.danger.deleteAllHint.one", { count: sessionsCount })
                : t("settings.danger.deleteAllHint.other", { count: sessionsCount })}
            </p>
          </div>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="outline"
                className="h-11 shrink-0 border-destructive/50 text-destructive hover:bg-destructive/10 hover:text-destructive"
              >
                <Trash2 aria-hidden="true" className="size-4" />
                {t("settings.danger.deleteAllBtn")}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{t("settings.danger.confirmTitle")}</AlertDialogTitle>
                <AlertDialogDescription>
                  {t("settings.danger.confirmDesc")}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t("settings.danger.cancel")}</AlertDialogCancel>
                <AlertDialogAction
                  className="bg-destructive text-white hover:bg-destructive/90"
                  onClick={() => void handleDeleteAll()}
                >
                  <Trash2 aria-hidden="true" className="size-4" />
                  {t("settings.danger.confirm")}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </SectionCard>
    </div>
  );
}
