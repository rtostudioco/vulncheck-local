"use client";

/**
 * VulnCheck Local — Overview section: posture hero, severity summary,
 * category posture, module health strip and limitations alert.
 */

import { format } from "date-fns";
import {
  Activity,
  ClipboardCheck,
  Gauge,
  Layers,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import type { Category, Severity } from "@/lib/vulncheck/core/types";
import { CATEGORIES, CATEGORY_LABELS, SEVERITIES } from "@/lib/vulncheck/core/types";
import { useDashboardStore } from "@/lib/client/store";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";
import { DefItem, SectionCard } from "./section-card";
import { EmptyState } from "./empty-state";
import { ScoreRing } from "./score-ring";
import { SEVERITY_CLASSES } from "./severity-badge";
import { MODULE_STATE_DOT } from "./status-badge";
import { gradeBadgeClasses } from "./utils";

const ZERO_COUNTS = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  warnings: 0,
  passed: 0,
  failed: 0,
  notAssessed: 0,
  errors: 0,
  notApplicable: 0,
};

export function OverviewSection() {
  const detail = useDashboardStore((s) => s.detail);
  const loadingDetail = useDashboardStore((s) => s.loadingDetail);
  const sessions = useDashboardStore((s) => s.sessions);
  const runStarting = useDashboardStore((s) => s.runStarting);
  const runAudit = useDashboardStore((s) => s.runAudit);
  const openFindingsWithSeverity = useDashboardStore((s) => s.openFindingsWithSeverity);
  const { t } = useI18n();

  const auditBusy = runStarting || sessions.some((s) => s.status === "RUNNING");

  if (loadingDetail && !detail) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-52 w-full rounded-xl" />
        <Skeleton className="h-44 w-full rounded-xl" />
        <Skeleton className="h-56 w-full rounded-xl" />
      </div>
    );
  }

  if (detail && detail.status === "RUNNING") {
    return (
      <SectionCard
        title={t("overview.auditInProgressTitle")}
        description={t("overview.auditInProgressDescription")}
        icon={Activity}
      >
        <Progress value={detail.progress} className="h-3" aria-label={t("overview.auditProgressAria")} />
        <div className="mt-3 flex items-center justify-between gap-4 text-xs text-muted-foreground">
          <span className="min-w-0 truncate">{detail.currentStep ?? t("overview.working")}</span>
          <span className="font-mono tabular-nums">{Math.round(detail.progress)}%</span>
        </div>
      </SectionCard>
    );
  }

  if (!detail || detail.status !== "COMPLETED") {
    return (
      <EmptyState
        icon={detail && detail.status === "FAILED" ? ShieldAlert : ShieldCheck}
        title={t("overview.emptyTitle")}
        description={
          detail && detail.status === "FAILED"
            ? t("overview.emptyFailedDescription")
            : t("overview.emptyDescription")
        }
        action={
          <Button onClick={() => void runAudit()} disabled={auditBusy} className="h-11">
            {auditBusy ? <Loader2 aria-hidden="true" className="size-4 animate-spin" /> : <ShieldCheck aria-hidden="true" className="size-4" />}
            {t("overview.runFirstAudit")}
          </Button>
        }
      />
    );
  }

  const counts = detail.counts ?? ZERO_COUNTS;
  const severityCounts: Record<Severity, number> = {
    CRITICAL: counts.critical,
    HIGH: counts.high,
    MEDIUM: counts.medium,
    LOW: counts.low,
    INFO: counts.info,
  };
  const completedAt = detail.completedAt ? format(new Date(detail.completedAt), "MMM d, yyyy HH:mm") : "—";

  const miniStats = [
    { label: t("common.status.WARNING").toUpperCase(), value: counts.warnings, dot: "bg-amber-500" },
    { label: t("common.status.PASS").toUpperCase(), value: counts.passed, dot: "bg-emerald-500" },
    { label: t("common.status.NOT_ASSESSED").toUpperCase(), value: counts.notAssessed, dot: "bg-zinc-500" },
    { label: t("common.status.ERROR").toUpperCase(), value: counts.errors, dot: "bg-red-600" },
  ];

  return (
    <div className="space-y-6">
      {/* Hero */}
      <SectionCard title={t("overview.heroTitle")} description={t("overview.heroDescription")} icon={Gauge}>
        <div className="flex flex-col items-center gap-8 md:flex-row md:items-center">
          <ScoreRing score={detail.overallScore} grade={detail.grade} size={150} />
          <dl className="grid flex-1 grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
            <DefItem
              label={t("overview.grade")}
              value={
                <Badge variant="outline" className={cn("text-xs", gradeBadgeClasses(detail.grade))}>
                  {detail.grade ?? "—"}
                </Badge>
              }
            />
            <DefItem
              label={t("overview.coverage")}
              value={detail.coverage == null ? "—" : `${Math.round(detail.coverage)}%`}
            />
            <DefItem label={t("overview.findings")} value={detail.findingsCount} />
            <DefItem label={t("overview.lastAudit")} value={completedAt} />
            <DefItem label={t("overview.hostname")} value={detail.profile?.hostname ?? "—"} mono />
            <DefItem label={t("overview.platform")} value={detail.platform} />
          </dl>
        </div>
      </SectionCard>

      {/* Severity summary */}
      <SectionCard
        title={t("overview.severityTitle")}
        description={t("overview.severityDescription")}
        icon={Layers}
      >
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
          {SEVERITIES.map((sev) => {
            const c = SEVERITY_CLASSES[sev];
            return (
              <button
                key={sev}
                type="button"
                onClick={() => openFindingsWithSeverity(sev)}
                aria-label={t("overview.viewFindingsAria", { sev: t(`common.severity.${sev}`).toLowerCase() })}
                className={cn(
                  "rounded-lg border border-l-4 bg-card p-4 text-left transition-colors hover:bg-accent/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                  c.borderL,
                  c.text
                )}
              >
                <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{t(`common.severity.${sev}`)}</p>
                <p className={cn("mt-1 text-2xl font-semibold tabular-nums", c.text)}>{severityCounts[sev]}</p>
              </button>
            );
          })}
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {miniStats.map((stat) => (
            <span
              key={stat.label}
              className="inline-flex items-center gap-2 rounded-md border bg-card px-3 py-1.5 text-xs"
            >
              <span aria-hidden="true" className={cn("size-2 rounded-full", stat.dot)} />
              <span className="text-muted-foreground">{stat.label}</span>
              <span className="font-medium tabular-nums">{stat.value}</span>
            </span>
          ))}
        </div>
      </SectionCard>

      {/* Category posture */}
      <SectionCard title={t("overview.categoryTitle")} description={t("overview.categoryDescription")} icon={ClipboardCheck}>
        <div className="space-y-3">
          {CATEGORIES.map((cat: Category) => {
            const catFindings = (detail.findings ?? []).filter((f) => f.category === cat);
            const assessed = catFindings.filter(
              (f) => f.status === "PASS" || f.status === "FAIL" || f.status === "WARNING"
            );
            const passed = catFindings.filter((f) => f.status === "PASS").length;
            const failed = catFindings.filter((f) => f.status === "FAIL").length;
            const share = assessed.length > 0 ? Math.round((passed / assessed.length) * 100) : 0;
            return (
              <div key={cat} className="flex items-center gap-3 sm:gap-4">
                <span className="w-32 shrink-0 truncate text-sm sm:w-44 sm:text-pretty">
                  {CATEGORY_LABELS[cat]}
                </span>
                <div
                  className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-muted"
                  role="img"
                  aria-label={t("overview.categoryAria", { cat: CATEGORY_LABELS[cat], pct: share })}
                >
                  <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${share}%` }} />
                </div>
                <span className="w-10 shrink-0 text-right text-xs text-muted-foreground tabular-nums">
                  {share}%
                </span>
                <Badge
                  variant="outline"
                  className={cn(
                    "w-16 shrink-0 justify-center tabular-nums",
                    failed > 0
                      ? "border-red-500/50 bg-red-500/10 text-red-500"
                      : "border-emerald-500/50 bg-emerald-500/10 text-emerald-500"
                  )}
                >
                  {t("overview.failBadge", { count: failed })}
                </Badge>
              </div>
            );
          })}
        </div>
      </SectionCard>

      {/* Module health */}
      <SectionCard title={t("overview.moduleHealthTitle")} description={t("overview.moduleHealthDescription")} icon={Activity}>
        {detail.modules.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("overview.moduleHealthEmpty")}</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {detail.modules.map((m) => (
              <Tooltip key={m.moduleKey}>
                <TooltipTrigger asChild>
                  <span
                    className="inline-flex cursor-default items-center gap-2 rounded-md border bg-card px-3 py-2 text-xs font-medium"
                    tabIndex={0}
                  >
                    <span aria-hidden="true" className={cn("size-2 rounded-full", MODULE_STATE_DOT[m.state])} />
                    {m.name}
                  </span>
                </TooltipTrigger>
                <TooltipContent className="max-w-80 whitespace-normal">
                  <p className="font-semibold">{m.name}</p>
                  <p className="opacity-80">{t("overview.moduleStateSource", { state: m.state, source: m.source })}</p>
                  {m.notes.length > 0 ? (
                    <ul className="mt-1 list-disc pl-4 opacity-80">
                      {m.notes.map((n, i) => (
                        <li key={i}>{n}</li>
                      ))}
                    </ul>
                  ) : null}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
        )}
      </SectionCard>

      {/* Limitations */}
      {detail.limitations.length > 0 ? (
        <Alert className="border-amber-500/50 bg-amber-500/10 text-amber-500 [&>svg]:text-amber-500">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>{t("overview.limitationsTitle")}</AlertTitle>
          <AlertDescription>
            <ul className="list-disc space-y-1 pl-4">
              {detail.limitations.map((item, i) => (
                <li key={i}>{item}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}
    </div>
  );
}
