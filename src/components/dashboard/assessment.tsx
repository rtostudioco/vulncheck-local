"use client";

/**
 * VulnCheck Local — Security Assessment section: methodology explanation,
 * live audit progress, completion summary and the 8 audit modules A–H.
 */

import { Activity, Loader2, ScanSearch, ShieldCheck } from "lucide-react";
import type { ModuleStatus } from "@/lib/vulncheck/core/types";
import { MODULES } from "@/lib/vulncheck/core/types";
import { useDashboardStore } from "@/lib/client/store";
import { useI18n } from "@/lib/i18n";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { SectionCard } from "./section-card";
import { ModuleStateBadge } from "./status-badge";

function AssessmentModuleCard({
  module,
  status,
  running,
}: {
  module: (typeof MODULES)[number];
  status: ModuleStatus | undefined;
  running: boolean;
}) {
  const { t } = useI18n();
  return (
    <div
      className={cn(
        "rounded-lg border bg-card p-4 transition-opacity",
        running && "animate-pulse"
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <span
            aria-hidden="true"
            className="flex size-8 shrink-0 items-center justify-center rounded-md bg-primary/10 font-mono text-sm font-semibold text-primary"
          >
            {module.ref}
          </span>
          <h3 className="truncate text-sm font-semibold">
            {t(`assessment.module.${module.key}.name`)}
          </h3>
        </div>
        {status ? (
          <ModuleStateBadge state={status.state} />
        ) : (
          <Badge variant="outline" className="text-zinc-500 border-zinc-500/50 bg-zinc-500/10">
            {t("assessment.modules.notCollected")}
          </Badge>
        )}
      </div>
      <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
        {t(`assessment.module.${module.key}.description`)}
      </p>
      <p className="mt-2 truncate font-mono text-xs text-muted-foreground/80">
        {t("assessment.modules.source", {
          source: status?.source ?? t("assessment.modules.notCollectedShort"),
        })}
      </p>
      {status && status.notes.length > 0 ? (
        <ul className="mt-2 space-y-1">
          {status.notes.map((note, i) => (
            <li key={i} className="flex items-start gap-1.5 text-xs text-muted-foreground">
              <span aria-hidden="true" className="mt-1.5 size-1 shrink-0 rounded-full bg-muted-foreground/60" />
              {note}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function AssessmentSection() {
  const { t } = useI18n();
  const detail = useDashboardStore((s) => s.detail);
  const sessions = useDashboardStore((s) => s.sessions);
  const runStarting = useDashboardStore((s) => s.runStarting);

  const running = runStarting || (detail?.status === "RUNNING") || sessions.some((s) => s.status === "RUNNING");
  const moduleStatusByKey = new Map<string, ModuleStatus>(
    (detail?.modules ?? []).map((m) => [m.moduleKey, m])
  );
  const completed = detail?.status === "COMPLETED";

  return (
    <div className="space-y-6">
      {/* Explanation */}
      <SectionCard
        title={t("assessment.methodology.title")}
        description={t("assessment.methodology.description")}
        icon={ScanSearch}
      >
        <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
          {t("assessment.methodology.text")}
        </p>
        <Alert className="mt-4">
          <ShieldCheck aria-hidden="true" />
          <AlertTitle>{t("assessment.readonly.title")}</AlertTitle>
          <AlertDescription>
            <p>{t("assessment.readonly.disclaimer")}</p>
            <p className="mt-1">{t("assessment.readonly.evidenceBased")}</p>
          </AlertDescription>
        </Alert>
      </SectionCard>

      {/* Running progress */}
      {running ? (
        <SectionCard
          title={t("assessment.progress.title")}
          description={t("assessment.progress.description")}
          icon={Activity}
        >
          <Progress
            value={detail?.status === "RUNNING" ? detail.progress : 0}
            className="h-3"
            aria-label={t("assessment.progress.ariaLabel")}
          />
          <div className="mt-3 flex items-center justify-between gap-4 text-xs text-muted-foreground">
            <span className="inline-flex min-w-0 items-center gap-2">
              <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
              <span className="truncate">
                {detail?.currentStep ?? t("assessment.progress.starting")}
              </span>
            </span>
            <span className="shrink-0 font-mono tabular-nums">
              {detail?.status === "RUNNING" ? Math.round(detail.progress) : 0}%
            </span>
          </div>
        </SectionCard>
      ) : null}

      {/* Completion summary */}
      {completed ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-muted-foreground">
            {t("assessment.summary.latestAudit")}
          </span>
          <Badge variant="outline" className="border-emerald-500/50 bg-emerald-500/10 text-emerald-500">
            {t("assessment.summary.score", { score: detail.overallScore ?? "—" })}
          </Badge>
          <Badge variant="outline">
            {t("assessment.summary.findings", { count: detail.findingsCount })}
          </Badge>
          <Badge variant="outline">
            {t("assessment.summary.coverage", {
              value: detail.coverage == null ? "—" : `${Math.round(detail.coverage)}%`,
            })}
          </Badge>
        </div>
      ) : null}

      {/* Modules A–H */}
      <SectionCard
        title={t("assessment.modules.title")}
        description={t("assessment.modules.description")}
        icon={Activity}
      >
        <div className="grid gap-4 md:grid-cols-2">
          {MODULES.map((module) => (
            <AssessmentModuleCard
              key={module.key}
              module={module}
              status={moduleStatusByKey.get(module.key)}
              running={running}
            />
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
