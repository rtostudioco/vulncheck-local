"use client";

/**
 * VulnCheck Local — Vulnerability Findings section: filter bar, sortable
 * collapsible findings list, evidence blocks and optional AI explanations.
 */

import { useMemo, useState } from "react";
import { Bug, ChevronDown, Loader2, Sparkles } from "lucide-react";
import type { FindingDTO } from "@/lib/vulncheck/core/types";
import {
  CATEGORIES,
  CHECK_STATUSES,
  SEVERITIES,
} from "@/lib/vulncheck/core/types";
import { useDashboardStore } from "@/lib/client/store";
import { ApiError, explainFinding } from "@/lib/client/api";
import { useI18n } from "@/lib/i18n";
import { toast } from "@/hooks/use-toast";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { DetailBlock, EvidencePre } from "./evidence-block";
import { EmptyState } from "./empty-state";
import { SectionCard } from "./section-card";
import { SeverityBadge, SEVERITY_CLASSES } from "./severity-badge";
import { StatusBadge } from "./status-badge";
import { sortFindings } from "./utils";

function ChipButton({
  active,
  activeClasses,
  onClick,
  children,
}: {
  active: boolean;
  activeClasses?: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "inline-flex h-9 items-center rounded-md border px-3 text-xs font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
        active
          ? cn("border-primary/50 bg-primary/10 text-primary", activeClasses)
          : "text-muted-foreground hover:bg-accent hover:text-foreground"
      )}
    >
      {children}
    </button>
  );
}

function FindingRow({ finding }: { finding: FindingDTO }) {
  const { t } = useI18n();
  const sessionId = useDashboardStore((s) => s.activeId);
  const aiConsentEnabled = useDashboardStore((s) => s.meta?.aiConsentEnabled ?? false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiText, setAiText] = useState<string | null>(null);

  const handleExplain = async () => {
    if (!sessionId || aiLoading) return;
    setAiLoading(true);
    try {
      const { explanation } = await explainFinding(sessionId, finding.id);
      setAiText(explanation);
    } catch (err) {
      const message =
        err instanceof ApiError && err.status === 403
          ? t("findings.ai.disabledError")
          : err instanceof Error && err.message
            ? err.message
            : t("findings.ai.requestFailed");
      toast({ title: t("findings.ai.failedTitle"), description: message, variant: "destructive" });
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <Collapsible className="group rounded-lg border bg-card">
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full flex-col gap-2 rounded-t-lg px-3 py-3 text-left transition-colors hover:bg-accent/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:flex-row sm:items-center sm:gap-3 md:px-4"
        >
          <span className="flex items-center gap-2 sm:shrink-0">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
          </span>
          <span className="hidden shrink-0 font-mono text-xs text-muted-foreground lg:inline">
            {finding.ruleId}
          </span>
          <span className="min-w-0 flex-1 truncate text-sm font-medium">{finding.title}</span>
          <ChevronDown
            aria-hidden="true"
            className="size-4 shrink-0 text-muted-foreground transition-transform group-data-[state=open]:rotate-180"
          />
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="space-y-4 border-t px-3 py-4 md:px-4">
          <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
            {finding.description}
          </p>
          <DetailBlock label={t("findings.detail.evidence")}>
            <EvidencePre text={finding.evidence || t("findings.detail.noEvidence")} />
          </DetailBlock>
          <DetailBlock label={t("findings.detail.risk")}>
            <p className="text-sm leading-relaxed text-pretty">{finding.riskExplanation}</p>
          </DetailBlock>
          <DetailBlock label={t("findings.detail.remediation")}>
            <p className="text-sm leading-relaxed text-pretty">{finding.remediation}</p>
          </DetailBlock>
          {finding.verification ? (
            <DetailBlock label={t("findings.detail.verification")}>
              <EvidencePre text={finding.verification} maxHeight="max-h-32" />
            </DetailBlock>
          ) : null}
          {aiText ? (
            <Alert className="border-emerald-500/50 bg-emerald-500/10 text-emerald-500 [&>svg]:text-emerald-500">
              <Sparkles aria-hidden="true" />
              <AlertTitle>{t("findings.ai.title")}</AlertTitle>
              <AlertDescription>
                <p className="whitespace-pre-wrap">{aiText}</p>
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
            <Badge variant="outline" className="font-mono text-[10px] uppercase text-muted-foreground">
              {t("findings.row.osTarget", { os: finding.osTarget })}
            </Badge>
            {aiConsentEnabled ? (
              <Button
                variant="outline"
                size="sm"
                className="h-9"
                onClick={() => void handleExplain()}
                disabled={aiLoading}
              >
                {aiLoading ? (
                  <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
                ) : (
                  <Sparkles aria-hidden="true" className="size-3.5" />
                )}
                {aiLoading ? t("findings.ai.loading") : t("findings.ai.explain")}
              </Button>
            ) : (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span tabIndex={0} className="inline-flex">
                    <Button variant="outline" size="sm" className="h-9" disabled>
                      <Sparkles aria-hidden="true" className="size-3.5" />
                      {t("findings.ai.explain")}
                    </Button>
                  </span>
                </TooltipTrigger>
                <TooltipContent>{t("findings.ai.enableInSettings")}</TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

export function FindingsSection() {
  const { t } = useI18n();
  const detail = useDashboardStore((s) => s.detail);
  const severity = useDashboardStore((s) => s.findingsSeverity);
  const category = useDashboardStore((s) => s.findingsCategory);
  const status = useDashboardStore((s) => s.findingsStatus);
  const setSeverity = useDashboardStore((s) => s.setFindingsSeverity);
  const setCategory = useDashboardStore((s) => s.setFindingsCategory);
  const setStatus = useDashboardStore((s) => s.setFindingsStatus);
  const clearFilters = useDashboardStore((s) => s.clearFindingsFilters);

  const findings = useMemo(() => detail?.findings ?? [], [detail]);

  const filtered = useMemo(
    () =>
      findings.filter(
        (f) =>
          (severity === "ALL" || f.severity === severity) &&
          (category === "ALL" || f.category === category) &&
          (status === "ALL" || f.status === status)
      ),
    [findings, severity, category, status]
  );
  const sorted = useMemo(() => sortFindings(filtered), [filtered]);

  const filtersActive = severity !== "ALL" || category !== "ALL" || status !== "ALL";

  if (!detail || findings.length === 0) {
    return (
      <EmptyState
        icon={Bug}
        title={t("findings.empty.title")}
        description={t("findings.empty.description")}
      />
    );
  }

  return (
    <SectionCard
      title={t("findings.title")}
      description={t("findings.description")}
      icon={Bug}
      contentClassName="space-y-4"
    >
      {/* Filters */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {t("findings.filters.severity")}
          </span>
          <ChipButton active={severity === "ALL"} onClick={() => setSeverity("ALL")}>
            {t("findings.filters.all")}
          </ChipButton>
          {SEVERITIES.map((sev) => {
            const c = SEVERITY_CLASSES[sev];
            return (
              <ChipButton
                key={sev}
                active={severity === sev}
                onClick={() => setSeverity(sev)}
                activeClasses={cn(c.border, c.text, c.bg)}
              >
                {t(`common.severity.${sev}`)}
              </ChipButton>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger className="h-9 w-44" aria-label={t("findings.filters.byCategory")}>
              <SelectValue placeholder={t("findings.filters.category")} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">{t("findings.filters.allCategories")}</SelectItem>
              {CATEGORIES.map((c) => (
                <SelectItem key={c} value={c}>
                  {t(`findings.category.${c}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="h-9 w-44" aria-label={t("findings.filters.byStatus")}>
              <SelectValue placeholder={t("findings.filters.status")} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">{t("findings.filters.allStatuses")}</SelectItem>
              {CHECK_STATUSES.map((st) => (
                <SelectItem key={st} value={st}>
                  {t(`common.status.${st}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="ml-auto text-xs text-muted-foreground tabular-nums">
            {t("findings.filters.showing", { shown: sorted.length, total: findings.length })}
          </span>
          {filtersActive ? (
            <Button variant="ghost" size="sm" className="h-9" onClick={clearFilters}>
              {t("findings.filters.clear")}
            </Button>
          ) : null}
        </div>
      </div>

      {/* List */}
      {sorted.length === 0 ? (
        <EmptyState
          icon={Bug}
          title={t("findings.empty.filteredTitle")}
          description={t("findings.empty.filteredDescription")}
          action={
            <Button variant="outline" className="h-11" onClick={clearFilters}>
              {t("findings.filters.clear")}
            </Button>
          }
        />
      ) : (
        <div className="space-y-3">
          {sorted.map((finding) => (
            <FindingRow key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </SectionCard>
  );
}
