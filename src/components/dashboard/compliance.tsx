"use client";

/**
 * VulnCheck Local — Compliance section: methodology/disclaimer banner and
 * all rule results grouped by category with expandable evidence rows.
 */

import { useMemo } from "react";
import { ChevronDown, ClipboardCheck, Info } from "lucide-react";
import type { Category, FindingDTO } from "@/lib/vulncheck/core/types";
import { CATEGORIES } from "@/lib/vulncheck/core/types";
import { useDashboardStore } from "@/lib/client/store";
import { useI18n } from "@/lib/i18n";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { cn } from "@/lib/utils";
import { DetailBlock, EvidencePre } from "./evidence-block";
import { EmptyState } from "./empty-state";
import { SectionCard } from "./section-card";
import { StatusIcon } from "./status-badge";
import { sortFindings } from "./utils";

function ComplianceRow({ finding }: { finding: FindingDTO }) {
  const { t } = useI18n();
  return (
    <Collapsible className="group">
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-3 rounded-md px-2 py-2 text-left transition-colors hover:bg-accent/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <StatusIcon status={finding.status} />
          <span className="hidden w-28 shrink-0 font-mono text-xs text-muted-foreground sm:inline">
            {finding.ruleId}
          </span>
          <Badge
            variant="outline"
            className="hidden shrink-0 font-mono text-[10px] text-muted-foreground md:inline-flex"
          >
            v{finding.ruleVersion}
          </Badge>
          <span className="min-w-0 flex-1 truncate text-sm">{finding.title}</span>
          <Badge variant="outline" className="hidden shrink-0 font-mono text-[10px] text-muted-foreground uppercase lg:inline-flex">
            {finding.osTarget}
          </Badge>
          <ChevronDown
            aria-hidden="true"
            className="size-4 shrink-0 text-muted-foreground transition-transform group-data-[state=open]:rotate-180"
          />
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="mb-2 ml-2 space-y-3 border-l-2 border-border py-2 pl-4">
          <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
            {finding.description}
          </p>
          <DetailBlock label={t("compliance.evidence.label")}>
            <EvidencePre text={finding.evidence || t("compliance.evidence.empty")} />
          </DetailBlock>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function SummaryChip({
  label,
  count,
  className,
}: {
  label: string;
  count: number;
  className?: string;
}) {
  return (
    <Badge variant="outline" className={cn("tabular-nums", className)}>
      {count} {label}
    </Badge>
  );
}

export function ComplianceSection() {
  const { t } = useI18n();
  const detail = useDashboardStore((s) => s.detail);
  const findings = useMemo(() => detail?.findings ?? [], [detail]);

  const groups = useMemo(() => {
    return CATEGORIES.map((cat: Category) => {
      const items = sortFindings(findings.filter((f) => f.category === cat));
      return {
        category: cat,
        items,
        pass: items.filter((f) => f.status === "PASS").length,
        fail: items.filter((f) => f.status === "FAIL").length,
        warn: items.filter((f) => f.status === "WARNING").length,
      };
    });
  }, [findings]);

  if (!detail || findings.length === 0) {
    return (
      <EmptyState
        icon={ClipboardCheck}
        title={t("compliance.empty.title")}
        description={t("compliance.empty.description")}
      />
    );
  }

  return (
    <div className="space-y-6">
      <SectionCard
        title={t("compliance.title")}
        description={t("compliance.description")}
        icon={ClipboardCheck}
        contentClassName="space-y-4"
      >
        <Alert>
          <Info aria-hidden="true" />
          <AlertTitle>{t("compliance.methodology.title")}</AlertTitle>
          <AlertDescription className="space-y-2">
            <p className="text-xs leading-relaxed">{t("compliance.methodology.text")}</p>
            <ul className="list-disc space-y-1 pl-4 text-xs">
              {[1, 2, 3, 4].map((i) => (
                <li key={i}>{t(`compliance.methodology.disclaimer${i}`)}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>

        <div className="space-y-6">
          {groups.map((group) => (
            <section key={group.category} aria-label={t(`compliance.category.${group.category}`)}>
              <div className="flex flex-wrap items-center gap-2 border-b pb-2">
                <h3 className="text-sm font-semibold">{t(`compliance.category.${group.category}`)}</h3>
                <span className="ml-auto flex flex-wrap items-center gap-1.5">
                  <SummaryChip label={t("compliance.summary.pass")} count={group.pass} className="border-emerald-500/50 bg-emerald-500/10 text-emerald-500" />
                  <SummaryChip label={t("compliance.summary.fail")} count={group.fail} className="border-red-500/50 bg-red-500/10 text-red-500" />
                  <SummaryChip label={t("compliance.summary.warn")} count={group.warn} className="border-amber-500/50 bg-amber-500/10 text-amber-500" />
                  <SummaryChip label={t("compliance.summary.total")} count={group.items.length} className="text-muted-foreground" />
                </span>
              </div>
              {group.items.length === 0 ? (
                <p className="px-2 py-3 text-sm text-muted-foreground">{t("compliance.category.empty")}</p>
              ) : (
                <div className="pt-2">
                  {group.items.map((finding) => (
                    <ComplianceRow key={finding.id} finding={finding} />
                  ))}
                </div>
              )}
            </section>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
