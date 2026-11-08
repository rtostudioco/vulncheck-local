"use client";

/**
 * VulnCheck Local — Remediation section: actionable cards for every
 * FAIL/WARNING finding, ordered CRITICAL → LOW, with problem, impact,
 * solution and verification blocks.
 */

import { useMemo } from "react";
import { CheckCircle2, Wrench } from "lucide-react";
import type { FindingDTO } from "@/lib/vulncheck/core/types";
import { useDashboardStore } from "@/lib/client/store";
import { useI18n } from "@/lib/i18n";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { DetailBlock, EvidencePre } from "./evidence-block";
import { EmptyState } from "./empty-state";
import { SectionCard } from "./section-card";
import { SeverityBadge } from "./severity-badge";
import { SEVERITY_RANK, sortFindings } from "./utils";

function RemediationCard({ finding }: { finding: FindingDTO }) {
  const { t } = useI18n();
  return (
    <Card>
      <CardContent className="space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-2">
            <SeverityBadge severity={finding.severity} />
            <h3 className="text-sm font-semibold leading-snug text-pretty">{finding.title}</h3>
          </div>
          <Badge
            variant="outline"
            className="shrink-0 font-mono text-[10px] text-muted-foreground uppercase"
          >
            {t("remediation.card.os", { value: finding.osTarget })}
          </Badge>
        </div>
        <DetailBlock label={t("remediation.card.problem")}>
          <p className="text-sm leading-relaxed text-muted-foreground text-pretty">
            {finding.description}
          </p>
        </DetailBlock>
        <DetailBlock label={t("remediation.card.whyItMatters")}>
          <p className="text-sm leading-relaxed text-pretty">{finding.riskExplanation}</p>
        </DetailBlock>
        <DetailBlock label={t("remediation.card.solution")}>
          <p className="text-sm leading-relaxed text-pretty">{finding.remediation}</p>
        </DetailBlock>
        {finding.verification ? (
          <DetailBlock label={t("remediation.card.verify")}>
            <EvidencePre text={finding.verification} maxHeight="max-h-32" />
          </DetailBlock>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function RemediationSection() {
  const { t } = useI18n();
  const detail = useDashboardStore((s) => s.detail);
  const findings = useMemo(() => detail?.findings ?? [], [detail]);

  const actionable = useMemo(
    () =>
      sortFindings(findings.filter((f) => f.status === "FAIL" || f.status === "WARNING")).sort(
        (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
      ),
    [findings]
  );

  if (!detail) {
    return (
      <EmptyState
        icon={Wrench}
        title={t("remediation.empty.title")}
        description={t("remediation.empty.description")}
      />
    );
  }

  if (actionable.length === 0) {
    return (
      <EmptyState
        icon={CheckCircle2}
        title={t("remediation.empty.allPassed.title")}
        description={t("remediation.empty.allPassed.description")}
      />
    );
  }

  return (
    <SectionCard
      title={t("remediation.title")}
      description={
        actionable.length === 1
          ? t("remediation.description.one")
          : t("remediation.description.other", { count: actionable.length })
      }
      icon={Wrench}
    >
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {actionable.map((finding) => (
          <RemediationCard key={finding.id} finding={finding} />
        ))}
      </div>
    </SectionCard>
  );
}
