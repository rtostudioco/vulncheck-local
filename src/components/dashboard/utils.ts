/**
 * VulnCheck Local — shared frontend helpers: sorting, formatting, band colors.
 */

import type { CheckStatus, FindingDTO, Severity } from "@/lib/vulncheck/core/types";

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

/** Primary sort: severity (CRITICAL → INFO). Secondary: status order below. */
export const STATUS_RANK: Record<CheckStatus, number> = {
  FAIL: 0,
  WARNING: 1,
  ERROR: 2,
  NOT_ASSESSED: 3,
  PASS: 4,
  NOT_APPLICABLE: 5,
};

export function sortFindings(list: FindingDTO[]): FindingDTO[] {
  return [...list].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      STATUS_RANK[a.status] - STATUS_RANK[b.status] ||
      a.ruleId.localeCompare(b.ruleId)
  );
}

/** Tailwind text color class for a score, by band: ≥90 emerald, ≥65 amber, ≥40 orange, else red. */
export function scoreBandTextClass(score: number | null | undefined): string {
  if (score == null) return "text-muted-foreground";
  if (score >= 90) return "text-emerald-500";
  if (score >= 65) return "text-amber-500";
  if (score >= 40) return "text-orange-500";
  return "text-red-500";
}

/** Badge classes for grade letters A/B/C/D/F. */
export function gradeBadgeClasses(grade: string | null | undefined): string {
  switch (grade) {
    case "A":
    case "B":
      return "border-emerald-500/50 bg-emerald-500/10 text-emerald-500";
    case "C":
      return "border-amber-500/50 bg-amber-500/10 text-amber-500";
    case "D":
      return "border-orange-500/50 bg-orange-500/10 text-orange-500";
    case "F":
      return "border-red-500/50 bg-red-500/10 text-red-500";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

export function formatUptime(hours: number | null | undefined): string {
  if (hours == null) return "—";
  if (hours < 48) return `${Math.round(hours)} h`;
  const days = Math.floor(hours / 24);
  const rest = Math.round(hours % 24);
  return rest > 0 ? `${days} d ${rest} h` : `${days} d`;
}

export function formatMemoryGiB(mb: number | null | undefined): string {
  if (mb == null) return "—";
  return `${(mb / 1024).toFixed(1)} GiB`;
}

export function formatDiskSize(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${mb} MB`;
}
