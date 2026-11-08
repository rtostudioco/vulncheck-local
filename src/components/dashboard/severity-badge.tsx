"use client";

/**
 * VulnCheck Local — severity badge + shared severity color mapping.
 * Mapping is used consistently across all sections and stat cards.
 */

import type { Severity } from "@/lib/vulncheck/core/types";
import { useI18n } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export interface SeverityClasses {
  text: string;
  border: string;
  /** Left-border-only variant (for stat cards with colored left edge). */
  borderL: string;
  bg: string;
  dot: string;
}

export const SEVERITY_CLASSES: Record<Severity, SeverityClasses> = {
  CRITICAL: {
    text: "text-red-500",
    border: "border-red-500/50",
    borderL: "border-l-red-500/50",
    bg: "bg-red-500/10",
    dot: "bg-red-500",
  },
  HIGH: {
    text: "text-orange-500",
    border: "border-orange-500/50",
    borderL: "border-l-orange-500/50",
    bg: "bg-orange-500/10",
    dot: "bg-orange-500",
  },
  MEDIUM: {
    text: "text-amber-500",
    border: "border-amber-500/50",
    borderL: "border-l-amber-500/50",
    bg: "bg-amber-500/10",
    dot: "bg-amber-500",
  },
  LOW: {
    text: "text-lime-400",
    border: "border-lime-400/50",
    borderL: "border-l-lime-400/50",
    bg: "bg-lime-400/10",
    dot: "bg-lime-400",
  },
  INFO: {
    text: "text-zinc-400",
    border: "border-zinc-400/50",
    borderL: "border-l-zinc-400/50",
    bg: "bg-zinc-400/10",
    dot: "bg-zinc-400",
  },
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const { t } = useI18n();
  const s = SEVERITY_CLASSES[severity];
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        s.text,
        s.border,
        s.bg,
        className
      )}
    >
      {t(`common.severity.${severity}`)}
    </span>
  );
}
