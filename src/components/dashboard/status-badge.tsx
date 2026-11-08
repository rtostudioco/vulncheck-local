"use client";

/**
 * VulnCheck Local — status badges: check statuses (PASS/FAIL/…), audit
 * statuses (RUNNING/COMPLETED/FAILED) and audit module states.
 */

import type { CheckStatus, ModuleStatus } from "@/lib/vulncheck/core/types";
import { useI18n } from "@/lib/i18n";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Minus,
  XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

const BADGE_BASE =
  "inline-flex shrink-0 items-center justify-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap";

export const STATUS_CLASSES: Record<CheckStatus, string> = {
  PASS: "text-emerald-500 border-emerald-500/50 bg-emerald-500/10",
  FAIL: "text-red-500 border-red-500/50 bg-red-500/10",
  WARNING: "text-amber-500 border-amber-500/50 bg-amber-500/10",
  NOT_APPLICABLE: "text-zinc-500 border-zinc-500/50 bg-zinc-500/10",
  NOT_ASSESSED: "text-zinc-500 border-zinc-500/50 bg-zinc-500/10",
  ERROR: "text-red-600 border-red-600/50 bg-red-600/10",
};

export const STATUS_LABELS: Record<CheckStatus, string> = {
  PASS: "PASS",
  FAIL: "FAIL",
  WARNING: "WARNING",
  NOT_APPLICABLE: "N/A",
  NOT_ASSESSED: "NOT ASSESSED",
  ERROR: "ERROR",
};

export function StatusBadge({
  status,
  className,
}: {
  status: CheckStatus;
  className?: string;
}) {
  const { t } = useI18n();
  return (
    <span className={cn(BADGE_BASE, STATUS_CLASSES[status], className)}>
      {t(`common.status.${status}`)}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Status icons (used by Compliance rows and elsewhere)
// ---------------------------------------------------------------------------

export const STATUS_ICONS: Record<CheckStatus, LucideIcon> = {
  PASS: CheckCircle2,
  FAIL: XCircle,
  WARNING: AlertTriangle,
  NOT_APPLICABLE: Minus,
  NOT_ASSESSED: CircleDashed,
  ERROR: AlertOctagon,
};

export const STATUS_ICON_CLASSES: Record<CheckStatus, string> = {
  PASS: "text-emerald-500",
  FAIL: "text-red-500",
  WARNING: "text-amber-500",
  NOT_APPLICABLE: "text-zinc-600",
  NOT_ASSESSED: "text-zinc-500",
  ERROR: "text-red-600",
};

export function StatusIcon({
  status,
  className,
}: {
  status: CheckStatus;
  className?: string;
}) {
  const Icon = STATUS_ICONS[status];
  return (
    <Icon
      aria-hidden="true"
      className={cn("size-4 shrink-0", STATUS_ICON_CLASSES[status], className)}
    />
  );
}

// ---------------------------------------------------------------------------
// Audit (session) status
// ---------------------------------------------------------------------------

export type AuditStatusValue = "RUNNING" | "COMPLETED" | "FAILED";

const AUDIT_STATUS_CLASSES: Record<AuditStatusValue, string> = {
  RUNNING: "text-amber-500 border-amber-500/50 bg-amber-500/10",
  COMPLETED: "text-emerald-500 border-emerald-500/50 bg-emerald-500/10",
  FAILED: "text-red-500 border-red-500/50 bg-red-500/10",
};

export function AuditStatusBadge({
  status,
  className,
}: {
  status: AuditStatusValue;
  className?: string;
}) {
  const { t } = useI18n();
  return (
    <span className={cn(BADGE_BASE, AUDIT_STATUS_CLASSES[status], className)}>
      {status === "RUNNING" ? (
        <span className="size-1.5 animate-pulse rounded-full bg-amber-500" />
      ) : null}
      {t(`common.audit.${status}`)}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Audit module state (OK / PARTIAL / UNAVAILABLE / ERROR)
// ---------------------------------------------------------------------------

export type ModuleState = ModuleStatus["state"];

export const MODULE_STATE_CLASSES: Record<ModuleState, string> = {
  OK: "text-emerald-500 border-emerald-500/50 bg-emerald-500/10",
  PARTIAL: "text-amber-500 border-amber-500/50 bg-amber-500/10",
  UNAVAILABLE: "text-zinc-400 border-zinc-400/50 bg-zinc-400/10",
  ERROR: "text-red-600 border-red-600/50 bg-red-600/10",
};

export const MODULE_STATE_DOT: Record<ModuleState, string> = {
  OK: "bg-emerald-500",
  PARTIAL: "bg-amber-500",
  UNAVAILABLE: "bg-zinc-500",
  ERROR: "bg-red-600",
};

export function ModuleStateBadge({
  state,
  className,
}: {
  state: ModuleState;
  className?: string;
}) {
  const { t } = useI18n();
  return (
    <span className={cn(BADGE_BASE, MODULE_STATE_CLASSES[state], className)}>
      {t(`common.moduleState.${state}`)}
    </span>
  );
}
