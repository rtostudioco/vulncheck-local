"use client";

/**
 * VulnCheck Local — SectionCard: consistent card wrapper for all dashboard
 * sections (p-6 padding, optional icon/title/description/actions header),
 * plus DefItem used for definition grids.
 */

import { Card, CardContent, CardDescription, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface SectionCardProps {
  title?: string;
  description?: string;
  icon?: LucideIcon;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  contentClassName?: string;
}

export function SectionCard({
  title,
  description,
  icon: Icon,
  actions,
  children,
  className,
  contentClassName,
}: SectionCardProps) {
  const hasHeader = Boolean(title || actions);
  return (
    <Card className={cn("gap-4", className)}>
      {hasHeader ? (
        <div className="flex flex-col gap-3 px-6 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3">
            {Icon ? (
              <div className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
                <Icon aria-hidden="true" className="size-4" />
              </div>
            ) : null}
            <div className="min-w-0">
              {title ? <CardTitle className="text-base">{title}</CardTitle> : null}
              {description ? <CardDescription className="mt-1">{description}</CardDescription> : null}
            </div>
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      <CardContent className={contentClassName}>{children}</CardContent>
    </Card>
  );
}

/** Definition item used in host info and posture grids. */
export function DefItem({
  label,
  value,
  mono = false,
  className,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{label}</dt>
      <dd
        className={cn("mt-1 truncate text-sm text-foreground", mono && "font-mono")}
        title={typeof value === "string" ? value : undefined}
      >
        {value ?? "—"}
      </dd>
    </div>
  );
}
