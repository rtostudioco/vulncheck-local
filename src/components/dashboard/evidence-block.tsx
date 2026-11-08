"use client";

/**
 * VulnCheck Local — shared content blocks for findings and compliance rows:
 * labeled detail blocks and the capped, scrollable evidence <pre> block.
 */

import { cn } from "@/lib/utils";

export function DetailBlock({
  label,
  children,
  className,
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <p className="mb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {label}
      </p>
      {children}
    </div>
  );
}

export function EvidencePre({
  text,
  className,
  maxHeight = "max-h-40",
}: {
  text: string;
  className?: string;
  maxHeight?: string;
}) {
  return (
    <pre
      className={cn(
        "overflow-y-auto rounded-md bg-black/30 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap text-foreground/90 vc-scroll",
        maxHeight,
        className
      )}
    >
      {text}
    </pre>
  );
}
