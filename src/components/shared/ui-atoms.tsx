'use client'

// SENTINEL DESK 1.0 — Shared UI atoms
// Severity is NEVER communicated by color alone: every badge carries a text
// label (§10 accessibility requirement).

import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import type { Severity, IncidentStatus, SourceStatus } from '@/types/soc'
import { useApp } from '@/stores/app-store'
import { Inbox } from 'lucide-react'
import type { ReactNode } from 'react'

const SEV_CLASS: Record<Severity, string> = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
  info: 'sev-info',
}

const SEV_DOT: Record<Severity, string> = {
  critical: 'sev-critical-dot',
  high: 'sev-high-dot',
  medium: 'sev-medium-dot',
  low: 'sev-low-dot',
  info: 'sev-info-dot',
}

export function SeverityBadge({ severity, className }: { severity: Severity | string; className?: string }) {
  const t = useApp((s) => s.t)
  const sev = (severity in SEV_CLASS ? severity : 'info') as Severity
  return (
    <Badge variant="outline" className={cn('gap-1.5 font-medium', SEV_CLASS[sev], className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', SEV_DOT[sev])} aria-hidden />
      {t(`sev.${sev}`)}
    </Badge>
  )
}

const LEVEL_CLASS: Record<string, string> = {
  Critical: 'sev-critical',
  Error: 'sev-high',
  Warning: 'sev-medium',
  Information: 'sev-info',
}

export function LevelBadge({ level, className }: { level: string; className?: string }) {
  const t = useApp((s) => s.t)
  const cls = LEVEL_CLASS[level] ?? 'sev-info'
  return (
    <Badge variant="outline" className={cn('text-[11px]', cls, className)}>
      {t(`lm.level.${level}`)}
    </Badge>
  )
}

const STATUS_CLASS: Record<IncidentStatus, string> = {
  new: 'sev-info',
  investigating: 'sev-medium',
  monitoring: 'sev-low',
  resolved: 'sev-success',
  false_positive: 'sev-success',
}

export function IncidentStatusBadge({ status, className }: { status: IncidentStatus | string; className?: string }) {
  const t = useApp((s) => s.t)
  const st = (status in STATUS_CLASS ? status : 'new') as IncidentStatus
  return (
    <Badge variant="outline" className={cn(STATUS_CLASS[st], className)}>
      {t(`in.st.${st}`)}
    </Badge>
  )
}

const SOURCE_CLASS: Record<SourceStatus, string> = {
  active: 'sev-success',
  demo: 'sev-info',
  permission_required: 'sev-medium',
  unavailable: 'sev-critical',
}

export function SourceStatusBadge({ status, className }: { status: SourceStatus | string; className?: string }) {
  const t = useApp((s) => s.t)
  const st = (status in SOURCE_CLASS ? status : 'unavailable') as SourceStatus
  return (
    <Badge variant="outline" className={cn(SOURCE_CLASS[st], className)}>
      {t(`src.status.${st}`)}
    </Badge>
  )
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('font-mono text-[12px] tracking-tight', className)}>{children}</span>
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  hint,
  action,
}: {
  icon?: typeof Inbox
  title: string
  hint?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border/70 px-6 py-14 text-center">
      <div className="flex h-11 w-11 items-center justify-center rounded-full bg-muted">
        <Icon className="h-5 w-5 text-muted-foreground" aria-hidden />
      </div>
      <div>
        <p className="text-sm font-medium text-foreground">{title}</p>
        {hint && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{hint}</p>}
      </div>
      {action}
    </div>
  )
}

export function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = 'default',
}: {
  label: string
  value: string | number
  sub?: string
  icon: typeof Inbox
  tone?: 'default' | 'critical' | 'high' | 'success'
}) {
  const toneCls =
    tone === 'critical' ? 'text-[#f07a72]' :
    tone === 'high' ? 'text-[#f2a06c]' :
    tone === 'success' ? 'text-[#58c48f]' : 'text-foreground'
  return (
    <div className="rounded-lg border bg-card p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
        <Icon className="h-4 w-4 text-muted-foreground/70" aria-hidden />
      </div>
      <p className={cn('mt-2 text-2xl font-semibold tabular-nums', toneCls)}>{value}</p>
      {sub && <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>}
    </div>
  )
}

export function SectionTitle({ title, sub, right }: { title: string; sub?: string; right?: ReactNode }) {
  return (
    <div className="mb-4 flex items-end justify-between gap-4">
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{title}</h2>
        {sub && <p className="mt-0.5 text-xs text-muted-foreground/80">{sub}</p>}
      </div>
      {right}
    </div>
  )
}

export function ConfidenceBar({ value }: { value: number }) {
  return (
    <div className="flex items-center gap-2" title={`${value}%`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full bg-primary/70" style={{ width: `${Math.min(100, value)}%` }} />
      </div>
      <span className="font-mono text-[11px] text-muted-foreground">{value}%</span>
    </div>
  )
}
