'use client'

// SENTINEL DESK 1.0 — Persistent desktop sidebar (§9 main navigation)
// Desktop: fixed rail ≥ md. Mobile: off-canvas drawer controlled by the header
// hamburger (responsive mandate).

import { useEffect } from 'react'
import { useApp, type ViewId } from '@/stores/app-store'
import { cn } from '@/lib/utils'
import {
  LayoutDashboard, Radar, ShieldAlert, FolderSearch, GitBranch,
  Globe2, Bot, ShieldCheck, FileText, Settings2, Shield, X,
} from 'lucide-react'

export const NAV: { section: string; items: { id: ViewId; icon: typeof Shield; key: string }[] }[] = [
  {
    section: 'nav.section.monitor',
    items: [
      { id: 'overview', icon: LayoutDashboard, key: 'nav.overview' },
      { id: 'monitor', icon: Radar, key: 'nav.monitor' },
      { id: 'detections', icon: ShieldAlert, key: 'nav.detections' },
    ],
  },
  {
    section: 'nav.section.investigate',
    items: [
      { id: 'incidents', icon: FolderSearch, key: 'nav.incidents' },
      { id: 'timeline', icon: GitBranch, key: 'nav.timeline' },
      { id: 'intel', icon: Globe2, key: 'nav.intel' },
    ],
  },
  {
    section: 'nav.section.tools',
    items: [
      { id: 'ai', icon: Bot, key: 'nav.ai' },
      { id: 'response', icon: ShieldCheck, key: 'nav.response' },
      { id: 'reports', icon: FileText, key: 'nav.reports' },
      { id: 'settings', icon: Settings2, key: 'nav.settings' },
    ],
  },
]

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const view = useApp((s) => s.view)
  const setView = useApp((s) => s.setView)
  const t = useApp((s) => s.t)

  return (
    <nav className="scroll-slim flex-1 overflow-y-auto px-2 py-3" aria-label={t('app.name')}>
      {NAV.map((group) => (
        <div key={group.section} className="mb-3">
          <p className="px-3 pb-1.5 pt-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70">
            {t(group.section)}
          </p>
          <ul className="space-y-0.5">
            {group.items.map((item) => {
              const active = view === item.id
              return (
                <li key={item.id}>
                  <button
                    onClick={() => {
                      setView(item.id)
                      onNavigate?.()
                    }}
                    aria-current={active ? 'page' : undefined}
                    className={cn(
                      'group flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-[13px] transition-colors',
                      active
                        ? 'bg-sidebar-accent font-medium text-foreground'
                        : 'text-sidebar-foreground/80 hover:bg-sidebar-accent/60 hover:text-foreground',
                    )}
                  >
                    <item.icon
                      className={cn(
                        'h-4 w-4 shrink-0 transition-colors',
                        active ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground',
                      )}
                      aria-hidden
                    />
                    <span className="truncate">{t(item.key)}</span>
                    {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary" aria-hidden />}
                  </button>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )
}

function Brand() {
  const t = useApp((s) => s.t)
  return (
    <div className="flex items-center gap-2.5 px-4 pb-4 pt-5">
      <div className="flex h-9 w-9 items-center justify-center rounded-md border border-primary/30 bg-primary/10">
        <Shield className="h-5 w-5 text-primary" aria-hidden />
      </div>
      <div>
        <p className="text-sm font-semibold leading-tight text-foreground">{t('app.name')}</p>
        <p className="font-mono text-[10px] text-muted-foreground">{t('app.version')}</p>
      </div>
    </div>
  )
}

export function Sidebar() {
  const t = useApp((s) => s.t)
  return (
    <aside
      className="hidden h-full w-56 shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex"
      role="navigation"
      aria-label={t('app.name')}
    >
      <Brand />
      <div className="hairline mx-4" />
      <NavList />
      <div className="px-4 pb-4">
        <p className="text-[10px] leading-relaxed text-muted-foreground/60">{t('app.tagline')}</p>
      </div>
    </aside>
  )
}

/** Mobile off-canvas navigation drawer. */
export function MobileNav({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useApp((s) => s.t)

  // Close on Escape
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 md:hidden" role="dialog" aria-modal="true" aria-label={t('nav.section.monitor')}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden />
      <aside className="absolute left-0 top-0 flex h-full w-64 flex-col border-r border-sidebar-border bg-sidebar shadow-xl">
        <div className="flex items-center justify-between pr-3">
          <Brand />
          <button
            onClick={onClose}
            className="flex h-10 w-10 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
            aria-label={t('common.close')}
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="hairline mx-4" />
        <NavList onNavigate={onClose} />
        <div className="px-4 pb-4">
          <p className="text-[10px] leading-relaxed text-muted-foreground/60">{t('app.tagline')}</p>
        </div>
      </aside>
    </div>
  )
}
