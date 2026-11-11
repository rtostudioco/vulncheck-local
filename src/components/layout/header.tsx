'use client'

// SENTINEL DESK 1.0 — Global header: collector status, machine, demo badge,
// notification center, language selector, help & about (§9 global elements)

import { useEffect, useState } from 'react'
import { useApp } from '@/stores/app-store'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { MobileNav } from '@/components/layout/sidebar'
import {
  Popover, PopoverContent, PopoverTrigger,
} from '@/components/ui/popover'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger,
} from '@/components/ui/dialog'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Bell, CircleDot, Languages, HelpCircle, MonitorDot, AlertTriangle, FolderSearch, Info, Menu,
} from 'lucide-react'
import { cn } from '@/lib/utils'

export function Header() {
  const t = useApp((s) => s.t)
  const lang = useApp((s) => s.lang)
  const setLang = useApp((s) => s.setLang)
  const notifications = useApp((s) => s.notifications)
  const unread = useApp((s) => s.unread)
  const markAllRead = useApp((s) => s.markAllRead)
  const setView = useApp((s) => s.setView)
  const [collecting, setCollecting] = useState<boolean | null>(null)
  const [navOpen, setNavOpen] = useState(false)

  // Poll collector running state
  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const res = await fetch('/api/collector')
        const data = await res.json()
        if (alive) setCollecting(Boolean(data.running))
      } catch { /* keep last state */ }
    }
    load()
    const id = setInterval(load, 15000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  return (
    <TooltipProvider delayDuration={300}>
      <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-border bg-background/80 px-4 backdrop-blur">
        <div className="flex items-center gap-3">
          {/* Mobile nav trigger */}
          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9 md:hidden"
            aria-label={t('nav.section.monitor')}
            onClick={() => setNavOpen(true)}
          >
            <Menu className="h-4 w-4" />
          </Button>

          {/* Collector status */}
          <div className="flex items-center gap-2 rounded-md border bg-card px-2.5 py-1.5" aria-live="polite">
            <CircleDot
              className={cn('h-3.5 w-3.5', collecting === null ? 'text-muted-foreground' : collecting ? 'text-primary pulse-dot' : 'text-muted-foreground/60')}
              aria-hidden
            />
            <span className="text-xs font-medium text-muted-foreground">
              {t('header.collector')}
            </span>
            <span className={cn('text-xs font-semibold', collecting ? 'text-primary' : 'text-muted-foreground')}>
              {collecting ? t('header.collectorOn') : t('header.collectorOff')}
            </span>
          </div>

          {/* Machine */}
          <div className="hidden items-center gap-2 rounded-md border bg-card px-2.5 py-1.5 sm:flex">
            <MonitorDot className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            <span className="text-xs text-muted-foreground">{t('header.machine')}</span>
            <span className="font-mono text-xs text-foreground">WS-FINANCE-04</span>
          </div>

          {/* Demo data badge — mandatory transparency */}
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge variant="outline" className="sev-info hidden cursor-pointer gap-1.5 px-2 py-1 text-[10px] font-semibold tracking-wider sm:inline-flex">
                <Info className="h-3 w-3" aria-hidden />
                {t('app.demo')}
              </Badge>
            </TooltipTrigger>
            <TooltipContent side="bottom" className="max-w-xs text-xs leading-relaxed">
              {t('app.demoTooltip')}
            </TooltipContent>
          </Tooltip>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Notifications */}
          <Popover onOpenChange={(open) => open && markAllRead()}>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="icon" className="relative h-9 w-9" aria-label={t('header.notifications')}>
                <Bell className="h-4 w-4" />
                {unread > 0 && (
                  <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 font-mono text-[9px] font-bold text-primary-foreground">
                    {unread > 9 ? '9+' : unread}
                  </span>
                )}
              </Button>
            </PopoverTrigger>
            <PopoverContent align="end" className="w-96 p-0">
              <div className="border-b px-3 py-2.5">
                <p className="text-sm font-semibold">{t('header.notifications')}</p>
              </div>
              <div className="scroll-slim max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <p className="px-3 py-8 text-center text-xs text-muted-foreground">{t('header.noNotifications')}</p>
                ) : (
                  <ul className="divide-y divide-border/60">
                    {notifications.map((n) => (
                      <li key={n.id}>
                        <button
                          onClick={() => n.target && setView(n.target)}
                          className="flex w-full items-start gap-2.5 px-3 py-2.5 text-left transition-colors hover:bg-accent"
                        >
                          {n.kind === 'incident' ? (
                            <FolderSearch className="mt-0.5 h-4 w-4 shrink-0 text-[#e5bc55]" aria-hidden />
                          ) : n.kind === 'alert' ? (
                            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[#f07a72]" aria-hidden />
                          ) : (
                            <Info className="mt-0.5 h-4 w-4 shrink-0 text-[#5cbecd]" aria-hidden />
                          )}
                          <div className="min-w-0">
                            <p className="truncate text-xs font-medium">{n.title}</p>
                            <p className="mt-0.5 line-clamp-2 text-[11px] text-muted-foreground">{n.body}</p>
                            <p className="mt-1 font-mono text-[10px] text-muted-foreground/60">
                              {new Date(n.at).toLocaleTimeString()}
                            </p>
                          </div>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </PopoverContent>
          </Popover>

          {/* Language selector (§17) */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-9 gap-1.5 px-2.5" aria-label={t('st.language')}>
                <Languages className="h-4 w-4" />
                <span className="font-mono text-xs uppercase">{lang}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => setLang('en')} className={cn(lang === 'en' && 'bg-accent')}>
                English
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setLang('es')} className={cn(lang === 'es' && 'bg-accent')}>
                Español
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Help & About */}
          <Dialog>
            <DialogTrigger asChild>
              <Button variant="ghost" size="icon" className="h-9 w-9" aria-label={t('header.help')}>
                <HelpCircle className="h-4 w-4" />
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <span className="font-mono text-primary">SD</span> {t('app.name')} {t('app.version')}
                </DialogTitle>
              </DialogHeader>
              <p className="text-sm leading-relaxed text-muted-foreground">{t('header.helpBody')}</p>
              <p className="font-mono text-[11px] text-muted-foreground/70">{t('app.tagline')}</p>
            </DialogContent>
          </Dialog>
        </div>
      </header>
      <MobileNav open={navOpen} onClose={() => setNavOpen(false)} />
    </TooltipProvider>
  )
}
