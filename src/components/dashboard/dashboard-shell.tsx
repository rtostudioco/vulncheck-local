"use client";

/**
 * VulnCheck Local — dashboard shell: sticky header, sidebar navigation
 * (desktop) + Sheet navigation (mobile), section switching and footer.
 * All user-visible strings come from the i18n dictionaries (common.*).
 */

import { useEffect, useState } from "react";
import {
  AlertCircle,
  Bug,
  Check,
  ClipboardCheck,
  FileText,
  Globe,
  History,
  LayoutDashboard,
  Loader2,
  Menu,
  MonitorCog,
  Network,
  Play,
  RefreshCw,
  ScanSearch,
  Settings as SettingsIcon,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import {
  AVAILABLE_LOCALES,
  initLocaleFromStorage,
  useI18n,
} from "@/lib/i18n";
import type { Locale } from "@/lib/i18n";
import { useDashboardStore } from "@/lib/client/store";
import type { SectionId } from "@/lib/client/store";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { OverviewSection } from "./overview";
import { InventorySection } from "./inventory";
import { AssessmentSection } from "./assessment";
import { FindingsSection } from "./findings";
import { NetworkExposureSection } from "./network-exposure";
import { ComplianceSection } from "./compliance";
import { RemediationSection } from "./remediation";
import { HistorySection } from "./history";
import { ReportsSection } from "./reports";
import { SettingsSection } from "./settings";

interface NavItem {
  id: SectionId;
  labelKey: string;
  icon: LucideIcon;
}

const NAV_ITEMS: NavItem[] = [
  { id: "overview", labelKey: "overview", icon: LayoutDashboard },
  { id: "inventory", labelKey: "inventory", icon: MonitorCog },
  { id: "assessment", labelKey: "assessment", icon: ScanSearch },
  { id: "findings", labelKey: "findings", icon: Bug },
  { id: "network", labelKey: "network", icon: Network },
  { id: "compliance", labelKey: "compliance", icon: ClipboardCheck },
  { id: "remediation", labelKey: "remediation", icon: Wrench },
  { id: "history", labelKey: "history", icon: History },
  { id: "reports", labelKey: "reports", icon: FileText },
  { id: "settings", labelKey: "settings", icon: SettingsIcon },
];

function NavList({
  section,
  onSelect,
}: {
  section: SectionId;
  onSelect: (id: SectionId) => void;
}) {
  const { t } = useI18n();
  return (
    <nav aria-label={t("shell.navAria")} className="flex flex-col gap-1">
      {NAV_ITEMS.map((item) => {
        const active = section === item.id;
        const Icon = item.icon;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onSelect(item.id)}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex h-11 w-full items-center gap-3 rounded-md border-l-2 px-3 text-left text-sm font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
              active
                ? "border-primary bg-primary/10 text-foreground"
                : "border-transparent text-muted-foreground hover:bg-accent hover:text-foreground"
            )}
          >
            <Icon aria-hidden="true" className="size-4 shrink-0" />
            {t(`nav.${item.labelKey}`)}
          </button>
        );
      })}
    </nav>
  );
}

function SectionHeading({ item }: { item: NavItem }) {
  const { t } = useI18n();
  const Icon = item.icon;
  return (
    <div className="mb-6 flex items-center gap-3">
      <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
        <Icon aria-hidden="true" className="size-5" />
      </div>
      <h1 className="text-xl font-semibold tracking-tight">{t(`nav.${item.labelKey}`)}</h1>
    </div>
  );
}

/**
 * Language selector (desktop header + mobile Sheet nav).
 * State source is the shared i18n store; `locale`/`setLocale` come from the
 * shell's own useI18n() subscription so both mounts stay in sync.
 */
function LanguageMenu({
  locale,
  setLocale,
  className,
}: {
  locale: Locale;
  setLocale: (l: Locale) => void;
  className?: string;
}) {
  const { t } = useI18n();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          className={cn("h-9 shrink-0 gap-1.5 px-2.5", className)}
          aria-label={t("common.lang.label")}
        >
          <Globe aria-hidden="true" className="size-4" />
          <span className="text-xs font-semibold tabular-nums">{locale.toUpperCase()}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-36">
        {AVAILABLE_LOCALES.map((l) => (
          <DropdownMenuItem key={l.value} onSelect={() => setLocale(l.value)}>
            <span aria-hidden="true" className="flex size-4 shrink-0 items-center justify-center">
              {l.value === locale ? <Check className="size-4" /> : null}
            </span>
            {l.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function renderSection(section: SectionId): React.ReactNode {
  switch (section) {
    case "overview":
      return <OverviewSection />;
    case "inventory":
      return <InventorySection />;
    case "assessment":
      return <AssessmentSection />;
    case "findings":
      return <FindingsSection />;
    case "network":
      return <NetworkExposureSection />;
    case "compliance":
      return <ComplianceSection />;
    case "remediation":
      return <RemediationSection />;
    case "history":
      return <HistorySection />;
    case "reports":
      return <ReportsSection />;
    case "settings":
      return <SettingsSection />;
  }
}

export function DashboardShell() {
  const { locale, setLocale, t } = useI18n();
  const section = useDashboardStore((s) => s.section);
  const setSection = useDashboardStore((s) => s.setSection);
  const meta = useDashboardStore((s) => s.meta);
  const metaError = useDashboardStore((s) => s.metaError);
  const loadingMeta = useDashboardStore((s) => s.loadingMeta);
  const loadingDetail = useDashboardStore((s) => s.loadingDetail);
  const detailError = useDashboardStore((s) => s.detailError);
  const activeId = useDashboardStore((s) => s.activeId);
  const selectSession = useDashboardStore((s) => s.selectSession);
  const init = useDashboardStore((s) => s.init);
  const runAudit = useDashboardStore((s) => s.runAudit);
  const auditBusy = useDashboardStore(
    (s) => s.runStarting || s.sessions.some((x) => x.status === "RUNNING")
  );

  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    initLocaleFromStorage();
  }, []);

  useEffect(() => {
    void init();
  }, [init]);

  const handleSelect = (id: SectionId) => {
    setSection(id);
    setNavOpen(false);
  };

  const activeItem = NAV_ITEMS.find((i) => i.id === section) ?? NAV_ITEMS[0];

  return (
    <div className="vc-dark flex min-h-screen flex-col bg-background text-foreground">
      {/* Header */}
      <header className="sticky top-0 z-40 flex h-14 shrink-0 items-center justify-between gap-3 border-b bg-background/95 px-4 backdrop-blur md:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            className="size-11 md:hidden"
            aria-label={t("shell.openNav")}
            onClick={() => setNavOpen(true)}
          >
            <Menu aria-hidden="true" className="size-5" />
          </Button>
          <ShieldCheck aria-hidden="true" className="size-5 shrink-0 text-primary" />
          <span className="truncate font-semibold tracking-tight">VulnCheck Local</span>
          {meta ? (
            <Badge variant="outline" className="hidden shrink-0 sm:inline-flex">
              v{meta.engineVersion}
            </Badge>
          ) : null}
          {meta ? (
            <Badge variant="secondary" className="hidden shrink-0 md:inline-flex">
              {meta.platform}
            </Badge>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <LanguageMenu locale={locale} setLocale={setLocale} />
          <Button
            className="h-11 shrink-0 px-4 md:h-9"
            onClick={() => void runAudit()}
            disabled={auditBusy}
          >
            {auditBusy ? (
              <Loader2 aria-hidden="true" className="size-4 animate-spin" />
            ) : (
              <Play aria-hidden="true" className="size-4" />
            )}
            {auditBusy ? t("shell.auditing") : t("shell.runAudit")}
          </Button>
        </div>
      </header>

      {/* Body */}
      <div className="flex w-full flex-1">
        {/* Desktop sidebar */}
        <aside className="hidden w-60 shrink-0 border-r md:block">
          <div className="sticky top-14 flex h-[calc(100vh-3.5rem)] flex-col overflow-y-auto p-3 vc-scroll">
            <NavList section={section} onSelect={handleSelect} />
          </div>
        </aside>

        {/* Mobile sheet nav */}
        <Sheet open={navOpen} onOpenChange={setNavOpen}>
          <SheetContent side="left" id="nav-sheet" className="w-72 gap-0 p-0">
            <SheetHeader className="border-b px-4 py-4 text-left">
              <SheetTitle className="flex items-center gap-2 text-sm">
                <ShieldCheck aria-hidden="true" className="size-4 text-primary" />
                VulnCheck Local
              </SheetTitle>
              <SheetDescription>{t("shell.nav.description")}</SheetDescription>
            </SheetHeader>
            <div className="flex-1 overflow-y-auto p-3 vc-scroll">
              <NavList section={section} onSelect={handleSelect} />
            </div>
            <div className="border-t p-3">
              <LanguageMenu
                locale={locale}
                setLocale={setLocale}
                className="w-full justify-between"
              />
            </div>
          </SheetContent>
        </Sheet>

        {/* Content */}
        <main className="min-w-0 flex-1">
          <div className="mx-auto w-full max-w-[1400px] p-4 md:p-6">
            {metaError ? (
              <Alert variant="destructive" className="mb-6">
                <AlertCircle aria-hidden="true" />
                <AlertTitle>{t("shell.error.meta")}</AlertTitle>
                <AlertDescription>{metaError}</AlertDescription>
                <div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2 h-9"
                    onClick={() => void init()}
                  >
                    <RefreshCw aria-hidden="true" className="size-3.5" />
                    {t("shell.retry")}
                  </Button>
                </div>
              </Alert>
            ) : null}

            {detailError && !loadingDetail ? (
              <Alert variant="destructive" className="mb-6">
                <AlertCircle aria-hidden="true" />
                <AlertTitle>{t("shell.error.detail")}</AlertTitle>
                <AlertDescription>{detailError}</AlertDescription>
                <div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2 h-9"
                    disabled={!activeId}
                    onClick={() => {
                      if (activeId) void selectSession(activeId);
                    }}
                  >
                    <RefreshCw aria-hidden="true" className="size-3.5" />
                    {t("shell.retry")}
                  </Button>
                </div>
              </Alert>
            ) : null}

            <AnimatePresence mode="wait" initial={false}>
              <motion.div
                key={section}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.18, ease: "easeOut" }}
              >
                {loadingMeta && !meta ? (
                  <div className="space-y-6">
                    <SectionHeading item={activeItem} />
                    <Skeleton className="h-52 w-full rounded-xl" />
                    <Skeleton className="h-72 w-full rounded-xl" />
                  </div>
                ) : (
                  <>
                    <SectionHeading item={activeItem} />
                    {renderSection(section)}
                  </>
                )}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer className="mt-auto border-t px-4 py-3 md:px-6">
        <div className="mx-auto flex max-w-[1400px] flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs leading-relaxed text-muted-foreground sm:max-w-2xl sm:text-pretty">
            {t("shell.footer.guarantee", { version: meta?.engineVersion ?? "—" })}
          </p>
          <div className="flex shrink-0 flex-col gap-0.5 sm:items-end">
            <p className="text-xs text-muted-foreground tabular-nums">
              {t("shell.footer.engine", {
                version: meta?.engineVersion ?? "—",
                rules: meta?.ruleCount ?? "—",
              })}
            </p>
            <p className="text-xs text-muted-foreground/80">
              {t("shell.credit", { year: new Date().getFullYear() })}
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
