// SENTINEL DESK 1.0 — Desktop app shell
// Sidebar + header + view router (react-router), wired to Tauri IPC only.

import { useCallback, useEffect, useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import {
  Activity, BellRing, Database, FolderSearch, LayoutDashboard, Shield,
  ShieldAlert, Hourglass,
} from "lucide-react";
import { ipc, type CollectorStatus } from "./lib/ipc";
import { translate, type Lang } from "./i18n";
import OverviewPage from "./pages/OverviewPage";
import EventsPage from "./pages/EventsPage";
import DetectionsPage from "./pages/DetectionsPage";
import IncidentsPage from "./pages/IncidentsPage";
import PlannedPage from "./pages/PlannedPage";

export default function App() {
  const [lang, setLang] = useState<Lang>("en");
  const [collector, setCollector] = useState<CollectorStatus | null>(null);
  const [machine, setMachine] = useState("—");

  const t = useCallback((key: string) => translate(lang, key), [lang]);

  const refreshCollector = useCallback(() => {
    ipc.collectorStatus().then(setCollector).catch(() => undefined);
  }, []);

  useEffect(() => {
    void refreshCollector();
    const timer = setInterval(refreshCollector, 10000);
    return () => clearInterval(timer);
  }, [refreshCollector]);

  useEffect(() => {
    ipc.settingsGet().then((s) => setLang(s.language === "es" ? "es" : "en")).catch(() => undefined);
  }, []);

  // Current machine name: from the most recent event's computer field
  useEffect(() => {
    ipc
      .eventsQuery({ pageSize: 10 })
      .then((r) => {
        const c = r.events.find((e) => e.computer)?.computer;
        if (c) setMachine(c);
      })
      .catch(() => undefined);
  }, [collector?.running]);

  const navGroups: { label: string; items: { to: string; label: string; icon: React.ReactNode }[] }[] = [
    {
      label: t("nav.monitor"),
      items: [
        { to: "/", label: t("nav.overview"), icon: <LayoutDashboard size={15} /> },
        { to: "/events", label: t("nav.events"), icon: <Activity size={15} /> },
      ],
    },
    {
      label: t("nav.investigate"),
      items: [
        { to: "/detections", label: t("nav.detections"), icon: <ShieldAlert size={15} /> },
        { to: "/incidents", label: t("nav.incidents"), icon: <FolderSearch size={15} /> },
      ],
    },
    {
      label: t("nav.tools"),
      items: [
        { to: "/planned", label: t("nav.planned"), icon: <Hourglass size={15} /> },
      ],
    },
  ];

  const active = (to: string): string =>
    (to === "/" ? window.location.pathname === "/" : window.location.pathname.startsWith(to))
      ? "nav-item active"
      : "nav-item";

  return (
    <BrowserRouter>
      <div className="app">
        <aside className="sidebar" role="navigation" aria-label={t("app.name")}>
          <div className="brand">
            <div className="brand-shield" aria-hidden>
              <Shield size={17} />
            </div>
            <div>
              <div className="brand-name">{t("app.name")}</div>
              <div className="brand-ver">{t("app.version")}</div>
            </div>
          </div>
          {navGroups.map((g) => (
            <div className="nav-group" key={g.label}>
              <div className="nav-label">{g.label}</div>
              {g.items.map((item) => (
                <button
                  key={item.to}
                  className={active(item.to)}
                  onClick={() => (window.location.href = item.to)}
                  type="button"
                >
                  {item.icon}
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </aside>

        <div className="main">
          <header className="header" role="banner">
            <span className="pill" aria-live="polite">
              <span className={collector?.running ? "dot on" : "dot"} aria-hidden />
              {t("hd.collector")} <b>{collector?.running ? t("hd.running") : t("hd.paused")}</b>
            </span>
            <span className="pill">
              {t("hd.machine")} <b className="mono">{machine}</b>
            </span>
            <span className="badge-demo">LOCAL · READ-ONLY</span>
            <span style={{ flex: 1 }} />
            <span className="pill" title={t("app.notEdr")}>
              <BellRing size={12} aria-hidden /> {t("app.notEdr")}
            </span>
          </header>

          <main className="content" role="main">
            <Routes>
              <Route path="/" element={<OverviewPage t={t} onChanged={refreshCollector} />} />
              <Route path="/events" element={<EventsPage t={t} />} />
              <Route path="/detections" element={<DetectionsPage t={t} />} />
              <Route path="/incidents" element={<IncidentsPage t={t} />} />
              <Route path="/planned" element={<PlannedPage t={t} />} />
            </Routes>
          </main>

          <footer className="footer" role="contentinfo">
            <span>
              <Database size={11} aria-hidden style={{ verticalAlign: "-1.5px", marginRight: 5 }} />
              {t("app.name")} <span className="mono">{t("app.version")}</span> · {t("app.tagline")}
            </span>
            <span>{t("app.notEdr")}</span>
          </footer>
        </div>
      </div>
    </BrowserRouter>
  );
}
