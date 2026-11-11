// MODULE 01 — Overview (desktop): real IPC data, honest empty states.

import { useCallback, useEffect, useState } from "react";
import { ipc, type OverviewStats } from "../lib/ipc";

type T = (key: string) => string;

const SEV_CLASS: Record<string, string> = {
  critical: "sev sev-critical",
  high: "sev sev-high",
  medium: "sev sev-medium",
  low: "sev sev-low",
  info: "sev sev-info",
};

export default function OverviewPage({ t, onChanged }: { t: T; onChanged: () => void }) {
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    ipc
      .overviewStats()
      .then(setStats)
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const collectNow = async () => {
    setBusy(true);
    try {
      await ipc.collectorTick();
      refresh();
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="spread">
        <div>
          <h1 className="page-title">{t("ov.title")}</h1>
          <p className="page-sub">{t("ov.sub")}</p>
        </div>
        <div className="row">
          <button className="btn" onClick={refresh} type="button">↻ {t("nav.overview")}</button>
          <button className="btn primary" onClick={() => void collectNow()} disabled={busy} type="button">
            ▶ {t("ov.collectNow")}
          </button>
        </div>
      </div>

      {error && <div className="notice">⚠ {t("common.error")}: <span className="mono">{error}</span></div>}

      {!stats && !error && <div className="empty">…</div>}

      {stats && (
        <>
          <div className="grid stats" style={{ marginBottom: 14 }}>
            <div className="card">
              <div className="stat-label">{t("ov.events24h")}</div>
              <div className="stat-value mono">{stats.events24h}</div>
              <div className="stat-hint">{stats.eventsTotal} total</div>
            </div>
            <div className="card">
              <div className="stat-label">{t("ov.openAlerts")}</div>
              <div className="stat-value mono">{stats.openAlerts}</div>
            </div>
            <div className="card">
              <div className="stat-label">{t("ov.activeIncidents")}</div>
              <div className="stat-value mono">{stats.activeIncidents}</div>
            </div>
            <div className="card">
              <div className="stat-label">{t("ov.rules")}</div>
              <div className="stat-value mono">
                {stats.rulesEnabled}/{stats.rulesTotal}
              </div>
            </div>
          </div>

          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
            <div className="card">
              <div className="stat-label" style={{ marginBottom: 10 }}>{t("ov.sources")}</div>
              <table>
                <thead>
                  <tr><th>Channel</th><th>Status</th><th>Events</th></tr>
                </thead>
                <tbody>
                  {stats.sources.map((s) => (
                    <tr key={s.channel}>
                      <td className="mono">{s.channel}</td>
                      <td>
                        <span className={s.status === "active" ? "sev sev-success" : s.status === "permission_required" ? "sev sev-medium" : "sev sev-info"}>
                          {s.available ? "●" : "○"} {s.status}
                        </span>
                        {s.note && <div className="stat-hint">{s.note}</div>}
                      </td>
                      <td className="mono">{s.eventsCollected}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="card">
              <div className="stat-label" style={{ marginBottom: 10 }}>{t("common.sev.info").toUpperCase()} · BY SEVERITY</div>
              <table>
                <thead>
                  <tr><th>Severity</th><th>Alerts</th><th>Incidents</th></tr>
                </thead>
                <tbody>
                  {stats.bySeverity.map((b) => (
                    <tr key={b.severity}>
                      <td><span className={SEV_CLASS[b.severity] ?? "sev sev-info"}>▲ {b.severity}</span></td>
                      <td className="mono">{b.alerts}</td>
                      <td className="mono">{b.incidents}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
