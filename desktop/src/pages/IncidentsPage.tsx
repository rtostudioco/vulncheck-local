// MODULE 05 — Incident Center (desktop): list + detail + status + notes.
// The hypothesis banner enforces the five-layer discipline: a correlation is
// presented as a HYPOTHESIS, never as a confirmed compromise.

import { useCallback, useEffect, useState } from "react";
import { ipc, type IncidentDetail, type IncidentSummary } from "../lib/ipc";

type T = (key: string) => string;

const SEV_CLASS: Record<string, string> = {
  critical: "sev sev-critical",
  high: "sev sev-high",
  medium: "sev sev-medium",
  low: "sev sev-low",
  info: "sev sev-info",
};
const STATUSES = ["new", "investigating", "monitoring", "resolved", "false_positive"];

export default function IncidentsPage({ t }: { t: T }) {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    ipc
      .incidentsList({ pageSize: 100 })
      .then((r) => setIncidents(r.incidents))
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 20000);
    return () => clearInterval(timer);
  }, [load]);

  const open = (id: string) => {
    ipc.incidentGet(id).then(setDetail).catch((e) => setError(String(e)));
  };

  const changeStatus = async (status: string) => {
    if (!detail) return;
    try {
      await ipc.incidentStatus(detail.id, status);
      const fresh = await ipc.incidentGet(detail.id);
      setDetail(fresh);
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  const addNote = async () => {
    if (!detail || !note.trim()) return;
    try {
      await ipc.incidentNoteAdd(detail.id, note);
      setNote("");
      setDetail(await ipc.incidentGet(detail.id));
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div>
      <h1 className="page-title">{t("in.title")}</h1>
      <p className="page-sub">{t("in.sub")}</p>

      {error && <div className="notice">⚠ {t("common.error")}: <span className="mono">{error}</span></div>}

      <div className="grid" style={{ gridTemplateColumns: "1fr 2fr", alignItems: "start" }}>
        <div className="card" style={{ padding: 0, maxHeight: "70vh", overflowY: "auto" }}>
          {incidents.length === 0 && <div className="empty">No incidents yet.</div>}
          {incidents.map((i) => (
            <button
              key={i.id}
              className="nav-item"
              style={{ border: "none", borderBottom: "1px solid var(--border)", width: "100%" }}
              onClick={() => open(i.id)}
              type="button"
            >
              <span className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
                <span className="mono" style={{ color: "var(--primary)" }}>{i.code}</span>
                <span className={SEV_CLASS[i.severity] ?? "sev sev-info"}>▲ {i.severity}</span>
                <span style={{ color: "var(--text-faint)", fontSize: 11 }}>{i.status}</span>
              </span>
            </button>
          ))}
        </div>

        <div>
          {!detail && <div className="empty">Select an incident.</div>}
          {detail && (
            <>
              <div className="card">
                <div className="spread">
                  <div className="row">
                    <span className="mono" style={{ color: "var(--primary)", fontWeight: 700 }}>{detail.code}</span>
                    <span className={SEV_CLASS[detail.severity] ?? "sev sev-info"}>▲ {detail.severity}</span>
                    <span className="pill">{detail.status}</span>
                  </div>
                  <select value={detail.status} onChange={(e) => void changeStatus(e.target.value)} aria-label={t("in.status")}>
                    {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <h2 style={{ margin: "10px 0 0", fontSize: 16 }}>{detail.title}</h2>
              </div>

              {detail.hypothesis && (
                <div className="hypothesis" role="note">
                  <div className="h-title">⚠ Correlation hypothesis</div>
                  <p>{detail.hypothesis}</p>
                </div>
              )}

              <div className="card" style={{ marginTop: 12 }}>
                <div className="stat-label" style={{ marginBottom: 8 }}>RELATED ALERTS ({detail.alerts.length})</div>
                <table>
                  <thead><tr><th>Rule</th><th>Severity</th><th>Summary</th></tr></thead>
                  <tbody>
                    {detail.alerts.map((a) => (
                      <tr key={a.id}>
                        <td className="mono" style={{ color: "var(--primary)" }}>{a.ruleId}</td>
                        <td><span className={SEV_CLASS[a.severity] ?? "sev sev-info"}>▲ {a.severity}</span></td>
                        <td style={{ fontSize: 12 }}>{a.summary}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="card" style={{ marginTop: 12 }}>
                <div className="stat-label" style={{ marginBottom: 8 }}>ANALYST NOTES</div>
                {detail.notes.map((n) => (
                  <div key={n.id} style={{ borderBottom: "1px solid var(--border)", padding: "8px 0" }}>
                    <span className="pill" style={{ fontSize: 10 }}>{n.author}</span>
                    <p style={{ margin: "6px 0 0", fontSize: 12.5, color: "var(--text-dim)", lineHeight: 1.55 }}>{n.body}</p>
                  </div>
                ))}
                <div className="row" style={{ marginTop: 12 }}>
                  <input
                    style={{ flex: 1 }}
                    placeholder={t("in.note")}
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    aria-label={t("in.note")}
                  />
                  <button className="btn primary" onClick={() => void addNote()} disabled={!note.trim()} type="button">
                    {t("in.addNote")}
                  </button>
                </div>
                <p className="stat-hint" style={{ marginTop: 10 }}>{t("in.timeline")}</p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
