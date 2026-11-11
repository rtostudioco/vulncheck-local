// MODULE 02 — Live Monitor (desktop): events table + filters + detail pane.

import { useCallback, useEffect, useState } from "react";
import { ipc, type EventRow } from "../lib/ipc";

type T = (key: string) => string;

const CHANNELS = ["All", "Security", "System", "PowerShell/Operational", "TaskScheduler/Operational", "Sysmon"];
const LEVELS = ["All", "Information", "Warning", "Error", "Critical"];

export default function EventsPage({ t }: { t: T }) {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [channel, setChannel] = useState("All");
  const [level, setLevel] = useState("All");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<EventRow | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    ipc
      .eventsQuery({
        channel: channel === "All" ? undefined : channel,
        level: level === "All" ? undefined : level,
        search: search || undefined,
        pageSize: 100,
      })
      .then((r) => {
        setEvents(r.events);
        setTotal(r.total);
        setError(null);
      })
      .catch((e) => setError(String(e)));
  }, [channel, level, search]);

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, [load]);

  return (
    <div>
      <h1 className="page-title">{t("ev.title")}</h1>
      <p className="page-sub">{t("ev.sub")}</p>

      <div className="row" style={{ marginBottom: 14 }}>
        <input
          placeholder={t("ev.search")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ minWidth: 260 }}
          aria-label={t("ev.search")}
        />
        <select value={channel} onChange={(e) => setChannel(e.target.value)} aria-label="Channel">
          {CHANNELS.map((c) => <option key={c}>{c}</option>)}
        </select>
        <select value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Level">
          {LEVELS.map((l) => <option key={l}>{l}</option>)}
        </select>
        <span className="pill mono">{total} events</span>
      </div>

      {error && <div className="notice">⚠ {t("common.error")}: <span className="mono">{error}</span></div>}

      {events.length === 0 && !error && <div className="empty">{t("ev.empty")}</div>}

      {events.length > 0 && (
        <div className="grid" style={{ gridTemplateColumns: "2fr 1fr", alignItems: "start" }}>
          <div className="card" style={{ padding: 0, maxHeight: "70vh", overflowY: "auto" }}>
            <table>
              <thead>
                <tr><th>Time</th><th>Channel</th><th>EventID</th><th>Level</th><th>Computer</th><th>User</th></tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr
                    key={e.id}
                    className={selected?.id === e.id ? "selected" : ""}
                    onClick={() => setSelected(e)}
                    style={{ cursor: "pointer" }}
                  >
                    <td className="mono">{new Date(e.ts).toLocaleTimeString()}</td>
                    <td className="mono">{e.channel}</td>
                    <td className="mono">{e.eventId}</td>
                    <td>
                      <span className={e.level === "Warning" ? "sev sev-medium" : e.level === "Error" || e.level === "Critical" ? "sev sev-critical" : "sev sev-info"}>
                        {e.level}
                      </span>
                    </td>
                    <td className="mono">{e.computer}</td>
                    <td className="mono">{e.userName ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card">
            {selected ? (
              <>
                <div className="stat-label">EVENT DETAIL</div>
                <p className="mono" style={{ fontSize: 12, lineHeight: 1.7 }}>
                  {Object.entries(selected).map(([k, v]) => (
                    <span key={k}>
                      <span style={{ color: "var(--text-faint)" }}>{k}</span>: {String(v ?? "—")}
                      <br />
                    </span>
                  ))}
                </p>
                <div className="notice" style={{ marginTop: 12 }}>
                  Provenance: <span className="mono">{selected.sourceRef ?? "evt record"}</span> · record{" "}
                  <span className="mono">{selected.recordId ?? "—"}</span>
                </div>
              </>
            ) : (
              <div className="empty">Select an event to inspect its normalized fields and provenance.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
