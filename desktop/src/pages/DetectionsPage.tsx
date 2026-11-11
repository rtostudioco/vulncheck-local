// MODULE 03 — Detections (desktop): rule cards + toggle + dry-run fixture test.

import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, ShieldX } from "lucide-react";
import { ipc, type RuleSummary, type RuleTestResult } from "../lib/ipc";

type T = (key: string) => string;

const SEV_CLASS: Record<string, string> = {
  critical: "sev sev-critical",
  high: "sev sev-high",
  medium: "sev sev-medium",
  low: "sev sev-low",
  info: "sev sev-info",
};

export default function DetectionsPage({ t }: { t: T }) {
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [tests, setTests] = useState<Record<string, RuleTestResult>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    ipc.rulesList().then((r) => setRules(r.rules)).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggle = async (rule: RuleSummary) => {
    await ipc.ruleToggle(rule.id, !rule.enabled).catch((e) => setError(String(e)));
    load();
  };

  const runTest = async (rule: RuleSummary) => {
    setTesting(rule.id);
    try {
      const result = await ipc.ruleTest(rule.id);
      setTests((prev) => ({ ...prev, [rule.id]: result }));
    } catch (e) {
      setError(String(e));
    } finally {
      setTesting(null);
    }
  };

  return (
    <div>
      <h1 className="page-title">{t("dt.title")}</h1>
      <p className="page-sub">{t("dt.sub")}</p>

      {error && <div className="notice">⚠ {t("common.error")}: <span className="mono">{error}</span></div>}

      <div className="grid" style={{ gridTemplateColumns: "repeat(2, minmax(0, 1fr))" }}>
        {rules.map((r) => (
          <div className="card" key={r.id} style={{ opacity: r.enabled ? 1 : 0.6 }}>
            <div className="spread">
              <div className="row">
                <span className="mono" style={{ color: "var(--primary)", fontWeight: 700 }}>{r.id}</span>
                <span style={{ fontWeight: 600 }}>{r.name}</span>
                <span className={SEV_CLASS[r.severity] ?? "sev sev-info"}>▲ {r.severity}</span>
              </div>
              <button className="btn" onClick={() => void toggle(r)} type="button" aria-label={`${r.id} ${r.enabled ? t("dt.disabled") : t("dt.enabled")}`}>
                {r.enabled ? t("dt.enabled") : t("dt.disabled")}
              </button>
            </div>
            <div className="row" style={{ marginTop: 8 }}>
              {r.mitreId && <span className="pill mono">MITRE {r.mitreId}{r.mitreName ? ` · ${r.mitreName}` : ""}</span>}
              <span className="pill">{r.alertCount} {t("dt.alerts")}</span>
              <span className="pill mono">v{r.version}</span>
            </div>
            <p style={{ color: "var(--text-dim)", fontSize: 12.5, lineHeight: 1.55 }}>{r.description}</p>
            <button className="btn" onClick={() => void runTest(r)} disabled={testing === r.id} type="button">
              🧪 {t("dt.runTest")}
            </button>
            {tests[r.id] && (
              <div className={tests[r.id].matched ? "test-pass" : "notice"} role="status">
                <div className="row">
                  {tests[r.id].matched ? <ShieldCheck size={14} aria-hidden /> : <ShieldX size={14} aria-hidden />}
                  <b style={{ fontSize: 12 }}>{tests[r.id].matched ? t("dt.passed") : t("dt.failed")}</b>
                </div>
                <p className="mono" style={{ fontSize: 11.5, marginTop: 6, lineHeight: 1.6 }}>{tests[r.id].explanation}</p>
                <p className="stat-hint">{t("dt.fixtures")}: {tests[r.id].fixtureEvents} · fixture: <span className="mono">{tests[r.id].fixtureScenario}</span></p>
              </div>
            )}
            <details style={{ marginTop: 10 }}>
              <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--text-dim)" }}>Limitations &amp; false positives</summary>
              <p style={{ fontSize: 11.5, color: "var(--text-dim)", lineHeight: 1.55 }}>
                <b>False positives:</b> {r.falsePositives}
                <br />
                <b>Limitations:</b> {r.limitations}
              </p>
            </details>
          </div>
        ))}
      </div>
    </div>
  );
}
