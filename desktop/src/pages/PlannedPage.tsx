// Honest "planned" page — the spec forbids fake data and dead buttons.
// Modules that exist in the verified web prototype but are not yet ported to
// the desktop shell are listed here with their planned phase, no mock UI.

type T = (key: string) => string;

const PLANNED = [
  { key: "Timeline — chronological reconstruction & relationship graph", phase: "Phase 5" },
  { key: "Threat Intel — local indicators + consent-gated lookups", phase: "Phase 5" },
  { key: "AI Analyst — local-first provider, redaction preview, audit trail", phase: "Phase 5" },
  { key: "Response Center — advisory-only checklists (never executes)", phase: "Phase 5" },
  { key: "SOC Reports UI — JSON/CSV builders already exist in the Rust backend", phase: "Phase 5" },
  { key: "Settings UI — commands already exist (settings_get / settings_save / audit_list)", phase: "Phase 5" },
];

export default function PlannedPage({ t }: { t: T }) {
  return (
    <div>
      <h1 className="page-title">{t("pl.title")}</h1>
      <p className="page-sub">{t("pl.sub")}</p>
      <div className="card">
        {PLANNED.map((p) => (
          <div key={p.key} className="spread" style={{ borderBottom: "1px solid var(--border)", padding: "10px 2px" }}>
            <span style={{ fontSize: 13, color: "var(--text-dim)" }}>{p.key}</span>
            <span className="pill mono">{p.phase}</span>
          </div>
        ))}
      </div>
      <div className="notice">
        The full interactive experience of every module above is verified in the Sentinel Desk web
        prototype. The desktop build prioritizes the read-only Windows collector, the detection
        pipeline and the incident workflow first (Phases 1–4), then ports the remaining views.
      </div>
    </div>
  );
}
