# Sentinel Desk 1.0 — Installation & Operation

## Requirements

- Node.js ≥ 20 or Bun ≥ 1.1 (Bun recommended; this build was developed and verified on Bun)
- ~200 MB disk for dependencies + database

## Setup

```bash
bun install          # or: npm install
bun run db:push      # create/refresh the SQLite database at db/sentinel.db
bun run dev          # start on http://localhost:3000
```

The first request provisions the event-source registry, the ten detection rules, default settings and a few labeled demo indicators (idempotent bootstrap).

## First-run tour

1. **Overview** — see collector health, counts and the last pipeline run.
2. **Live Monitor → Collect now** — pulls one synthetic batch through the full pipeline. Enable **Settings → Collector → Automatic collection** for continuous batches (default every 20 s; the app tab drives the interval and shows toasts/notifications for new alerts and incidents).
3. **Detections** — each rule documents its logic, false positives and limitations. **Run test** executes the rule against its synthetic fixture and shows the real evaluation result.
4. **Incidents** — correlated alerts become cases. Change status (New → Investigating → …), read the correlation hypothesis (always labeled as a hypothesis), expand each alert's evidence.
5. **Timeline** — the relationship graph shows incident → alerts (dashed = inferred) → evidence events (solid = observed). A chronological list with command lines serves as the accessible alternative.
6. **AI Analyst** — pick an incident, review the privacy preview, run the analysis. Output is labeled AI-generated, redacted per settings, and recorded with provider/model/prompt version.
7. **Response Center** — advisory checklists per incident; export as JSON. Nothing is executed.
8. **Reports** — generate a preview, download JSON (SHA-256 integrity metadata) or CSV, or use Print/Save-as-PDF.
9. **Settings** — language (EN/ES), collector, retention, AI mode/redaction, TI consent, data purge/reset, local audit log.

## Configuration reference (Settings are persisted in SQLite)

| Setting | Values | Effect |
|---|---|---|
| Language | en / es | Entire UI (§17); persisted server-side + client store |
| Automatic collection | on / off | Drives the pipeline tick loop |
| Collection interval | 5–600 s | Tick cadence |
| Event retention | 1–365 days | Older events pruned each tick (raw payloads are not kept indefinitely) |
| AI provider mode | off / sandbox / local / remote | off disables AI entirely; local/remote are shown for desktop parity and require configured providers |
| AI redaction | on / off | Redact hosts/users/IPs/base64 before AI input (default **on**) |
| TI external consent | on / off | Global gate; every lookup still requires explicit per-indicator consent |

## Data management

- **Delete all events, alerts & incidents** — purges collected data, keeps rules/indicators/settings (audited).
- **Reset application data** — factory state for everything including settings and indicators (audited).
- The database file lives at `db/sentinel.db`; back it up by copying the file while the app is idle.

## Troubleshooting

| Symptom | Resolution |
|---|---|
| No events appear | Collector is paused by default — use Collect now or enable automatic collection. |
| Rule test shows "no match" | The rule's fixture should always match; a no-match is a defect — check the rule logic JSON and the explanation panel. |
| AI analysis fails | Check AI mode in Settings; provider failures degrade to a labeled deterministic fallback, never a fake success. |
| External TI lookup returns "unavailable" | Honest result: no external provider is configured in this build. Verdicts remain unknown by design. |
