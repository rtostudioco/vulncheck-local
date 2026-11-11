# Sentinel Desk 1.0 — Architecture

## 1. Build target and porting strategy

This repository implements the Sentinel Desk product architecture on a **Next.js 16 (App Router) + TypeScript + Prisma/SQLite** stack. The original product specification targets **Tauri 2 + React + Rust on Windows**; this build is the environment-feasible implementation of the same architecture, with one deliberate substitution:

| Spec component | This build | Desktop port (Tauri 2) |
|---|---|---|
| Windows Event Log collector | `src/lib/engine/generator.ts` — synthetic, labeled source emitting XML-shaped raw records | Rust `collectors/` module using `windows-rs` (`EvtQuery`/`EvtSubscribe`) — **same raw payload shape**, so the normalizer logic transfers 1:1 |
| Secure IPC layer | Next.js route handlers under `src/app/api/**` (typed, validated) | Tauri commands + capabilities; the frontend already speaks request/response, so handlers map to commands |
| Rust application core | TypeScript engine modules (`src/lib/engine/*`) | Same modules in Rust; rule JSON format is portable by design |
| Storage | Prisma + SQLite (`db/sentinel.db`) | `rusqlite` with the same schema and versioned migrations |
| AI Gateway | Server-side `z-ai-web-dev-sdk` (never client-side) | Rust HTTP client to the configured local/remote provider |
| Frontend | React 19 + Tailwind 4 + shadcn/ui + Zustand + Recharts | Unchanged (Tauri hosts the same frontend) |

The frontend contains **no** engine logic: it exclusively consumes the API contract. That is the boundary that makes the desktop port mechanical rather than a rewrite.

## 2. Layer map

```
src/
├── app/page.tsx                  # App shell: sidebar, header, view router, collector loop
├── app/api/**                    # "IPC" layer — one route per command group
│   ├── overview/                 # GET  aggregated dashboard payload
│   ├── events/, events/[id]/     # GET list+detail, DELETE purge
│   ├── collector/                # GET status, POST tick|start|stop
│   ├── rules/, rules/[id]/test/  # GET catalog, PATCH toggle, POST fixture test
│   ├── incidents/**              # GET list+detail, PATCH status, POST notes
│   ├── ai/analyze/               # POST incident explanation (backend-only LLM)
│   ├── ti/analyze/, ti/lookup/   # POST indicator analysis, consent-gated lookup
│   ├── reports/                  # GET json|csv exports
│   └── settings/                 # GET/PATCH/DELETE settings + audit
├── components/
│   ├── layout/                   # sidebar (desktop + mobile drawer), header
│   ├── shared/                   # severity/status badges, empty states, markdown
│   └── views/                    # one file per module (10 views)
├── lib/
│   ├── engine/
│   │   ├── rules.ts              # SD-001…SD-010 catalog (portable JSON logic)
│   │   ├── generator.ts          # synthetic Windows event scenarios (labeled)
│   │   ├── normalizer.ts         # raw → common schema + human summary
│   │   ├── detection.ts          # single/threshold/correlation evaluation
│   │   └── pipeline.ts           # orchestrator + incident grouping + rule tests
│   ├── ai.ts                     # AI gateway: evidence bundle, redaction, audit
│   ├── bootstrap.ts              # idempotent source/rule/settings provisioning
│   ├── i18n.ts                   # EN/ES dictionaries
│   ├── serialize.ts              # DB row → API contract
│   └── db.ts                     # Prisma client
├── stores/app-store.ts           # Zustand: view, language, notifications
└── types/soc.ts                  # shared API contract types
```

## 3. Data flow (§7 of the product spec)

1. **Collector** — `generateBatch()` emits scenario bursts (raw Windows records with `recordId`, provider, XML-data fields, `sourceRef` provenance). In the desktop build this is the only file replaced by a real EVTX subscription.
2. **Normalizer** — `normalize()` maps raw → common schema (channel, provider, eventId, level, computer, user/SID, process tree, command line, IP, logon type, service/task names) + a search summary + the original raw JSON for reproducibility.
3. **Detection** — three logic kinds:
   - `single`: per-event condition matchers (op: eq/in/neq/contains/regex/startsWith/gt/lt). Sigma-style inline flags `(?i)` are translated to JS regex flags.
   - `threshold`: grouped sliding-window counts (e.g. ≥5 × 4625 in 300 s per computer).
   - `correlation`: combines prior rule matches (+ optional direct event conditions) inside a window linked by shared fields. Emits **hypotheses**, never confirmations.
4. **Correlation/incident engine** — clusters alerts by computer within a 20-minute window; opens a case when a high/critical alert exists or ≥2 distinct rules converge; writes a system note documenting the linkage parameters.
5. **Persistence** — all stages write to SQLite; `AlertEvent` join table preserves exactly which events constitute each alert's evidence.
6. **AI / UI** — evidence-only AI explanation, always-labeled output; UI never receives data outside the API contract.

### Pipeline observability
Every tick returns/records a `PipelineRun`: per-stage `{status, input, output, errors[], durationMs}`. The Overview renders the last run. Retention pruning runs on each tick (`settings.retentionDays`).

## 4. Database schema (SQLite)

Entities (`prisma/schema.prisma`): `Event` (fully indexed: ts, eventId, channel, computer, processId), `EventSource`, `DetectionRule`, `Alert` + `AlertEvent` (evidence join), `Incident`, `IncidentNote`, `AiAnalysis`, `Indicator`, `Setting`, `AuditLog`.

Design decisions:
- Raw payloads are stored **with** events for reproducibility, but retention pruning deletes aged events (default 7 days) — raw payloads are not retained indefinitely (§11).
- Alerts store denormalized evidence JSON (eventIds + matched fields) for fast rendering, plus the relational join for integrity.
- Identifiers are CUIDs; incident codes are sequential human-readable (`INC-0007`).
- All queries are parameterized through Prisma; writes that must stay consistent (alert + evidence rows) are looped per alert with per-item error capture feeding stage errors.

## 5. Rule format (portable)

```json
{
  "kind": "threshold",
  "channel": "Security",
  "eventIds": [4625],
  "threshold": { "count": 5, "windowSec": 300, "groupBy": ["computer"] },
  "conditions": []
}
```

Correlation rules reference `signals: [{ruleId, minCount}]` and `linkBy: ["computer"]`. This JSON is stored per rule in the DB and re-serializable to YAML for Sigma-family tooling. `docs/DETECTION-RULES.md` documents the full catalog.

## 6. Testing

- **Rule fixture tests**: `POST /api/rules/:id/test` regenerates the rule's synthetic scenario (deterministic seed), runs the real evaluator, and returns match/no-match with the explanation. All 10 rules pass.
- **Type safety**: `bunx tsc --noEmit` covers the whole codebase.
- **Lint**: `bun run lint` (ESLint 9).
- **Manual E2E**: every view exercised in a real browser; pipeline verified from collection to incident to AI analysis to notifications.
- The Rust port adds `cargo test` for normalizer/detection units; the rule JSON fixtures in `src/lib/engine/rules.ts` are the shared test vector source.

## 7. Key design rules enforced by the architecture

1. The frontend never touches logs, files, or the OS — only the API layer.
2. The AI module receives a constructed evidence bundle; it has no execution path.
3. Every event carries `synthetic` + `sourceRef`; the UI surfaces provenance permanently.
4. Correlation output is labeled `inferred` everywhere it appears.
5. Response actions are generated as advisory text only; no write capability exists outside `Event`/`Alert`/`Incident`/`Setting` tables.
