<div align="center">
  <img src="public/social-preview.png" alt="Sentinel Desk — Personal SOC & Threat Detection Platform. Local Intelligence. Human-Controlled Defense." width="780">
</div>

# 🛡️ Sentinel Desk

<div align="center">

**Personal SOC & Threat Detection Platform — Local Intelligence. Human-Controlled Defense.**

*Developed by **Ramón Taboada Olivella — RTO Studio*** · [github.com/rtostudioco](https://github.com/rtostudioco)

**🇬🇧 English** · [🇪🇸 Español](README.es.md)

![version](https://img.shields.io/badge/version-1.0.0-10b981?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-10b981?style=flat-square)
![platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-10b981?style=flat-square)
![privacy](https://img.shields.io/badge/privacy-100%25%20local%20%C2%B7%20no%20cloud%20%C2%B7%20no%20telemetry-10b981?style=flat-square)
![i18n](https://img.shields.io/badge/UI-English%20%7C%20Espa%C3%B1ol-10b981?style=flat-square)

</div>

Sentinel Desk is a local-first security operations investigation assistant. It collects Windows security events, normalizes them into a common schema, evaluates them against **10 versioned, explainable detection rules** (`SD-001 … SD-010`), correlates related activity inside time windows, groups it into investigation incidents, and explains findings through an optional AI analyst — while keeping **a human in control of every conclusion and every action**.

> **Disclaimer:** Sentinel Desk is a *personal SOC investigation and learning tool*. It is **not** an EDR, not an antivirus, and not a replacement for Microsoft Defender or an enterprise SIEM. It never changes your system: v1.0 is read-only + advisory. In this repository build, the event source is a **clearly labeled synthetic demo source** (`synthetic=true` on every event, permanent DEMO badge in the UI) — nothing reads a real system, and no event is ever presented as real telemetry. A Tauri 2 + Rust port that replaces the synthetic source with a real EVTX collector ships in [`desktop/`](desktop/) and builds Windows installers via GitHub Actions.

---

## ✨ Features

- **Complete detection pipeline** — collector → normalizer → detection engine → correlation → incident engine → SQLite → UI. Every pipeline run reports per-stage status, input/output counts, errors and duration; events never disappear silently.
- **10 versioned detection rules** (`SD-001`…`SD-010`) with MITRE ATT&CK mapping, evidence fields, false-positive notes and limitations — each one testable against a harmless synthetic fixture from the UI.
- **Correlation with honesty labels** — time-window + host/user/process linking; every relationship is explicitly labeled `inferred`, and proximity never claims causality.
- **Incident Storytelling (the defining feature)** — five strictly separated layers: *Observed facts* · *Detection rule matches* · *Correlation hypotheses* · *AI-generated interpretations* · *Human-confirmed conclusions*. The product never auto-confirms compromise.
- **Incident state machine** — New → Investigating → Monitoring → Resolved / False Positive, with analyst notes and full audit trail.
- **Interactive investigation timeline** — chronological reconstruction + relationship graph (SVG) with an accessible list alternative.
- **Threat intelligence** — indicator format validation (hash / IP / domain / URL), local heuristics, per-indicator event traceability; external lookup is consent-gated and disabled by design in this build.
- **Optional AI Security Analyst** — LLM-powered incident explanation with mandatory redaction, full audit record (provider / model / prompt version), deterministic fallback when the provider is down.
- **Response Center (advisory only)** — checklists that explain what an analyst *could* do. **No automated remediation exists.**
- **SOC reports** — JSON report with SHA-256 integrity metadata, CSV exports (events / alerts), print-to-PDF executive preview.
- **Bilingual UI (English / Español)** — one-click language switcher, persisted locally.
- **Desktop port included** — [`desktop/`](desktop/) contains the Tauri 2 + Rust backend (real EVTX collectors, same 10 rules, same correlation semantics) with a GitHub Actions workflow that builds `.msi` / `.exe` installers.

---

## 📸 Screenshots

| Security Overview — pipeline KPIs, severity posture, source health | Incident Center — correlation hypotheses, five-layer storytelling |
|---|---|
| ![Security Overview dashboard with event volume, alert severity and collector health](public/screenshot-overview.png) | ![Incident detail with correlation hypothesis, related alerts and analyst notes](public/screenshot-incident.png) |

![Threat Detection Engine — all 10 versioned rules (SD-001…SD-010) with enable/disable and per-rule fixture test runner](public/screenshot-detections.png)

---

## 🧱 Tech stack

| Layer | Technology |
|---|---|
| Runtime | Node.js ≥ 20 / Bun ≥ 1.1 |
| Framework | Next.js 16 (App Router) + TypeScript 5 (strict) |
| UI | Tailwind CSS 4, shadcn/ui (New York), lucide-react |
| State | Typed fetch helpers + server components; local persistence for UI settings |
| Database | SQLite via Prisma ORM (10 entities, versioned schema) |
| Design system | "SOC Editorial" — deep graphite surfaces, restrained emerald/cyan accents, semantic severity palette, monospace IDs |
| Desktop port | Tauri 2 + Rust (windows-rs EVTX collector, rusqlite, Tokio pipeline) |
| AI (optional) | LLM provider behind a consent-gated, redacting server-side adapter |

---

## 📂 Project structure

```
src/
├── app/
│   ├── page.tsx                  # Single-page SOC console (10 modules)
│   └── api/
│       ├── collector/            # POST — run a collect batch · GET — collector status
│       ├── events/               # GET — paginated event query + [id] detail (raw payload)
│       ├── rules/                # GET — rule catalog · POST — rule fixture dry-run test
│       ├── incidents/            # GET — list / [id] detail · PATCH — status · notes
│       ├── overview/             # GET — dashboard KPIs, trends, source health
│       ├── reports/              # GET — JSON report (SHA-256) + CSV exports
│       ├── ai/analyze            # POST — consent-gated, redacting incident analysis
│       ├── ti/                   # POST — indicator lookup + analyze (local heuristics)
│       └── settings/             # GET/PUT — application settings
├── components/
│   ├── layout/                   # header (collector status, notifications, i18n, help)
│   ├── views/                    # the 10 module views
│   └── ui/                       # shadcn/ui primitives
└── lib/
    ├── engine/                   # pipeline.ts · normalizer.ts · detection.ts · rules.ts · generator.ts
    ├── ai.ts                     # consent-gated AI adapter (redaction + audit record)
    ├── bootstrap.ts              # first-run seeding (rules + settings)
    ├── db.ts                     # Prisma client
    └── i18n.ts                   # EN / ES strings
desktop/                          # Tauri 2 + Rust port — real EVTX collectors, MSI/NSIS CI
prisma/                           # schema.prisma (SQLite, 10 entities)
docs/                             # architecture, security, rules, installation, limitations
```

---

## 🚀 Getting started

### Prerequisites
- **Node.js 20+** (or Bun 1.1+) — no database server needed, SQLite is embedded.
- The synthetic demo collector is built in: **no admin rights, no real system access, no Windows required** (runs on any OS).

### Install & run

```bash
# 1. Install dependencies
bun install            # or: npm install

# 2. Create/refresh the SQLite schema (db/sentinel.db)
bun run db:push        # or: npx prisma db push

# 3. Start the app
bun run dev            # or: npm run dev  →  http://localhost:3000
```

Then open **Live Monitor → Collect now** (or enable automatic batches in **Settings → Collector**). Events flow through the pipeline, alerts appear on **Detections**, correlated cases appear on **Incidents**. Every screen carries the permanent **DEMO data** badge.

### Test a detection rule

Every rule ships with a harmless synthetic fixture and can be dry-run from the UI (**Detections → Run test**) or with one HTTP call:

```bash
curl -X POST localhost:3000/api/rules/SD-001/test
```

---

## 🔒 Security model

Sentinel Desk is built to be **safe to run**:

- ✅ **Read-only by design**: no code path kills processes, deletes files, modifies the registry, alters services/tasks/firewall rules, or disables your antivirus.
- ✅ **No privilege elevation**: never asks for admin rights; degraded sources are reported honestly as unavailable.
- ✅ **Explicit provenance**: every event carries its source, channel, record ID and `synthetic` flag; every alert lists its evidence events; every incident lists its alerts.
- ✅ **Inference is labeled**: correlation relationships are marked `inferred` — proximity is never presented as causality.
- ✅ **No silent failures**: pipeline stages report errors; retention deletes with visibility, never in silence.
- ✅ **No telemetry**: all data stays in your local SQLite file. No cloud account, no phone-home.
- ✅ **AI cannot act**: the AI layer cannot create evidence, modify rules, execute anything, or declare a confirmed compromise — enforced in the product copy, the prompt contract, and the absence of any execution capability.

### Optional AI module
- Reads **only** the evidence of the incident you select — nothing else.
- Sensitive values (hostnames, usernames, IPs, base64 blobs) are **redacted before any model call** when privacy mode is on (on by default).
- Every analysis is stored with provider, model, privacy mode, prompt version, the exact redacted input and the output.
- The application is **fully functional without it**.

---

## 📊 The ten detection rules

| Rule | Name | MITRE ATT&CK | Type | Fixture test |
|------|------|--------------|------|--------------|
| SD-001 | Multiple failed logon events | T1110 Brute Force | Threshold | ✅ passing |
| SD-002 | Successful logon after failed-logon burst | T1078 Valid Accounts | Correlation | ✅ passing |
| SD-003 | Suspicious PowerShell command-line patterns | T1059.001 | Single event | ✅ passing |
| SD-004 | Scheduled task creation or modification | T1053.005 | Single event | ✅ passing |
| SD-005 | New service creation | T1543.003 | Single event | ✅ passing |
| SD-006 | Security configuration changes | T1562 Impair Defenses | Single event | ✅ passing |
| SD-007 | Process execution from unusual location | T1036.005 | Single event | ✅ passing |
| SD-008 | Suspicious process-associated network activity | T1071 (needs Sysmon) | Single event | ✅ passing |
| SD-009 | Potential persistence sequence | T1053.005 | Correlation | ✅ passing |
| SD-010 | Multi-signal suspicious activity | T1059 | Correlation | ✅ passing |

Rules live in [`src/lib/engine/rules.ts`](src/lib/engine/rules.ts) in a portable, Sigma-inspired JSON format (thresholds, conditions, correlation signals) designed to move to the Rust engine unchanged — and they already have, in [`desktop/`](desktop/). Each rule carries evidence fields, false-positive notes and limitations, rendered in the Detections view. See [`docs/DETECTION-RULES.md`](docs/DETECTION-RULES.md).

---

## 🖥️ The ten modules

1. **Security Overview** — live KPIs, 24h trend, severity distribution, collector health, source status, last pipeline run.
2. **Live Monitor** — event table with filters + pagination, detail panel with provenance and raw payload, collector control.
3. **Threat Detection Engine** — 10 versioned rules, enable/disable, per-rule fixture test runner, rule metadata (logic, false positives, limitations).
4. **Event Correlation** — time-window + host/user/process linking with explicit inferred-vs-observed labels.
5. **Incident Center** — cases with status workflow, evidence lists, analyst notes, correlation hypotheses.
6. **Incident Timeline** — chronological reconstruction + SVG relationship graph + accessible list alternative.
7. **Threat Intelligence** — indicator validation, local heuristics, event traceability, consent-gated external lookup.
8. **AI Security Analyst** — incident explanation with mandatory redaction and full audit record, five-layer discipline.
9. **Response Center** — advisory checklists only. No automated remediation exists.
10. **SOC Reports** — JSON report with SHA-256 integrity, CSV exports, print-to-PDF executive preview.

---

## 🗄️ Data model (SQLite / Prisma)

`Event` · `EventSource` · `DetectionRule` · `Alert` · `Incident` · `IncidentEvent` · `IncidentNote` · `AiAnalysis` · `Setting` · `AuditLog` — UUID stable IDs, UTC timestamps, evidence reference tables, indexed queries, retention policy. See `prisma/schema.prisma`.

---

## 🧪 Quality

```bash
bun run lint          # ESLint (Next.js rules)
bunx tsc --noEmit     # strict type check
curl -X POST localhost:3000/api/rules/SD-001/test   # rule fixture tests, one call per rule
```

---

## 📦 Packaging / distribution (Windows installers)

This repository includes a **Tauri 2 desktop port** ([`desktop/`](desktop/)) whose CI builds real Windows installers from your own GitHub account:

1. Push this repository to GitHub (guide below).
2. Push a tag: `git tag v1.0.0 && git push origin v1.0.0` — or run the workflow manually from the **Actions** tab.
3. Open the workflow run → **Artifacts** → download `sentinel-desk-windows` (`Sentinel Desk_1.0.0_x64_en-US.msi` / `_x64-setup.exe`).

> **Honesty note:** the CI-built installers are compiled on GitHub's `windows-latest` runners. The Rust code was written to be correct, but it has not been executed on a physical Windows machine from this development environment — expect to file issues on first run. The web prototype, by contrast, is fully browser-verified.

For manual desktop builds and requirements, see [`docs/INSTALLATION.md`](docs/INSTALLATION.md) and [`desktop/docs/IMPLEMENTATION-STATUS.md`](desktop/docs/IMPLEMENTATION-STATUS.md) (honest per-module matrix).

---

## 📚 Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module map, data flow, database schema, Tauri/Rust porting path
- [`docs/SECURITY.md`](docs/SECURITY.md) — security model: least privilege, read-only collection, redaction, consent gates, audit log
- [`docs/INSTALLATION.md`](docs/INSTALLATION.md) — setup, configuration, data management
- [`docs/DETECTION-RULES.md`](docs/DETECTION-RULES.md) — rule format, catalog, test methodology
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — known limitations and honest boundaries (read before trusting anything)
- [`README.es.md`](README.es.md) — README completo en español (este archivo de docs redirige allí)

## 🚫 What Sentinel Desk is NOT

- Not an EDR, antivirus, or replacement for Microsoft Defender.
- Not an enterprise SIEM (no Splunk/Sentinel/QRadar equivalence is claimed).
- Not a compliance-certified product.
- **Not capable of changing your system** — v1.0 is read-only + advisory.
- In this repository build: not connected to real Windows telemetry (synthetic source, permanently labeled).

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🐛 Responsible disclosure

Found a security issue in Sentinel Desk? Please open a **private security advisory** via GitHub (Security → Report a vulnerability) rather than a public issue. Do not include real logs, credentials, or personal data in any issue.
