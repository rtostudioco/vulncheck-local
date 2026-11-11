# Implementation status — Sentinel Desk desktop 1.0.0

Honest per-module matrix. "Web prototype" = the verified Next.js build in the
parent project (browser-tested end to end). "Desktop" = this Tauri 2 project.

| Spec module | Web prototype | Desktop backend (Rust) | Desktop UI (React) | Notes |
| --- | --- | --- | --- | --- |
| 01 Overview dashboard | ✅ verified in browser | ✅ `overview_stats` command | ✅ OverviewPage | Real IPC; empty states honest |
| 02 Collector + Live Monitor | ✅ (labeled synthetic demo source) | ✅ read-only windows-rs EVTX collector + health probing | ✅ EventsPage | Per-channel degradation with exact reason; never elevates |
| 03 Detection engine + rules | ✅ 10/10 rule fixture tests passing | ✅ same 10 rules embedded (`rules/windows.json`), same logic semantics | ✅ DetectionsPage + dry-run tests | Evidence refs + explainability strings ported |
| 04 Correlation engine | ✅ verified | ✅ ported (window/linkBy semantics identical) | (visible via incidents) | SD-002, SD-009, SD-010 |
| 05 Incident Center | ✅ verified | ✅ clustering + status machine + notes + audit | ✅ IncidentsPage | Hypothesis wording identical ("NOT a confirmed compromise") |
| 06 Timeline + relationship graph | ✅ verified | 🔜 planned | 🔜 planned | Data model already supports it |
| 07 Threat Intel | ✅ verified (consent-gated) | 🔜 planned | 🔜 planned | Indicators table exists in migrations |
| 08 AI Analyst (local-first) | ✅ verified (sandbox provider + redaction) | 🔜 planned | 🔜 planned | `ai_analyses` table exists; five-layer discipline enforced in web UX |
| 09 Response Center (advisory) | ✅ verified | 🔜 planned | 🔜 planned | Never executes anything, by design |
| 10 SOC Reports | ✅ JSON+SHA-256, CSVs, print-to-PDF | ✅ `report_json` / `report_csv` commands | 🔜 planned | UI pending; backend ready |
| Settings + audit | ✅ verified | ✅ settings/audit commands | 🔜 planned (in-app honest link) | |
| Installer (MSI/NSIS) | — | ✅ CI workflow (windows-latest) | — | Signing not configured (documented) |
| i18n EN/ES | ✅ full | — | ✅ core views (i18n.ts) | No hardcoded visible text in desktop UI |

## Known TODO-verify markers (Windows API)

- `src-tauri/src/collectors/windows_event_log.rs`
  - `classify()` — `windows::core::Error::code()` HRESULT extraction
  - `is_no_more_items()` — ERROR_NO_MORE_ITEMS detection
  Both are isolated in two small functions and fail safe (classified as
  `Other`, i.e. the channel reports `unavailable` with the raw error text).
  They are the ONLY places not verifiable without a Windows toolchain.
