# Sentinel Desk 1.0 — Windows Desktop (Tauri 2 + Rust)

**Local Intelligence. Human-Controlled Defense.**

Sentinel Desk is a **local-first SOC investigation assistant** for Windows 10/11.
It reads a limited set of Windows Event Log channels **strictly read-only**,
normalizes them, evaluates **versioned, explainable detection rules**
(SD-001…SD-010, Sigma-inspired JSON logic) and organizes matches into
**human-controlled incident investigations**.

> ⚠️ **NOT an antivirus, NOT an EDR, NOT an enterprise SIEM.** Sentinel Desk
> does not replace Microsoft Defender, Sentinel, CrowdStrike or Splunk. It
> never executes remediation, never modifies the system it observes, and never
> announces a "confirmed compromise" — every correlation is a hypothesis a
> human must verify.

---

## 📦 Where do I download the .exe / .msi?

Sentinel Desk is **built from source** or **via CI**. There is no public
download yet.

**Option A — GitHub Actions (recommended, no local toolchain needed):**
1. Push this repository to GitHub.
2. `git tag v1.0.0 && git push origin v1.0.0` (or run the workflow manually).
3. Download the artifacts:
   - `Sentinel Desk_1.0.0_x64_en-US.msi` (WiX installer)
   - `Sentinel Desk_1.0.0_x64-setup.exe` (NSIS installer)
   from the workflow run **Artifacts** (or the draft GitHub Release).

**Option B — Build on your Windows machine** — see `docs/INSTALLATION.md`.

---

## Honest implementation status (v1.0.0 desktop)

| Module | Rust backend | Desktop UI | Notes |
| --- | --- | --- | --- |
| Windows Event Log collector (read-only) | ✅ implemented | ✅ Live Monitor | Per-channel degradation reported with exact reason; never elevates |
| Normalizer (common schema) | ✅ implemented | — | Same field mapping as the verified web prototype |
| Detection engine (SD-001…SD-010) | ✅ implemented | ✅ Detections + dry-run rule tests | Single / threshold / correlation logic, evidence refs |
| Incident engine (20-min clustering, hypothesis wording) | ✅ implemented | ✅ Incident Center | Status machine validated server-side |
| Analyst notes + audit log | ✅ implemented | ✅ | Every action audited locally |
| SQLite persistence (WAL, FK, migrations) | ✅ implemented | — | App-owned data only, retention purge |
| Reports (JSON+SHA-256, CSV) | ✅ implemented | 🔜 Phase 5 (backend commands ready) | |
| Overview dashboard | — | ✅ | Real IPC data, honest empty states |
| Timeline / Threat Intel / AI Analyst / Response UI | — | 🔜 Phase 5 | Listed honestly in-app as "Planned"; no fake data |
| AI gateway (local-first provider + redaction) | 🔜 Phase 5 | 🔜 | Web prototype has the verified UX |
| Installer code signing | ❌ not configured | — | Documented in INSTALLATION.md |

Full matrix: `docs/IMPLEMENTATION-STATUS.md`.

## Security model (summary)

- **Read-only collector** — no `EvtClearLog`, no channel/subscription/audit
  policy changes, no elevation, no services installed, nothing persisted
  outside the app data directory.
- **Minimal IPC capability** — the Tauri capability file grants only core
  defaults; no shell, filesystem or process plugins.
- **No dynamic execution** — event content is data, never code. All SQL is
  parameterized. All command inputs validated and length-capped.
- **Explicit degradation** — an unreadable channel is reported as
  `permission_required` / `unavailable` with the exact reason. Missing
  telemetry is never presented as "no threats".

## Repositorio / repo layout

```
sentinel-desk-tauri/
├── rules/windows.json          # 10 detection rules (SD-001…SD-010)
├── src-tauri/                  # Rust backend (collector, engine, storage, commands)
├── src/                        # Vite React UI (Overview, Events, Detections, Incidents)
├── .github/workflows/release.yml  # Windows MSI/NSIS build on tag push
└── docs/                       # Implementation status + installation
```

## Verificación / verification honesty

The Rust backend **has not been compiled in this sandbox** (no Windows/MSVC
toolchain available here). The first `cargo check` happens on Windows or in
CI. Two Windows-API call sites carry explicit `TODO-verify` markers
(`Error::code()` HRESULT handling in `windows_event_log.rs`). Everything else
is written against the documented `windows` 0.58 API surface.

The web prototype in the parent project is the **fully verified** product
experience (browser-tested end to end), including Timeline, Threat Intel,
AI Analyst, Response and Reports.
