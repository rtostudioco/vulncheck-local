# Sentinel Desk 1.0 — Known Limitations

Read this before drawing any conclusion from this application.

## 1. This build does not read real Windows telemetry

- The collector is a **synthetic fixture source**. Every event is tagged `synthetic=true` with a `sourceRef`, and the UI carries a permanent DEMO badge.
- No claim in this build describes a real machine. Hostnames, users, IPs (RFC 5737/1918 documentation ranges) are fictional fixtures.
- The Rust/Windows EVTX collector is specified in `docs/ARCHITECTURE.md` but not included here.

## 2. Detection coverage is inherently partial

- Windows does not expose all security-relevant activity through event logs; availability depends on audit policy, permissions and installed components.
- Missing telemetry is never interpreted as "no threat". Source health and report limitations state this explicitly.
- SD-008 requires Sysmon; Sysmon is not assumed present and is never auto-installed.
- Regular expressions detect known wrapper patterns (e.g. `-enc`, `DownloadString`); obfuscated payloads are not decoded. Detection rules are explainable heuristics, not a guarantee.

## 3. Correlation produces hypotheses

- Events linked by time window + shared host are **related**, not causally connected. Every correlation surfaces an `inferred` marker and the disclaimer "proximity is not proof of causation".
- The incident engine never labels anything as a confirmed compromise. Confirmation is a human act recorded through status changes and notes.

## 4. AI analyst boundaries

- The LLM can misread evidence; its output is advisory and always labeled.
- When the provider is unavailable, a deterministic fallback summary is shown and clearly marked as non-AI.
- Local (Ollama) and remote provider modes are present for desktop parity but require a configured provider; the sandbox assistant is the only active mode in this build.

## 5. Response is advisory only

- No automated remediation exists — by design and by code. The checklist generator contains no execution primitives.
- "Recommended steps" are generic professional guidance; they cannot know your environment's change-management rules.

## 6. Threat intelligence boundaries

- External reputation lookups are consent-gated and, in this build, intentionally report "provider unavailable" — an unavailable provider never yields a verdict.
- Local heuristics (private ranges, suspicious TLDs, punycode, payload-in-URL) are weak signals only. Verdicts default to *unknown*.

## 7. Reports

- PDF export is implemented as browser print-to-PDF from the executive preview (server-side PDF generation is a desktop-port item).
- Every report states the collection limitations of this build rather than presenting demo coverage as complete.

## 8. Engineering notes

- Collector interval is client-driven (the open tab issues ticks). A desktop build would move this to a background service with bounded queues.
- Retention pruning runs per tick; very large batches rely on database indexes and pagination (verified with hundreds of events; thousands are bounded by retention).
- The pipeline stage stats are per-process in memory (last run); they are not a historical metric store.
- Localization covers the full UI; Response Center step texts are currently English-only (known gap, documented in code).

## 9. Not a substitute

Sentinel Desk is not an EDR, antivirus, enterprise SIEM or compliance product, and does not replace Microsoft Defender or any platform detection stack.
