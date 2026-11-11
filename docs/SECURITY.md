# Sentinel Desk 1.0 — Security Model

## 1. Threat model for the application itself

Sentinel Desk handles hostile data: log contents can contain attacker-controlled strings (usernames, command lines, service names). The application's own attack surface is therefore treated seriously.

| Risk | Mitigation |
|---|---|
| Injection via event content | No dynamic SQL; all persistence via Prisma parameterized queries. Event content is never executed, eval'd, or injected into shells (no shell execution exists anywhere in the codebase). |
| XSS via event content / AI output | React escapes all text by default; AI markdown is rendered with `react-markdown` (no raw HTML injection). URLs in evidence are rendered as plain text. |
| Prompt injection from log content | The AI receives evidence as quoted data inside a system prompt that forbids treating content as instructions; output is advisory, labeled, and cannot trigger actions (no tool/execution capability exists). |
| Over-privileged collection | This build reads nothing from the host. The desktop port uses read-only EVTX handles and never requests elevation for the UI process. |
| Data exfiltration | No telemetry leaves the machine: the only outbound calls are (a) the configured AI provider, gated by mode + redaction, and (b) external TI lookups, gated by a global setting AND per-lookup consent, with a disclosure of exactly what will be sent. |
| Credential handling | No API keys are stored in this build (the sandbox provider is server-side). The desktop port stores provider keys in Windows Credential Manager (DPAPI), never in the database. |
| Tampering with local data | SQLite file owned by the user session; the app exposes audited purge/reset commands rather than hidden retention. Reports include SHA-256 integrity metadata over the canonical payload. |

## 2. Collection restrictions (product-level guarantees)

1. **Read-only.** No code path writes to the OS: no process termination, no file deletion, no registry, no service/task/firewall/policy modification, no command execution.
2. **No elevation for the UI.** The interface runs unprivileged. Sources that need elevation (parts of the Security channel on real Windows) are surfaced as `permission_required` with an explanation instead of silently elevating.
3. **No persistence changes.** The app installs no services, no drivers, no scheduled tasks, and does not disable Defender or modify audit policy.
4. **Sysmon is optional and never auto-installed.** SD-008 documents its dependency and is inert without the channel.
5. **Absence of evidence is not evidence of absence.** Disabled auditing or missing channels are reported as collection limitations in the UI and in every report.

## 3. AI gateway restrictions (§8)

Enforced in code (`src/lib/ai.ts`) and in the API route:

- Reads only the selected incident's evidence bundle (alerts + evidence events + analyst notes). No arbitrary queries.
- Redaction pass before any model call when `aiRedaction` is enabled (default): hostnames, usernames, IPs, executable filenames in paths, and base64 command payloads are replaced with placeholders.
- Every analysis is persisted with provider, model, privacy mode, prompt version (`sd-analyst-v1`), the exact redacted input summary, and the output — and emits an `ai.analyze` audit entry.
- The model is contractually constrained (system prompt) to: never declare a confirmed compromise, never invent events, only recommend safe manual steps. The UI always labels AI output and repeats the capability restrictions.
- Provider failure degrades to a clearly-marked deterministic fallback summary — never a fabricated "AI success".

## 4. Human-controlled response (§9)

The Response Center generates advisory checklists only. The application has no capability to act on the system, and the checklist generation code contains no execution primitives. Exported checklists are JSON documents with `"advisoryOnly": true`.

Future automation, if ever built, requires: a separate security review, an explicit per-action human approval flow, and audit logging — per the product specification.

## 5. Audit log

`AuditLog` records (locally, never transmitted): settings changes, rule enable/disable, incident creation/status changes, AI analyses, TI external-lookup attempts, and data purges. Visible in Settings → Local audit log.

## 6. Data minimization

- Events retain only fields required to reproduce and explain detections + the raw payload for provenance, under retention pruning.
- Sensitive values in AI inputs are redacted by default.
- The user can purge all collected data (Settings → Delete all events…) or reset the app to factory state; both are audited.

## 7. Reporting vulnerabilities

Use GitHub private security advisories. Do not open public issues for security reports, and never attach real logs, credentials, or personal data.
