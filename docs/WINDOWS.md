# Windows Support (v1.1.0)

VulnCheck Local now ships **native Windows evidence collectors**. On a Windows
host the engine automatically activates them (platform detection → `windows`)
and the same 10-section dashboard, scoring and exports work end-to-end.

> **Validation status:** collectors are implemented against documented,
> read-only PowerShell cmdlets but must be smoke-tested on a real Windows
> 10/11 machine before being considered production-hardened (this repository
> was developed inside a Linux sandbox). Follow the checklist below.

---

## What is collected on Windows (all read-only)

| Module | Sources (allowlisted PowerShell IDs) |
|---|---|
| Inventory | `Get-CimInstance Win32_OperatingSystem / ComputerSystem / Processor`, `Get-Volume`, package count from `HKLM` uninstall keys |
| Firewall | `Get-NetFirewallProfile`, UAC (`EnableLUA`, `ConsentPromptBehaviorAdmin`), RDP (`fDenyTSConnections`, NLA), SMBv1 state |
| Accounts | `Get-LocalUser`, `net accounts` password policy, local Administrators members |
| Network | `Get-NetAdapter`/`Get-NetIPAddress`, listening TCP/UDP (`Get-NetTCPConnection -State Listen`, `Get-NetUDPEndpoint`), established connections |
| Updates | COM `Microsoft.Update.Session` search (read-only), pending-reboot registry keys |
| Endpoint | `Get-MpComputerStatus`, `Get-MpPreference` exclusions, `Get-BitLockerVolume` |
| Services | `Get-CimInstance Win32_Service` (auto-start + stopped, run-as accounts) |
| Backup | `wbadmin get versions`, SystemRestore WMI |

Every command is a **static, registered script** in
`src/lib/vulncheck/core/runner.ts` (`PS_REGISTRY`). No shell is spawned
(`execFile` with `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy
Bypass -Command <registered script>`), every call is time-limited and
output-size-limited, and a minimal sanitized environment is forwarded.
Failures degrade to `UNAVAILABLE`/`PARTIAL` with notes — never to "secure".

## Requirements

- Windows 10 21H2+ or Windows 11 (PowerShell 5.1+ built in — no PS7 needed)
- Node.js 20+ or Bun 1.1+
- **Not** required: admin rights (but run from an **elevated terminal** for
  the fullest evidence — some checks like `net accounts`, `wbadmin` and
  certain registry reads return more data elevated)

## Run on Windows

Requires **Node.js 20+** (LTS recommended — nodejs.org) and Git (git-scm.com).
All npm scripts are cross-platform (they also work in plain cmd.exe).

```powershell
git clone https://github.com/rtostudioco/vulncheck-local.git
cd vulncheck-local
npm install
copy .env.example .env        # cmd  (PowerShell: Copy-Item .env.example .env)
npx prisma db push            # creates db/custom.db (SQLite, local)
npm run dev                   # → http://localhost:3000
```

Click **Run New Audit**. The header badge should show `windows`.

> **Tip:** run the terminal **as administrator** for the fullest evidence —
> some checks (`net accounts`, `wbadmin`, certain registry reads) return more
> data elevated. Admin rights are not mandatory; anything blocked simply
> reports as NOT_ASSESSED / PARTIAL instead of pretending to be secure.
>
> **AI explanations (optional):** the switch is off by default; if the AI SDK
> is not configured on the host, the Explain action degrades gracefully with
> an error toast — no other feature is affected.

## Single-executable packaging (optional)

**Option A — production server (recommended):**

```powershell
npm run build   # next build + copies static assets (cross-platform)
npm start       # node .next/standalone/server.js
```

**Option B — one self-contained binary with Bun:**

```powershell
bun install
npm run build
bun build --compile .next/standalone/server.js --outfile VulnCheckLocal.exe
# ship VulnCheckLocal.exe + .next/static + public + prisma + .env
```

> Node SEA (`node --experimental-sea-config`) is also viable; Bun's
> `--compile` is the least-friction path today.

## Manual validation checklist (real Windows host)

- [ ] Header/platform badge shows **windows** (not `NOT_ASSESSED` everywhere)
- [ ] Inventory: hostname, OS caption/build, CPU, RAM, volumes populated
- [ ] Firewall: 3 profiles (Domain/Private/Public) with real Enabled states
- [ ] UAC/RDP/SMBv1 values match `Get-MpPreference`-style registry reality
- [ ] Accounts: local users listed; password policy from `net accounts`
- [ ] Network: listening ports match `netstat -ano | findstr LISTENING`
- [ ] Defender: `Get-MpComputerStatus` toggles reflect in Endpoint module
- [ ] Updates: pending list loads (or honest PARTIAL note if COM blocked)
- [ ] Services: auto-start/stopped list matches `services.msc`
- [ ] Run a **second** audit with a non-elevated terminal and confirm missing
      evidence is reported as NOT_ASSESSED/PARTIAL — never as PASS

## Honest limitations

- WMI/COM calls can be blocked by endpoint-hardening policies → module goes
  `PARTIAL`/`UNAVAILABLE` with an explanatory note (by design).
- `PS_UPDATES_PENDING` performs a **read-only online search** via Microsoft
  Update COM; on air-gapped hosts it degrades gracefully.
- Windows rules that cannot find their evidence stay `NOT_ASSESSED` and
  reduce coverage — they never fake a PASS.
