# Installation — Sentinel Desk desktop (Windows 10/11 x64)

## A. Download from GitHub Actions (no toolchain needed)

1. Push this repository to GitHub.
2. Tag a release:
   ```
   git tag v1.0.0
   git push origin v1.0.0
   ```
   (or open **Actions → release-windows → Run workflow**.)
3. When the run finishes: **Run → Artifacts → `sentinel-desk-windows`**.
   Contents:
   - `Sentinel Desk_1.0.0_x64_en-US.msi`
   - `Sentinel Desk_1.0.0_x64-setup.exe`
4. Tag-triggered runs also create a **draft GitHub Release** with the
   installers attached — publish it when ready.

## B. Build from source (Windows 10/11)

Prerequisites:
- **Rust** (stable, `x86_64-pc-windows-msvc` target)
  - Visual Studio Build Tools with the "Desktop development with C++" workload
- **Node.js ≥ 20** (npm)
- **WebView2 Runtime** (preinstalled on Windows 11; on Windows 10 install the
  Evergreen Runtime if missing)

Build:
```powershell
cd sentinel-desk-tauri
npm install
npm run tauri dev      # run in development
npm run tauri build    # produce installers
```

Artifacts land in:
```
src-tauri\target\release\bundle\msi\*.msi
src-tauri\target\release\bundle\nsis\*.exe
```

## C. What the app can and cannot read

| Channel | Windows path | Typical access |
| --- | --- | --- |
| Security | `Security` | Requires admin or "Event Log Readers" membership |
| System | `System` | Usually readable by authenticated users |
| PowerShell (Operational) | `Microsoft-Windows-PowerShell/Operational` | Requires ScriptBlockLogging enabled |
| Task Scheduler (Operational) | `Microsoft-Windows-TaskScheduler/Operational` | Usually readable |
| Sysmon (Operational) | `Microsoft-Windows-Sysmon/Operational` | Only if Sysmon is installed (optional; never installed by Sentinel Desk) |

A channel you cannot read is reported as `permission_required` or
`unavailable` with the exact reason. **The app never elevates, never changes
audit policy, and never asks you to disable logging.**

## D. Code signing (optional)

Installers are unsigned by default (SmartScreen will warn). To sign:

1. Export your code-signing certificate (PFX) and base64-encode it.
2. Add repository secrets:
   - `WINDOWS_CERTIFICATE` = base64 PFX
   - `WINDOWS_CERTIFICATE_PASSWORD`
3. Extend the workflow env for `tauri-action`:
   ```yaml
   env:
     WINDOWS_CERTIFICATE: ${{ secrets.WINDOWS_CERTIFICATE }}
     WINDOWS_CERTIFICATE_PASSWORD: ${{ secrets.WINDOWS_CERTIFICATE_PASSWORD }}
   ```

## E. Data location & removal

- Database: `%APPDATA%\com.sentineldesk.app\sentinel.db` (WAL side files
  alongside). Delete these files to remove **all** data the app owns —
  nothing is stored anywhere else and no system state is modified.
