# Publishing VulnCheck Local to GitHub

This file contains ready-to-paste metadata for creating the GitHub repository.

---

## 1. Repository settings

| Field | Value |
|---|---|
| **Repository name** | `vulncheck-local` |
| **Visibility** | Public (or private — your choice) |
| **Default branch** | `main` |

## 2. Description (paste into the "About" field)

```
🛡️ Local-first defensive security auditor for Windows & Linux — read-only checks, 0–100 score, CIS-style compliance mapping, PDF/JSON/CSV reports. No cloud, no telemetry, 100% on your machine.
```

## 3. Topics / Tags (paste one by one)

```
security-audit   vulnerability-scanner   defensive-security   local-first
cis-benchmarks   security-hardening      nextjs               typescript
prisma           sqlite                  pdf-report           compliance
devsecops        cybersecurity           security-tools       windows
linux            self-hosted             privacy              offline
```

## 4. Release info

| Field | Value |
|---|---|
| **Tag** | `v1.1.0` |
| **Title** | VulnCheck Local v1.1.0 — Bilingual UI + Windows collectors |
| **Notes** | 🆕 EN/ES language switcher (persisted, full dashboard coverage) · 🆕 native read-only PowerShell collectors for Windows (24 allowlisted commands: firewall profiles, UAC/RDP/SMBv1, local users, Defender, BitLocker, updates, services, backup) · creator credits (Ramon Taboada Olivella / RTO Studio) · docs/WINDOWS.md with deployment + packaging guide. v1.0.0: 27 versioned rules · 8 Linux collectors · 10-section dashboard · PDF/JSON/CSV exports · optional consent-gated AI. |

---

## 5. Exact commands to publish

### Option A — Ready-to-push ZIP (recommended, repo already prepared)

Use `vulncheck-local-v1.1.0-github.zip`. It already contains a `.git` folder with
a clean single commit authored by you and the annotated tag `v1.1.0`.

```bash
# 1. Extract the ZIP and enter the folder
cd vulncheck-local

# 2. (Optional) link commits to your GitHub account:
git config user.name  "Ramon Taboada Olivella"
git config user.email "YOUR_REAL_EMAIL_OR_USERNAME@users.noreply.github.com"
git commit --amend --reset-author --no-edit
git tag -f -a v1.1.0 -m "VulnCheck Local v1.1.0 — Bilingual UI + Windows collectors"

# 3. Create the EMPTY repo on github.com (no README/license/gitignore),
#    then connect and push:
git remote add origin https://github.com/<TU_USUARIO>/vulncheck-local.git
git push -u origin main
git push origin v1.1.0
```

### Option B — Automated script (uses a GitHub token)

The repository includes `publish-github.sh`, which creates the repo via the
GitHub API and pushes `main` + the tag in one shot:

```bash
chmod +x publish-github.sh
./publish-github.sh TU_USUARIO TU_TOKEN public   # or private
```

> Token: GitHub → Settings → Developer settings → Personal access tokens
> (classic) → scope `repo`. Revoke the token right after publishing.

### Option C — From scratch (plain ZIP without .git)

```bash
cd vulncheck-local

git init -b main
git add .
git commit -m "feat: VulnCheck Local v1.1.0 — bilingual UI, Windows collectors, credits"

# Create the repo on github.com first (empty, without README/license),
# then connect and push:
git remote add origin https://github.com/<TU_USUARIO>/vulncheck-local.git
git push -u origin main

# Tag the release
git tag -a v1.1.0 -m "VulnCheck Local v1.1.0"
git push origin v1.1.0
```

> Tip: also enable **GitHub Topics** in the repo sidebar ⚙️ and add the topics
> from section 3 so the project is discoverable.

---

## 6. Suggested GitHub Social Preview

1280×640 px image with: shield logo 🛡️, the text
"VulnCheck Local — Local-first security auditing", and the score-ring motif
(green ring, dark graphite background #0f1412).
