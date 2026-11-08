#!/usr/bin/env bash
# ============================================================
# VulnCheck Local — GitHub publisher
# Creates the repository and pushes main + tag v1.1.0.
#
# Usage:
#   ./publish-github.sh TU_USUARIO TU_TOKEN [public|private]
#
# Token: GitHub → Settings → Developer settings →
#        Personal access tokens (classic) → scope: `repo`
# ============================================================
set -euo pipefail

USER="${1:?Usage: ./publish-github.sh TU_USUARIO TU_TOKEN [public|private]}"
TOKEN="${2:?Usage: ./publish-github.sh TU_USUARIO TU_TOKEN [public|private]}"
VIS="${3:-public}"   # public | private

REPO="vulncheck-local"
API="https://api.github.com"

echo "→ Creating ${VIS} repository ${USER}/${REPO} ..."
HTTP=$(curl -s -o /tmp/gh-create.json -w "%{http_code}" -X POST \
  -H "Authorization: token ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${API}/user/repos" \
  -d "{\"name\":\"${REPO}\",\"description\":\"🛡️ Local-first defensive security auditor for Windows & Linux — read-only checks, 0–100 score, CIS-style compliance mapping, PDF/JSON/CSV reports. No cloud, no telemetry.\",\"private\":$( [ "${VIS}" = "private" ] && echo true || echo false ),\"has_issues\":true,\"has_wiki\":false}")

if [ "${HTTP}" = "422" ]; then
  echo "  (repo already exists — continuing)"
elif [ "${HTTP}" != "201" ]; then
  echo "✗ GitHub API error ${HTTP}:"; cat /tmp/gh-create.json; exit 1
fi

git remote remove origin 2>/dev/null || true
git remote add origin "https://${USER}:${TOKEN}@github.com/${USER}/${REPO}.git"

echo "→ Pushing main ..."
git push -u origin main

echo "→ Tagging v1.1.0 ..."
git tag -a v1.1.0 -m "VulnCheck Local v1.1.0 — bilingual UI + Windows collectors" 2>/dev/null || true
git push origin v1.1.0 2>/dev/null || true

git remote set-url origin "https://github.com/${USER}/${REPO}.git"  # drop token from remote URL

echo ""
echo "✅ Done: https://github.com/${USER}/${REPO}"
echo "   Next: add Topics (security-audit, defensive-security, local-first, cis-benchmarks, nextjs, typescript, prisma, sqlite, pdf-report, cybersecurity, self-hosted, offline) and a Social Preview image."
