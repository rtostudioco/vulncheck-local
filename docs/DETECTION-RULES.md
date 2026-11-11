# Sentinel Desk 1.0 — Detection Rules

## Rule format

Rules are defined in `src/lib/engine/rules.ts` as versioned objects with a portable Sigma-inspired JSON `logic` block. The same JSON is stored in the database and rendered in the Detections view.

```typescript
interface DetectionRuleDef {
  id: string                  // "SD-001"
  name: string
  description: string
  version: string             // semver of the rule logic
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string            // credential_access | execution | persistence | ...
  mitreId?: string            // only when justified
  confidence: number          // base confidence 0..100
  logic: {
    kind: 'single' | 'threshold' | 'correlation'
    channel?: string; channels?: string[]
    eventIds?: number[]
    conditions?: { field: string; op: string; value: unknown }[]
    threshold?: { count: number; windowSec: number; groupBy: string[] }
    signals?: { ruleId: string; minCount?: number }[]
    correlationWindowSec?: number
    linkBy?: string[]
  }
  evidenceFields: string[]
  falsePositives: string
  limitations: string
}
```

Condition operators: `eq`, `in`, `neq`, `contains`, `startsWith`, `regex` (Sigma-style `(?i)` inline flags supported), `gt`, `lt`. All conditions are AND-combined.

## Catalog (v1.0.0)

| ID | Severity | Fires when | MITRE | Key false positives |
|----|----------|------------|-------|---------------------|
| SD-001 | high | ≥5 × 4625 failed logons per computer in 5 min | T1110 | expired passwords, stale service creds |
| SD-002 | high | 4624 (logon type 3/10) on a host within 10 min of an SD-001 burst | T1078 | user typo then success; VPN reconnect |
| SD-003 | high | 4104 script block or 4688 command line matches obfuscation/download-cradle regex (`-enc`, `FromBase64String`, `IEX`, `DownloadString`, `-nop -w hidden`, …) | T1059.001 | legit admin automation, CI agents |
| SD-004 | medium | 4698 / 4702 (Security) or 106 (TaskScheduler) | T1053.005 | GPO tasks, software updaters |
| SD-005 | medium | 7045 service install (System) | T1543.003 | legit installs |
| SD-006 | medium | 4719 audit policy change, 1102 log clear, 4720/4738 account mgmt | T1562 | planned hardening, offboarding |
| SD-007 | high | 4688 / Sysmon 1 with image path under Temp/Downloads/AppData\Roaming/Users\Public/Windows\Temp/ProgramData | T1036.005 | user-installed portable tools |
| SD-008 | medium | Sysmon 3 connection from powershell/cmd/certutil/rundll32/mshta/wscript/cscript to a non-private IP | T1071 | admin scripts fetching updates |
| SD-009 | high | **Correlation:** SD-003 + SD-004 same host, 15 min | T1053.005 | deployment tooling doing both |
| SD-010 | critical | **Correlation:** ≥3 distinct rules same host, 20 min | T1059 | mass maintenance activity |

**Event-ID mappings** are limited to channels the synthetic source models and are documented against Microsoft's Security Auditing and Sysmon references. On real Windows, availability depends on audit policy — each rule's `limitations` field says exactly what must be enabled for it to fire, and the UI renders it.

## Testing methodology

Each rule has a mapped synthetic fixture scenario (`SCENARIO_FOR_RULE` in `src/lib/engine/pipeline.ts`) that generates a harmless event burst deterministically (seed 42). `POST /api/rules/:id/test` runs the **real** evaluator over the fixture and returns:

```json
{
  "matched": true,
  "matchCount": 2,
  "fixtureEvents": 18,
  "explanation": "8 matching event(s) ≥ threshold 5 in 300s grouped by computer",
  "evidenceSample": [ ... ]
}
```

A rule that fails its fixture is a product defect, not a UI state — the test-no-match result is displayed as such in the Detections view. All ten rules pass in this build.

Correlation rules (SD-009, SD-010) are tested by first evaluating their signal rules over the same fixture, then the correlation stage — mirroring the production pipeline order.

## Extending

1. Add a `DetectionRuleDef` to `DETECTION_RULES` (it is upserted into the DB on next bootstrap).
2. Add a fixture scenario to `SCENARIOS` in `generator.ts` (harmless, labeled) and map it in `SCENARIO_FOR_RULE`.
3. Run its test; document false positives, limitations, and evidence fields — a rule without limitation notes is incomplete.
