// SENTINEL DESK 1.0 — Bootstrap: ensures event sources + rule catalog exist.
// Idempotent; called by API routes before serving data.

import { db } from '@/lib/db'
import { DETECTION_RULES } from './engine/rules'

const SOURCES = [
  {
    channel: 'Security',
    displayName: 'Security',
    description: 'Windows Security auditing channel — logons, process creation, task/service and account management events.',
    status: 'demo',
    available: true,
    requiresAdmin: false,
    note: 'Synthetic demo source in this build. On Windows, full coverage requires audit policy enabled; some subcategories need elevated read access.',
  },
  {
    channel: 'System',
    displayName: 'System',
    description: 'Service Control Manager installs, log clears, boot events.',
    status: 'demo',
    available: true,
    requiresAdmin: false,
    note: 'Synthetic demo source in this build.',
  },
  {
    channel: 'PowerShell/Operational',
    displayName: 'PowerShell/Operational',
    description: 'Script-block (4104) and module (4103) logging.',
    status: 'demo',
    available: true,
    requiresAdmin: false,
    note: 'Synthetic demo source. Requires ScriptBlockLogging to be enabled on real systems.',
  },
  {
    channel: 'TaskScheduler/Operational',
    displayName: 'TaskScheduler/Operational',
    description: 'Scheduled task registration and execution history.',
    status: 'demo',
    available: true,
    requiresAdmin: false,
    note: 'Synthetic demo source.',
  },
  {
    channel: 'Sysmon',
    displayName: 'Sysmon',
    description: 'Optional Sysmon channel — process creation with hashes, network connections.',
    status: 'unavailable',
    available: false,
    requiresAdmin: false,
    note: 'Sysmon is NOT assumed installed (§3). This source is intentionally disabled in the demo fixture set; events tagged Sysmon are synthetic examples included to exercise SD-008.',
  },
]

let bootstrapped = false

export async function ensureBootstrap(): Promise<void> {
  if (bootstrapped) return

  // Event sources
  for (const s of SOURCES) {
    await db.eventSource.upsert({
      where: { channel: s.channel },
      update: {},
      create: s,
    })
  }

  // Detection rules — upsert catalog (keeps admin `enabled` toggles)
  for (const r of DETECTION_RULES) {
    await db.detectionRule.upsert({
      where: { id: r.id },
      update: {},
      create: {
        id: r.id,
        name: r.name,
        description: r.description,
        version: r.version,
        author: r.author,
        severity: r.severity,
        category: r.category,
        mitreId: r.mitreId,
        mitreName: r.mitreName,
        enabled: true,
        logic: JSON.stringify(r.logic),
        falsePositives: r.falsePositives,
        limitations: r.limitations,
        evidenceFields: JSON.stringify(r.evidenceFields),
      },
    })
  }

  // Default settings
  const defaults = {
    language: 'en',
    collectorEnabled: false,
    collectorIntervalSec: 20,
    retentionDays: 7,
    aiMode: 'sandbox',
    aiRedaction: true,
    tiExternalConsent: false,
  }
  await db.setting.upsert({
    where: { key: 'app' },
    update: {},
    create: { key: 'app', value: JSON.stringify(defaults) },
  })

  // A few local demo indicators (labeled, harmless)
  const indicators = [
    { type: 'ip', value: '203.0.113.66', verdict: 'suspicious', source: 'local', note: 'Demo fixture: destination of multiple synthetic download-cradle events (RFC 5737 documentation range).' },
    { type: 'domain', value: 'cdn-updates.example', verdict: 'suspicious', source: 'local', note: 'Demo fixture: domain referenced by synthetic PowerShell download cradles. .example is IANA-reserved.' },
    { type: 'hash', value: 'A4C9E1B7D3F8A2C6E5B1D8F3A7C2E6B9D4F1A8C3E7B2D6F9A3C8E4B1D7F2A6C3', verdict: 'malicious', source: 'local', note: 'Demo fixture: synthetic hash for svcmon.exe in the persistence-chain scenario.' },
    { type: 'ip', value: '192.168.1.25', verdict: 'benign', source: 'local', note: 'RFC 1918 private address — internal workstation traffic.' },
  ]
  for (const i of indicators) {
    await db.indicator.upsert({ where: { value: i.value }, update: {}, create: i })
  }

  bootstrapped = true
}

export async function getSettings(): Promise<Record<string, unknown>> {
  const row = await db.setting.findUnique({ where: { key: 'app' } })
  if (!row) {
    await ensureBootstrap()
    const r2 = await db.setting.findUnique({ where: { key: 'app' } })
    return r2 ? JSON.parse(r2.value) : {}
  }
  return JSON.parse(row.value)
}

export async function saveSettings(patch: Record<string, unknown>): Promise<Record<string, unknown>> {
  const current = await getSettings()
  const next = { ...current, ...patch }
  await db.setting.upsert({
    where: { key: 'app' },
    update: { value: JSON.stringify(next) },
    create: { key: 'app', value: JSON.stringify(next) },
  })
  await db.auditLog.create({
    data: { action: 'settings.update', target: 'app', detail: JSON.stringify(patch) },
  })
  return next
}
