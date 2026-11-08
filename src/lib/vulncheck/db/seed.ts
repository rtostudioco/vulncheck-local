/**
 * Database seeding + schema versioning (spec §9).
 * Rules and remediation guides are code-defined (single source of truth) and
 * upserted into the registry tables so the DB always mirrors the engine.
 */

import { db } from '@/lib/db';
import type { RemediationGuide, SecurityRule } from '@prisma/client';
import { ALL_RULES } from '../compliance/rules';
import { ENGINE_VERSION } from '../core/types';

export const SCHEMA_VERSION = '1';

const SETTINGS_DEFAULTS: Record<string, string> = {
  ai_consent_enabled: 'false',
  retention_days: '90',
};

let seedPromise: Promise<void> | null = null;

/// Idempotent, concurrency-safe seed executed lazily by API routes.
export function ensureSeeded(): Promise<void> {
  if (!seedPromise) {
    seedPromise = doSeed().catch((err) => {
      seedPromise = null; // allow retry on next request
      throw err;
    });
  }
  return seedPromise;
}

async function doSeed(): Promise<void> {
  const meta = await db.dbMeta.findUnique({ where: { key: 'schema_version' } });
  if (meta?.value === SCHEMA_VERSION) return;

  // Upsert rule registry + remediation guides
  for (const rule of ALL_RULES) {
    await db.securityRule.upsert({
      where: { id: rule.id },
      create: {
        id: rule.id,
        version: rule.version,
        category: rule.category,
        title: rule.title,
        description: rule.description,
        severityIfFail: rule.severityIfFail,
        osTarget: rule.osTarget,
        reference: rule.reference,
        enabled: true,
      },
      update: {
        version: rule.version,
        category: rule.category,
        title: rule.title,
        description: rule.description,
        severityIfFail: rule.severityIfFail,
        osTarget: rule.osTarget,
        reference: rule.reference,
      },
    });

    await db.remediationGuide.upsert({
      where: { ruleId_osTarget: { ruleId: rule.id, osTarget: rule.osTarget } },
      create: {
        ruleId: rule.id,
        osTarget: rule.osTarget,
        problem: rule.guide.problem,
        impact: rule.guide.impact,
        solution: rule.guide.solution,
        verification: rule.guide.verification,
      },
      update: {
        problem: rule.guide.problem,
        impact: rule.guide.impact,
        solution: rule.guide.solution,
        verification: rule.guide.verification,
      },
    });
  }

  // Default application settings (do not override user choices)
  for (const [key, value] of Object.entries(SETTINGS_DEFAULTS)) {
    await db.applicationSetting.upsert({
      where: { key },
      create: { key, value },
      update: {},
    });
  }

  // Engine version marker
  await db.dbMeta.upsert({
    where: { key: 'engine_version' },
    create: { key: 'engine_version', value: ENGINE_VERSION },
    update: { value: ENGINE_VERSION },
  });

  await db.dbMeta.upsert({
    where: { key: 'schema_version' },
    create: { key: 'schema_version', value: SCHEMA_VERSION },
    update: { value: SCHEMA_VERSION },
  });
}

export async function getSetting(key: string): Promise<string | null> {
  const row = await db.applicationSetting.findUnique({ where: { key } });
  return row?.value ?? null;
}

export async function setSetting(key: string, value: string): Promise<void> {
  await db.applicationSetting.upsert({
    where: { key },
    create: { key, value },
    update: { value },
  });
}

/// Retention enforcement: delete sessions older than the configured window.
export async function pruneOldSessions(retentionDays: number): Promise<number> {
  if (!Number.isFinite(retentionDays) || retentionDays <= 0) return 0;
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  const stale = await db.auditSession.findMany({
    where: { startedAt: { lt: cutoff } },
    select: { id: true },
  });
  if (stale.length === 0) return 0;
  const result = await db.auditSession.deleteMany({
    where: { id: { in: stale.map((s) => s.id) } },
  });
  return result.count;
}

/// Expose registry rows for the settings/meta endpoints
export async function getRuleRegistry(): Promise<SecurityRule[]> {
  return db.securityRule.findMany({ orderBy: { id: 'asc' } });
}

export async function getRemediationGuides(): Promise<RemediationGuide[]> {
  return db.remediationGuide.findMany({ orderBy: { ruleId: 'asc' } });
}
