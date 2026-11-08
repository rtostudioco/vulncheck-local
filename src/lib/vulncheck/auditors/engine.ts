/**
 * Audit orchestration engine (spec §10 — auditors/).
 * Runs: collectors → compliance rules → scoring → persistence.
 * Progress is persisted on the session row so the UI can poll it.
 * The audit is strictly read-only; nothing on the host is modified.
 */

import { db } from '@/lib/db';
import { collectEvidence } from '../collectors';
import { evaluateRules, toFindings } from '../compliance/engine';
import { buildLimitations, markFailed, setProgress } from '../db/repo';
import { ensureSeeded, pruneOldSessions } from '../db/seed';
import { ENGINE_VERSION, type EvidenceBundle, type ScoreResult } from '../core/types';
import { getRunningSession } from '../db/repo';
import { computeScore } from '../scoring/score';
import { createLogger } from '../core/platform';

const log = createLogger('engine');

export class AuditConflictError extends Error {
  constructor() {
    super('An audit session is already running');
    this.name = 'AuditConflictError';
  }
}

/// Start a new audit session. Returns its id. Guarded against concurrency.
export async function startAuditRun(): Promise<string> {
  await ensureSeeded();

  const running = await getRunningSession();
  if (running) {
    // Reap sessions stuck RUNNING for more than 10 minutes, else conflict.
    const stale = Date.now() - running.startedAt.getTime() > 10 * 60 * 1000;
    if (!stale) throw new AuditConflictError();
    await markFailed(running.id, 'Audit timed out and was reaped');
  }

  const session = await db.auditSession.create({
    data: {
      status: 'RUNNING',
      progress: 0,
      currentStep: 'Starting audit',
      platform: 'unknown',
      engineVersion: ENGINE_VERSION,
    },
  });

  // Fire-and-forget execution; all errors are captured on the session row.
  executeAudit(session.id).catch(async (err) => {
    log.error('audit failed:', err);
    await markFailed(session.id, err instanceof Error ? err.message : String(err));
  });

  return session.id;
}

async function executeAudit(sessionId: string): Promise<void> {
  // --- MODULES A–H: evidence collection -----------------------------------
  let bundle: EvidenceBundle;
  try {
    bundle = await collectEvidence(async (step, pct) => {
      await setProgress(sessionId, pct, step).catch(() => undefined);
    });
  } catch (err) {
    throw new Error(`Evidence collection failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  await db.auditSession.update({
    where: { id: sessionId },
    data: { platform: bundle.platform },
  });

  // --- MODULE I: compliance evaluation -------------------------------------
  await setProgress(sessionId, 80, 'Evaluating compliance rules');
  const evaluated = evaluateRules(bundle);

  // --- MODULE J: risk scoring ----------------------------------------------
  await setProgress(sessionId, 86, 'Computing risk score');
  const score: ScoreResult = computeScore(
    evaluated.map((r) => ({ ruleId: r.rule.id, severity: r.severity, status: r.status })),
  );

  // --- Persistence ----------------------------------------------------------
  await setProgress(sessionId, 92, 'Persisting results');

  const inv = bundle.inventory;
  const profile = await db.systemProfile.create({
    data: {
      hostname: inv.hostname,
      platform: inv.platform,
      osName: inv.osName,
      osVersion: inv.osVersion,
      osBuild: inv.osBuild,
      kernelVersion: inv.kernelVersion,
      arch: inv.arch,
      cpuModel: inv.cpuModel,
      cpuCores: inv.cpuCores,
      totalMemoryMb: inv.totalMemoryMb,
      primaryIp: inv.primaryIp,
      packageCount: inv.packageCount,
      rawJson: JSON.stringify(inv),
    },
  });

  const findingRows = toFindings(evaluated).map((f) => ({
    sessionId,
    ruleId: f.ruleId,
    ruleVersion: f.ruleVersion,
    category: f.category,
    title: f.title,
    description: f.description,
    severity: f.severity,
    status: f.status,
    evidence: f.evidence,
    riskExplanation: f.riskExplanation,
    remediation: f.remediation,
    verification: f.verification,
    osTarget: f.osTarget,
  }));
  if (findingRows.length > 0) {
    await db.auditFinding.createMany({ data: findingRows });
  }

  const unavailableModules = bundle.modules
    .filter((m) => m.state === 'UNAVAILABLE' || m.state === 'ERROR')
    .map((m) => m.name);
  const limitations = buildLimitations(
    bundle.platform,
    unavailableModules,
    score.counts.notAssessed,
    score.counts.errors,
    score.coverage,
  );

  // summaryJson carries reusable aggregates (counts, network snapshot, module health)
  const summaryJson = JSON.stringify({
    counts: score.counts,
    network: {
      listeningPorts: bundle.network.listeningPorts,
      interfaces: bundle.network.available ? bundle.inventory.interfaces : [],
    },
    modules: bundle.modules,
  });

  await db.auditSession.update({
    where: { id: sessionId },
    data: {
      status: 'COMPLETED',
      completedAt: new Date(),
      progress: 100,
      currentStep: 'Completed',
      overallScore: score.score,
      grade: score.grade,
      coverage: score.coverage,
      summaryJson,
      limitations: JSON.stringify(limitations),
      profileId: profile.id,
    },
  });

  // Retention housekeeping (best-effort)
  try {
    const days = Number(await import('../db/seed').then((m) => m.getSetting('retention_days')));
    if (Number.isFinite(days) && days > 0) {
      const pruned = await pruneOldSessions(days);
      if (pruned > 0) log.info(`retention: pruned ${pruned} old session(s)`);
    }
  } catch {
    // non-fatal
  }

  log.info(`audit ${sessionId} completed: score ${score.score} (${score.grade}), coverage ${score.coverage}%`);
}
