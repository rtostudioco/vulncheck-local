/**
 * Data access layer mapping Prisma rows to API DTOs (spec §9).
 */

import { db } from '@/lib/db';
import type {
  AuditSession,
  AuditFinding,
  SystemProfile,
} from '@prisma/client';
import {
  ENGINE_VERSION,
  type AuditStatus,
  type HostProfile,
  type InterfaceInfo,
  type ModuleStatus,
  type PortInfo,
  type ScoreCounts,
  type SessionDetail,
  type SessionSummary,
} from '../core/types';

interface SessionExtras {
  counts?: ScoreCounts;
  network?: { listeningPorts: PortInfo[]; interfaces: InterfaceInfo[] } | null;
  modules?: ModuleStatus[];
}

function parseJsonSafe<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function countsFromFindings(findings: Pick<AuditFinding, 'severity' | 'status'>[]): ScoreCounts {
  const counts: ScoreCounts = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
    warnings: 0, passed: 0, failed: 0, notAssessed: 0, errors: 0, notApplicable: 0,
  };
  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': counts.critical += 1; break;
      case 'HIGH': counts.high += 1; break;
      case 'MEDIUM': counts.medium += 1; break;
      case 'LOW': counts.low += 1; break;
      default: counts.info += 1; break;
    }
    switch (f.status) {
      case 'PASS': counts.passed += 1; break;
      case 'FAIL': counts.failed += 1; break;
      case 'WARNING': counts.warnings += 1; break;
      case 'NOT_APPLICABLE': counts.notApplicable += 1; break;
      case 'NOT_ASSESSED': counts.notAssessed += 1; break;
      case 'ERROR': counts.errors += 1; break;
    }
  }
  return counts;
}

function toSummary(
  s: AuditSession & { _count?: { findings: number } },
): SessionSummary {
  const extras = parseJsonSafe<SessionExtras>(s.summaryJson, {});
  return {
    id: s.id,
    startedAt: s.startedAt.toISOString(),
    completedAt: s.completedAt ? s.completedAt.toISOString() : null,
    status: s.status as AuditStatus,
    progress: s.progress,
    currentStep: s.currentStep,
    platform: s.platform,
    engineVersion: s.engineVersion,
    overallScore: s.overallScore,
    grade: s.grade,
    coverage: s.coverage,
    findingsCount: s._count?.findings ?? 0,
    counts: extras.counts ?? null,
  };
}

export async function listSessions(limit = 25): Promise<SessionSummary[]> {
  const rows = await db.auditSession.findMany({
    orderBy: { startedAt: 'desc' },
    take: limit,
    include: { _count: { select: { findings: true } } },
  });
  return rows.map(toSummary);
}

function mapProfile(p: SystemProfile): HostProfile {
  const base = parseJsonSafe<Partial<HostProfile>>(p.rawJson, {});
  return {
    hostname: p.hostname,
    platform: p.platform,
    osName: p.osName,
    osVersion: p.osVersion,
    osBuild: p.osBuild,
    kernelVersion: p.kernelVersion,
    arch: p.arch,
    cpuModel: p.cpuModel,
    cpuCores: p.cpuCores,
    totalMemoryMb: p.totalMemoryMb,
    usedMemoryMb: base.usedMemoryMb ?? null,
    uptimeHours: base.uptimeHours ?? null,
    primaryIp: p.primaryIp,
    packageCount: p.packageCount,
    packages: base.packages ?? [],
    disks: base.disks ?? [],
    interfaces: base.interfaces ?? [],
  };
}

function mapFinding(f: AuditFinding): SessionDetail['findings'][number] {
  return {
    id: f.id,
    ruleId: f.ruleId,
    ruleVersion: f.ruleVersion,
    category: f.category,
    title: f.title,
    description: f.description,
    severity: f.severity as SessionDetail['findings'][number]['severity'],
    status: f.status as SessionDetail['findings'][number]['status'],
    evidence: f.evidence,
    riskExplanation: f.riskExplanation,
    remediation: f.remediation,
    verification: f.verification,
    osTarget: f.osTarget,
    aiExplanation: null,
  };
}

export async function getSessionDetail(id: string): Promise<SessionDetail | null> {
  const s = await db.auditSession.findUnique({
    where: { id },
    include: {
      findings: true,
      profile: true,
      _count: { select: { findings: true } },
    },
  });
  if (!s) return null;

  const extras = parseJsonSafe<SessionExtras>(s.summaryJson, {});
  const findings = s.findings.map(mapFinding);
  const summary = toSummary(s);

  // While RUNNING, counts come live from findings if present
  const counts = extras.counts ?? (findings.length > 0 ? countsFromFindings(findings) : null);

  return {
    ...summary,
    counts,
    profile: s.profile ? mapProfile(s.profile) : null,
    findings,
    modules: extras.modules ?? [],
    limitations: parseJsonSafe<string[]>(s.limitations, []),
    network: extras.network ?? null,
  };
}

export async function deleteSession(id: string): Promise<void> {
  await db.auditSession.delete({ where: { id } });
}

export async function getRunningSession(): Promise<AuditSession | null> {
  return db.auditSession.findFirst({ where: { status: 'RUNNING' }, orderBy: { startedAt: 'desc' } });
}

export async function setProgress(id: string, progress: number, step: string): Promise<void> {
  await db.auditSession.update({
    where: { id },
    data: { progress: Math.min(100, Math.max(0, Math.round(progress))), currentStep: step },
  });
}

export async function markFailed(id: string, message: string): Promise<void> {
  await db.auditSession.update({
    where: { id },
    data: { status: 'FAILED', currentStep: `Failed: ${message.slice(0, 300)}`, completedAt: new Date() },
  }).catch(() => undefined);
}

/// Assessment limitations disclosure (honest reporting, spec §4/§11)
export function buildLimitations(
  platform: string,
  unavailableModules: string[],
  notAssessedCount: number,
  errorCount: number,
  coverage: number,
): string[] {
  const out: string[] = [];
  if (platform === 'windows') {
    out.push(
      'This audit ran on a Windows host using read-only PowerShell collectors. Module availability depends on PowerShell availability and session privileges — unavailable inspections are listed below.',
    );
  } else if (platform !== 'linux') {
    out.push(
      `This audit ran on a ${platform} host. This build collects live evidence on Linux and Windows; the detected platform is not supported by the collectors.`,
    );
  }
  if (unavailableModules.length > 0) {
    out.push(`Modules with unavailable evidence: ${unavailableModules.join(', ')}. Related rules are reported as NOT_ASSESSED, never as secure.`);
  }
  if (notAssessedCount > 0) {
    out.push(`${notAssessedCount} rule(s) could not be assessed because required evidence was unreadable or absent (e.g. /etc/shadow without elevated privileges).`);
  }
  if (errorCount > 0) {
    out.push(`${errorCount} rule(s) ended in ERROR state during evaluation and are excluded from the score.`);
  }
  if (coverage < 70) {
    out.push(`Assessment coverage is ${coverage}% — the posture score should be interpreted with caution until coverage improves.`);
  }
  out.push('VulnCheck Local collects evidence passively and read-only. It does not verify exploitability and is not a substitute for a full penetration test.');
  return out;
}
