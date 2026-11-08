/**
 * MODULE J — Risk scoring engine.
 * Documented, reproducible rules (METHODOLOGY_TEXT in core/types.ts):
 *  - Start at 100; deduct per FAIL: CRITICAL −25, HIGH −15, MEDIUM −7, LOW −3, INFO −0.
 *  - WARNING deducts half of its severity weight.
 *  - Score floors at 0. Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.
 *  - NOT_ASSESSED / ERROR never deduct — they reduce coverage instead.
 */

import {
  SCORING_DEDUCTIONS,
  type CheckStatus,
  type FindingDTO,
  type ScoreCounts,
  type ScoreResult,
  type Severity,
} from '../core/types';

export interface ScorableFinding {
  ruleId: string;
  severity: Severity;
  status: CheckStatus;
}

function emptyCounts(): ScoreCounts {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    warnings: 0,
    passed: 0,
    failed: 0,
    notAssessed: 0,
    errors: 0,
    notApplicable: 0,
  };
}

export function computeScore(findings: ScorableFinding[]): ScoreResult {
  const counts = emptyCounts();
  const deductions: ScoreResult['deductions'] = [];
  let totalDeduction = 0;
  let assessable = 0;
  let assessed = 0;

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': counts.critical += 1; break;
      case 'HIGH': counts.high += 1; break;
      case 'MEDIUM': counts.medium += 1; break;
      case 'LOW': counts.low += 1; break;
      case 'INFO': counts.info += 1; break;
    }

    const weight = SCORING_DEDUCTIONS[f.severity];
    const applicable = f.status !== 'NOT_APPLICABLE';
    if (applicable) {
      assessable += 1;
      if (f.status === 'PASS' || f.status === 'FAIL' || f.status === 'WARNING') assessed += 1;
    }

    switch (f.status) {
      case 'PASS':
        counts.passed += 1;
        break;
      case 'FAIL':
        counts.failed += 1;
        totalDeduction += weight;
        deductions.push({ ruleId: f.ruleId, severity: f.severity, points: weight });
        break;
      case 'WARNING':
        counts.warnings += 1;
        if (weight > 0) {
          const half = weight / 2;
          totalDeduction += half;
          deductions.push({ ruleId: f.ruleId, severity: f.severity, points: half });
        }
        break;
      case 'NOT_APPLICABLE':
        counts.notApplicable += 1;
        break;
      case 'NOT_ASSESSED':
        counts.notAssessed += 1;
        break;
      case 'ERROR':
        counts.errors += 1;
        break;
    }
  }

  const score = Math.max(0, Math.round((100 - totalDeduction) * 10) / 10);
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
  const coverage = assessable > 0 ? Math.round((assessed / assessable) * 1000) / 10 : 0;

  return { score, grade, coverage, counts, deductions, totalDeduction };
}

/// Severity ranking helpers shared by reporting + API sorting
export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export const STATUS_RANK: Record<CheckStatus, number> = {
  FAIL: 0,
  WARNING: 1,
  ERROR: 2,
  NOT_ASSESSED: 3,
  PASS: 4,
  NOT_APPLICABLE: 5,
};

export function sortFindings<T extends FindingDTO>(findings: T[]): T[] {
  return [...findings].sort((a, b) => {
    const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (sev !== 0) return sev;
    return STATUS_RANK[a.status] - STATUS_RANK[b.status];
  });
}
