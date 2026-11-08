/**
 * MODULE L — CSV + JSON exports.
 */

import { ENGINE_VERSION, type SessionDetail } from '../core/types';

function csvField(value: string | number | null): string {
  const s = value === null || value === undefined ? '' : String(value);
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function generateCsv(detail: SessionDetail): string {
  const header = [
    'rule_id',
    'rule_version',
    'category',
    'title',
    'severity',
    'status',
    'os_target',
    'description',
    'evidence',
    'risk_explanation',
    'remediation',
    'verification',
  ].join(',');

  const rows = detail.findings.map((f) =>
    [
      f.ruleId,
      f.ruleVersion,
      f.category,
      f.title,
      f.severity,
      f.status,
      f.osTarget,
      f.description,
      f.evidence,
      f.riskExplanation,
      f.remediation,
      f.verification ?? '',
    ].map(csvField).join(','),
  );

  const meta = [
    `# VulnCheck Local export — engine ${ENGINE_VERSION}`,
    `# session ${detail.id} · started ${detail.startedAt} · completed ${detail.completedAt ?? '—'}`,
    `# host ${detail.profile?.hostname ?? '—'} · ${detail.profile?.osName ?? ''} ${detail.profile?.osVersion ?? ''}`,
    `# score ${detail.overallScore ?? '—'}/100 (grade ${detail.grade ?? '—'}) · coverage ${detail.coverage ?? '—'}%`,
  ].join('\n');

  return `${meta}\n${header}\n${rows.join('\n')}\n`;
}

export function generateJson(detail: SessionDetail): string {
  return JSON.stringify(
    {
      generator: `VulnCheck Local ${ENGINE_VERSION}`,
      generatedAt: new Date().toISOString(),
      session: {
        id: detail.id,
        startedAt: detail.startedAt,
        completedAt: detail.completedAt,
        status: detail.status,
        platform: detail.platform,
        engineVersion: detail.engineVersion,
        overallScore: detail.overallScore,
        grade: detail.grade,
        coverage: detail.coverage,
        counts: detail.counts,
        limitations: detail.limitations,
        modules: detail.modules,
      },
      profile: detail.profile,
      network: detail.network,
      findings: detail.findings,
    },
    null,
    2,
  );
}

export function exportFileName(detail: SessionDetail, format: 'json' | 'csv'): string {
  const host = (detail.profile?.hostname ?? 'host').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 40);
  const day = (detail.completedAt ?? detail.startedAt).slice(0, 10);
  return `vulncheck-${format}-${host}-${day}.${format}`;
}
