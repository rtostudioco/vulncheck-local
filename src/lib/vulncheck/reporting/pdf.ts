/**
 * MODULE L — Professional PDF report generator (ReportLab-equivalent).
 * Pure JS (jsPDF + autotable) so it runs inside the Next.js server runtime.
 * Content: identity, host info, date, score, executive summary, findings by
 * severity, evidence, remediation, limitations.
 */

import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  DISCLAIMERS,
  ENGINE_VERSION,
  METHODOLOGY_TEXT,
  type FindingDTO,
  type SessionDetail,
  type Severity,
} from '../core/types';
import { SEVERITY_RANK } from '../scoring/score';

const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 16;
const CONTENT_W = PAGE_W - MARGIN * 2;

const COLORS = {
  graphite: [34, 40, 48] as [number, number, number],
  panel: [247, 249, 250] as [number, number, number],
  emerald: [5, 150, 105] as [number, number, number],
  text: [55, 65, 81] as [number, number, number],
  muted: [120, 130, 140] as [number, number, number],
  line: [222, 228, 232] as [number, number, number],
  critical: [185, 28, 28] as [number, number, number],
  high: [217, 80, 20] as [number, number, number],
  medium: [180, 120, 10] as [number, number, number],
  low: [110, 140, 30] as [number, number, number],
  info: [120, 128, 140] as [number, number, number],
};

function severityColor(s: Severity): [number, number, number] {
  switch (s) {
    case 'CRITICAL': return COLORS.critical;
    case 'HIGH': return COLORS.high;
    case 'MEDIUM': return COLORS.medium;
    case 'LOW': return COLORS.low;
    default: return COLORS.info;
  }
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

/** jsPDF standard fonts use WinAnsi (cp1252): map math glyphs it cannot encode. */
function sanitize(value: string): string {
  return value
    .replace(/\u2212/g, '-')
    .replace(/\u2265/g, '>=')
    .replace(/\u2264/g, '<=')
    .replace(/\u2260/g, '!=');
}

function osDisplay(p: SessionDetail['profile']): string {
  if (!p) return '—';
  const build = p.osBuild && p.osBuild !== p.osVersion ? ` (${p.osBuild})` : '';
  return `${p.osName} ${p.osVersion}${build}`;
}

/// Simple y-cursor with automatic page breaks
class DocCursor {
  y = MARGIN;
  constructor(private doc: jsPDF) {}

  ensure(space: number): void {
    if (this.y + space > PAGE_H - MARGIN - 12) {
      this.doc.addPage();
      this.y = MARGIN;
    }
  }

  text(
    value: string,
    opts: { size?: number; style?: 'normal' | 'bold' | 'italic'; color?: [number, number, number]; gap?: number; indent?: number } = {},
  ): void {
    const { size = 9, style = 'normal', color = COLORS.text, gap = 2, indent = 0 } = opts;
    this.doc.setFont('helvetica', style);
    this.doc.setFontSize(size);
    this.doc.setTextColor(...color);
    const lines = this.doc.splitTextToSize(sanitize(value), CONTENT_W - indent);
    const lineH = size * 0.42 + 0.9;
    for (const line of lines) {
      this.ensure(lineH);
      this.doc.text(line, MARGIN + indent, this.y);
      this.y += lineH;
    }
    this.y += gap;
  }
}

function buildExecutiveSummary(detail: SessionDetail): string {
  const host = detail.profile ? `${detail.profile.hostname} (${detail.profile.osName} ${detail.profile.osVersion})` : 'the audited host';
  const c = detail.counts;
  const failedTotal = c ? c.critical + c.high + c.medium + c.low + c.info : 0;
  const urgent = detail.findings
    .filter((f) => f.status === 'FAIL' && (f.severity === 'CRITICAL' || f.severity === 'HIGH'))
    .slice(0, 4)
    .map((f) => `${f.ruleId} "${f.title}"`)
    .join('; ');

  const parts: string[] = [];
  parts.push(
    `A local, read-only security assessment of ${host} was completed on ${fmtDate(detail.completedAt)} ` +
    `using VulnCheck Local engine version ${detail.engineVersion}.`,
  );
  if (detail.overallScore !== null) {
    parts.push(
      `The overall security posture score is ${detail.overallScore}/100 (grade ${detail.grade}) with an assessment coverage of ${detail.coverage ?? 0}%.`,
    );
  }
  if (c) {
    parts.push(
      `The evaluation produced ${detail.findingsCount} findings: ${c.failed} failed check(s) ` +
      `(${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} informational), ` +
      `${c.warnings} warning(s), ${c.passed} passed check(s), ${c.notAssessed} not assessed and ${c.errors} error(s).`,
    );
    if (failedTotal === 0) {
      parts.push('No failed checks were identified by the current rule set.');
    }
  }
  if (urgent) {
    parts.push(`The most urgent remediation items are: ${urgent}.`);
  }
  parts.push(
    'Failed or unsupported inspections were reported as NOT_ASSESSED or ERROR and were never counted as secure. ' +
    'This score is an internal posture indicator, not an official compliance score.',
  );
  return parts.join(' ');
}

function tableHeader(doc: jsPDF, page: number, total: number): void {
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(...COLORS.muted);
  doc.text('VulnCheck Local — Security Assessment Report · engine ' + ENGINE_VERSION, MARGIN, 8);
  doc.text(`Page ${page} of ${total}`, PAGE_W - MARGIN, 8, { align: 'right' });
}

export function generatePdf(detail: SessionDetail): Uint8Array {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const cur = new DocCursor(doc);

  // ---------------- Cover / identity block ---------------------------------
  doc.setFillColor(...COLORS.graphite);
  doc.rect(0, 0, PAGE_W, 34, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text('VULNCHECK LOCAL', MARGIN, 14);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(180, 200, 190);
  doc.text('Local-First Security Assessment Report', MARGIN, 21);
  doc.setFontSize(8);
  doc.text(`Engine ${ENGINE_VERSION} · generated ${fmtDate(new Date().toISOString())}`, MARGIN, 27);
  doc.setFillColor(...COLORS.emerald);
  doc.rect(0, 34, PAGE_W, 1.2, 'F');

  cur.y = 44;

  // Host info
  cur.text('Host Information', { size: 12, style: 'bold', color: COLORS.graphite, gap: 4 });
  const p = detail.profile;
  autoTable(doc, {
    startY: cur.y,
    margin: { left: MARGIN, right: MARGIN },
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 1.6, textColor: COLORS.text },
    headStyles: { fillColor: COLORS.graphite, textColor: [255, 255, 255], fontSize: 8.5 },
    head: [['Property', 'Value']],
    body: [
      ['Hostname', p?.hostname ?? '—'],
      ['Operating system', osDisplay(p)],
      ['Kernel', p?.kernelVersion ?? '—'],
      ['Architecture', p?.arch ?? '—'],
      ['CPU', p?.cpuModel ? `${p.cpuModel} (${p.cpuCores} cores)` : '—'],
      ['Memory', p?.totalMemoryMb ? `${(p.totalMemoryMb / 1024).toFixed(1)} GiB` : '—'],
      ['Primary IP', p?.primaryIp ?? '—'],
      ['Assessment date', fmtDate(detail.startedAt)],
      ['Completion date', fmtDate(detail.completedAt)],
      ['Platform target', detail.platform],
    ],
  });
  // @ts-expect-error lastAutoTable is injected by autotable
  cur.y = doc.lastAutoTable.finalY + 8;

  // Score block
  cur.text('Overall Security Posture', { size: 12, style: 'bold', color: COLORS.graphite, gap: 4 });
  const scoreText = detail.overallScore !== null ? `${detail.overallScore} / 100  (grade ${detail.grade})` : 'Score unavailable';
  const scoreColor =
    detail.overallScore === null ? COLORS.muted
      : detail.overallScore >= 90 ? COLORS.emerald
      : detail.overallScore >= 65 ? COLORS.medium
      : detail.overallScore >= 40 ? COLORS.high
      : COLORS.critical;
  cur.text(scoreText, { size: 18, style: 'bold', color: scoreColor, gap: 2 });
  cur.text(
    `Assessment coverage: ${detail.coverage ?? 0}% of assessable rules produced a definitive result. ` +
    'Checks that could not be assessed are disclosed in the limitations section — they are never counted as secure.',
    { size: 8.5, color: COLORS.muted, gap: 6 },
  );

  // Severity summary table
  if (detail.counts) {
    autoTable(doc, {
      startY: cur.y,
      margin: { left: MARGIN, right: MARGIN },
      theme: 'grid',
      styles: { fontSize: 8.5, cellPadding: 1.6, textColor: COLORS.text },
      headStyles: { fillColor: COLORS.graphite, textColor: [255, 255, 255] },
      head: [['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'WARNING', 'PASS', 'NOT ASSESSED', 'ERROR', 'N/A']],
      body: [[
        String(detail.counts.critical), String(detail.counts.high), String(detail.counts.medium),
        String(detail.counts.low), String(detail.counts.info), String(detail.counts.warnings),
        String(detail.counts.passed), String(detail.counts.notAssessed), String(detail.counts.errors),
        String(detail.counts.notApplicable),
      ]],
    });
    // @ts-expect-error lastAutoTable is injected by autotable
    cur.y = doc.lastAutoTable.finalY + 8;
  }

  // ---------------- Executive summary --------------------------------------
  doc.addPage();
  cur.y = MARGIN;
  cur.text('Executive Summary', { size: 13, style: 'bold', color: COLORS.graphite, gap: 4 });
  cur.text(buildExecutiveSummary(detail), { size: 9.5, gap: 6 });

  cur.text('Scoring Methodology', { size: 11, style: 'bold', color: COLORS.graphite, gap: 3 });
  cur.text(METHODOLOGY_TEXT, { size: 8.5, color: COLORS.muted, gap: 6 });

  cur.text('Assessment Limitations', { size: 11, style: 'bold', color: COLORS.graphite, gap: 3 });
  for (const lim of detail.limitations) {
    cur.text(`• ${lim}`, { size: 8.5, indent: 2, gap: 1 });
  }
  cur.y += 4;
  for (const d of DISCLAIMERS) {
    cur.text(d, { size: 7.5, color: COLORS.muted, gap: 1 });
  }

  // ---------------- Detailed findings (by severity) -------------------------
  const notable = detail.findings
    .filter((f) => f.status === 'FAIL' || f.status === 'WARNING' || f.status === 'ERROR' || f.status === 'NOT_ASSESSED')
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

  doc.addPage();
  cur.y = MARGIN;
  cur.text('Detailed Findings', { size: 13, style: 'bold', color: COLORS.graphite, gap: 2 });
  cur.text(
    `Findings requiring attention (${notable.length}), ordered by severity. Passed and not-applicable checks are listed in the appendix.`,
    { size: 8.5, color: COLORS.muted, gap: 6 },
  );

  for (const f of notable) {
    cur.ensure(30);
    const sc = severityColor(f.severity);
    doc.setFillColor(...sc);
    doc.rect(MARGIN, cur.y - 3.4, 2.4, 2.4, 'F');
    cur.text(`[${f.severity}] ${f.ruleId} — ${f.title}`, { size: 10, style: 'bold', color: COLORS.graphite, indent: 5, gap: 1 });
    cur.text(`Status: ${f.status} · Category: ${f.category} · Rule version: ${f.ruleVersion} · Target: ${f.osTarget}`, { size: 7.5, color: COLORS.muted, indent: 5, gap: 3 });
    cur.text(f.description, { size: 9, indent: 5, gap: 3 });
    cur.text('Evidence', { size: 8, style: 'bold', color: COLORS.emerald, indent: 5, gap: 1 });
    cur.text(f.evidence, { size: 7.5, style: 'normal', color: COLORS.text, indent: 9, gap: 3 });
    cur.text('Why this matters', { size: 8, style: 'bold', color: COLORS.emerald, indent: 5, gap: 1 });
    cur.text(f.riskExplanation, { size: 8.5, indent: 9, gap: 3 });
    cur.text('Recommended remediation', { size: 8, style: 'bold', color: COLORS.emerald, indent: 5, gap: 1 });
    cur.text(f.remediation, { size: 8.5, indent: 9, gap: 3 });
    if (f.verification) {
      cur.text('Verification procedure', { size: 8, style: 'bold', color: COLORS.emerald, indent: 5, gap: 1 });
      cur.text(f.verification, { size: 8.5, indent: 9, gap: 3 });
    }
    cur.y += 5;
  }

  // ---------------- Appendix: passed / N/A rules ----------------------------
  const passed = detail.findings.filter((f) => f.status === 'PASS' || f.status === 'NOT_APPLICABLE');
  if (passed.length > 0) {
    doc.addPage();
    cur.y = MARGIN;
    cur.text('Appendix — Passed & Not-Applicable Checks', { size: 12, style: 'bold', color: COLORS.graphite, gap: 4 });
    autoTable(doc, {
      startY: cur.y,
      margin: { left: MARGIN, right: MARGIN },
      theme: 'grid',
      styles: { fontSize: 8, cellPadding: 1.4, textColor: COLORS.text },
      headStyles: { fillColor: COLORS.graphite, textColor: [255, 255, 255] },
      head: [['Rule', 'Status', 'Check', 'Category']],
      body: passed.map((f) => [f.ruleId, f.status, f.title, f.category]),
    });
    // @ts-expect-error lastAutoTable is injected by autotable
    cur.y = doc.lastAutoTable.finalY + 6;
    cur.text('End of report.', { size: 8, color: COLORS.muted });
  }

  // Page numbers + header on every page
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i += 1) {
    doc.setPage(i);
    tableHeader(doc, i, pages);
    doc.setDrawColor(...COLORS.line);
    doc.setLineWidth(0.2);
    doc.line(MARGIN, PAGE_H - 10, PAGE_W - MARGIN, PAGE_H - 10);
    doc.setFontSize(7);
    doc.setTextColor(...COLORS.muted);
    doc.text('Local, read-only assessment. No credentials collected. No system changes performed.', MARGIN, PAGE_H - 6);
  }

  return new Uint8Array(doc.output('arraybuffer'));
}

export function pdfFileName(detail: SessionDetail): string {
  const host = (detail.profile?.hostname ?? 'host').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 40);
  const day = (detail.completedAt ?? detail.startedAt).slice(0, 10);
  return `vulncheck-report-${host}-${day}.pdf`;
}
