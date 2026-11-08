/** EN strings — overview namespace. */
const strings: Record<string, string> = {
  // Audit in progress card
  'auditInProgressTitle': 'Audit in progress',
  'auditInProgressDescription': 'Collecting evidence and evaluating rules. This view updates automatically.',
  'auditProgressAria': 'Audit progress',
  'working': 'Working…',

  // Empty / failed state
  'emptyTitle': 'No audit performed yet',
  'emptyDescription': 'Run your first local security audit to score this machine, surface findings and produce exportable reports.',
  'emptyFailedDescription': 'The latest audit did not complete successfully. Start a new audit to assess this machine.',
  'runFirstAudit': 'Run first audit',

  // Hero — security posture
  'heroTitle': 'Security posture',
  'heroDescription': 'Result of the most recent completed audit',
  'grade': 'Grade',
  'coverage': 'Assessment coverage',
  'findings': 'Findings',
  'lastAudit': 'Last audit',
  'hostname': 'Hostname',
  'platform': 'Platform',

  // Severity summary
  'severityTitle': 'Severity summary',
  'severityDescription': 'Click a severity to open the matching findings',
  'viewFindingsAria': 'View {sev} findings',

  // Category posture
  'categoryTitle': 'Category posture',
  'categoryDescription': 'Pass share of assessed rules per category',
  'categoryAria': '{cat}: {pct}% passed',
  'failBadge': '{count} FAIL',

  // Module health
  'moduleHealthTitle': 'Module health',
  'moduleHealthDescription': 'Evidence collectors used by the latest audit',
  'moduleHealthEmpty': 'No module data available.',
  'moduleStateSource': 'State: {state} · Source: {source}',

  // Limitations alert
  'limitationsTitle': 'Assessment limitations',
};

export default strings;
