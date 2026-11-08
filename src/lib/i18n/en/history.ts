/** EN strings — history namespace (audit history section). */
const strings: Record<string, string> = {
  'title': 'Audit history',
  'subtitle': 'Newest first — up to 25 sessions are retained',

  'empty.title': 'No audits recorded',
  'empty.description': 'Completed audits appear here with score, grade and coverage.',

  'col.date': 'Date',
  'col.platform': 'Platform',
  'col.score': 'Score',
  'col.grade': 'Grade',
  'col.findings': 'Findings',
  'col.coverage': 'Coverage',
  'col.status': 'Status',
  'col.actions': 'Actions',

  'action.load': 'Load',

  'delete.title': 'Delete this audit session?',
  'delete.description':
    'The session, its findings and its score will be permanently removed from the local store. This action cannot be undone.',
  'delete.cancel': 'Cancel',
  'delete.confirm': 'Delete',

  'aria.deleteSession': 'Delete session from {date}',

  'retention': 'Sessions are stored locally in SQLite. Retention: {days} days (adjustable in Settings).',
};

export default strings;
