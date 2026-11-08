/** EN strings — reports namespace (export reports + report history). */
const strings: Record<string, string> = {
  'title': 'Export reports',
  'subtitle.ready': 'Generate a report for the selected completed audit',
  'subtitle.select': 'Select a completed audit (via Audit History) to enable downloads',
  'note.disabled': 'Run an audit or load a completed session to enable report downloads.',

  'format.pdf.title': 'PDF report',
  'format.pdf.description':
    'Multi-page professional report: executive summary, findings by severity, evidence, remediation, limitations',
  'format.json.title': 'JSON export',
  'format.json.description': 'Machine-readable full session detail',
  'format.csv.title': 'CSV export',
  'format.csv.description': 'Findings table for spreadsheets',

  'action.download': 'Download {format}',
  'action.refresh': 'Refresh',

  'toast.started.title': 'Report generation started',
  'toast.started.description': 'Your download will begin automatically when the report is ready.',
  'toast.failed.title': 'Download failed',
  'toast.failed.description': 'The report could not be generated.',

  'history.title': 'Report history',
  'history.subtitle': 'Reports previously generated on this machine',

  'error.title': 'Could not load report history',
  'error.fallback': 'Failed to load report history',

  'col.generated': 'Generated',
  'col.format': 'Format',
  'col.file': 'File',
  'col.sessionDate': 'Session date',
  'col.score': 'Score',

  'empty.title': 'No reports generated yet',
  'empty.description': 'Downloaded PDF, JSON and CSV reports are listed here.',

  'aria.refresh': 'Refresh report history',
};

export default strings;
