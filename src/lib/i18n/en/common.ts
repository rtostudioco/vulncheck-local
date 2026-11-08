/** EN shared strings: severity names, check statuses, audit states. */
const strings: Record<string, string> = {
  'severity.CRITICAL': 'Critical',
  'severity.HIGH': 'High',
  'severity.MEDIUM': 'Medium',
  'severity.LOW': 'Low',
  'severity.INFO': 'Info',

  'status.PASS': 'Pass',
  'status.FAIL': 'Fail',
  'status.WARNING': 'Warning',
  'status.NOT_APPLICABLE': 'Not applicable',
  'status.NOT_ASSESSED': 'Not assessed',
  'status.ERROR': 'Error',

  'audit.RUNNING': 'Running',
  'audit.COMPLETED': 'Completed',
  'audit.FAILED': 'Failed',

  'lang.label': 'Language',

  // Navigation items
  'nav.overview': 'Overview',
  'nav.inventory': 'System Inventory',
  'nav.assessment': 'Security Assessment',
  'nav.findings': 'Vulnerability Findings',
  'nav.network': 'Network Exposure',
  'nav.compliance': 'Compliance',
  'nav.remediation': 'Remediation',
  'nav.history': 'Audit History',
  'nav.reports': 'Reports',
  'nav.settings': 'Settings',

  // Shell (header, nav, alerts, footer)
  'shell.openNav': 'Open navigation menu',
  'shell.navAria': 'Dashboard sections',
  'shell.nav.description': 'Security auditing sections',
  'shell.runAudit': 'Run New Audit',
  'shell.auditing': 'Auditing…',
  'shell.retry': 'Retry',
  'shell.error.meta': 'Failed to load application metadata',
  'shell.error.detail': 'Failed to load session detail',
  'shell.error.poll': 'Failed to poll audit status',
  'shell.error.sessionStore': 'Could not read the local session store',
  'shell.error.startAudit': 'The audit could not be started',
  'shell.error.deleteSession': 'The session could not be deleted',
  'shell.footer.guarantee':
    'VulnCheck Local v{version} — Local-first security auditing. Read-only inspection: no system changes, no credential collection. Data never leaves this machine unless AI explanations are explicitly enabled in Settings.',
  'shell.footer.engine': 'Engine {version} · {rules} versioned rules',
  'shell.credit': '© {year} Ramon Taboada Olivella · RTO Studio',

  // Shell toasts (zustand store)
  'shell.toast.auditStarted': 'Audit started',
  'shell.toast.auditStartedDesc':
    'Collecting evidence and evaluating rules. Live progress is shown under Security Assessment.',
  'shell.toast.auditCompleted': 'Audit completed',
  'shell.toast.auditCompletedDesc': 'Score {score} · {count} findings recorded',
  'shell.toast.auditFailed': 'Audit failed',
  'shell.toast.auditFailedDesc':
    'The audit ended with status FAILED. Inspection errors are reported per module in Security Assessment.',
  'shell.toast.alreadyRunning': 'An audit is already running',
  'shell.toast.alreadyRunningDesc': 'Wait for the current audit to complete before starting another one.',
  'shell.toast.startFailed': 'Failed to start audit',
  'shell.toast.pollLost': 'Lost track of the running audit',
  'shell.toast.loadSessionsFailed': 'Failed to load audit sessions',
  'shell.toast.refreshFailed': 'Failed to refresh sessions',
  'shell.toast.sessionDeleted': 'Session deleted',
  'shell.toast.deleteFailed': 'Failed to delete session',
  'shell.toast.deletedOne': 'Deleted {count} session',
  'shell.toast.deletedMany': 'Deleted {count} sessions',
  'shell.toast.deleteFailedOne': '{count} session could not be deleted.',
  'shell.toast.deleteFailedMany': '{count} sessions could not be deleted.',
  'shell.toast.historyCleared': 'Audit history cleared.',

  // Audit module states
  'moduleState.OK': 'OK',
  'moduleState.PARTIAL': 'Partial',
  'moduleState.UNAVAILABLE': 'Unavailable',
  'moduleState.ERROR': 'Error',
};

export default strings;
