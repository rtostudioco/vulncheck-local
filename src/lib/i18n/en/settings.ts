/** EN strings — settings namespace. */
const strings: Record<string, string> = {
  // Language card
  'language.desc': 'Interface language for the dashboard.',

  // AI consent card
  'ai.title': 'AI explanations',
  'ai.subtitle': 'Optional, off by default',
  'ai.allow': 'Allow AI explanations for individual findings',
  'ai.hint': 'When enabled, an Explain button appears on each finding in Vulnerability Findings.',
  'ai.switchAria': 'Enable AI explanations',

  // Retention card
  'retention.title': 'Data retention',
  'retention.subtitle': 'How long local sessions are kept',
  'retention.label': 'Retention period (days)',
  'retention.save': 'Save',
  'retention.range': 'Allowed range: {min}–{max} days. Sessions are stored locally in SQLite.',

  // About card
  'about.title': 'About VulnCheck Local',
  'about.subtitle': 'Engine and assessment facts',
  'about.engineVersion': 'Engine version',
  'about.rules': 'Versioned rules',
  'about.platform': 'Detected platform',
  'about.readOnly':
    'Read-only inspection: no system changes, no credential collection. Data never leaves this machine unless AI explanations are explicitly enabled.',
  'createdBy': 'Created by Ramon Taboada Olivella',
  'studio': 'RTO Studio',

  // Project package card
  'download.title': 'Project package',
  'download.subtitle': 'Full source code, ready to publish',
  'download.desc':
    'Complete project as a ZIP: source code, documentation, license and a prepared git repository (branch main, commit and tag v1.1.0 included).',
  'download.btn': 'Download ZIP',
  'download.btnAria': 'Download project ZIP package',

  // Danger zone card
  'danger.title': 'Danger zone',
  'danger.subtitle': 'Irreversible maintenance actions',
  'danger.deleteAll': 'Delete all audit history',
  'danger.deleteAllHint.one':
    'Permanently removes all {count} recorded session, including findings and scores. Reports already downloaded are not affected.',
  'danger.deleteAllHint.other':
    'Permanently removes all {count} recorded sessions, including findings and scores. Reports already downloaded are not affected.',
  'danger.deleteAllBtn': 'Delete all history',
  'danger.confirmTitle': 'Delete all audit history?',
  'danger.confirmDesc':
    'Every session, finding and score stored on this machine will be permanently deleted. This action cannot be undone.',
  'danger.cancel': 'Cancel',
  'danger.confirm': 'Delete everything',

  // Toasts
  'toast.aiOn.title': 'AI explanations enabled',
  'toast.aiOn.desc': 'You can now request per-finding explanations in Vulnerability Findings.',
  'toast.aiOff.title': 'AI explanations disabled',
  'toast.aiOff.desc': 'No finding data will be sent to the AI provider.',
  'toast.aiFailed.title': 'Failed to update AI consent',
  'toast.saveFailed.desc': 'Settings could not be saved.',
  'toast.invalidRetention.title': 'Invalid retention value',
  'toast.invalidRetention.desc': 'Retention must be an integer between {min} and {max} days.',
  'toast.retentionSaved.title': 'Retention updated',
  'toast.retentionSaved.desc': 'Sessions older than {count} days will be cleaned up automatically.',
  'toast.retentionFailed.title': 'Failed to update retention',
  'ai.consentText': 'AI explanations are optional and off by default. When enabled, clicking "Explain" on an individual finding sends only that finding\'s metadata (category, title, description and a sanitized evidence excerpt, truncated) to the configured AI provider. Full system inventory, hostnames, addresses and audit evidence sets are never transmitted automatically.',
  'about.methodologyText': 'Each versioned rule evaluates collected evidence and returns one of: PASS, FAIL, WARNING, NOT_APPLICABLE, NOT_ASSESSED or ERROR. Failures deduct points from a 0\u2013100 posture score using fixed weights (CRITICAL \u221225, HIGH \u221215, MEDIUM \u22127, LOW \u22123, INFO \u22120); WARNING deducts half weight. The score starts at 100 and is floored at 0. Rules that could not be assessed do NOT deduct points; instead they reduce assessment coverage, which is reported alongside the score. Grade thresholds: A \u2265 90, B \u2265 80, C \u2265 65, D \u2265 50, F < 50.',
  'about.disclaimer.1': 'VulnCheck Local performs local, read-only, passive auditing. It never modifies systems, never disables services, never changes firewall or account configuration, and never collects credentials.',
  'about.disclaimer.2': 'The security posture score is an internal, reproducible indicator \u2014 it is NOT an official compliance score.',
  'about.disclaimer.3': 'The rule set is inspired by publicly documented CIS Benchmark concepts where technical requirements are documented. VulnCheck Local is not CIS-certified and this assessment is not a CIS compliance claim.',
  'about.disclaimer.4': 'A failed or unsupported inspection is always reported as NOT_ASSESSED / ERROR and never counted as secure.',
};


export default strings;
