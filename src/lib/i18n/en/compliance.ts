/** EN strings — compliance namespace (Compliance section). */
const strings: Record<string, string> = {
  // Section card
  'title': 'Compliance assessment',
  'description':
    'Rule results grouped by category — inspired by CIS concepts, not a CIS certification',

  // Empty state (no data yet)
  'empty.title': 'No compliance data',
  'empty.description':
    'Run an audit to evaluate rule results per category with references and evidence.',

  // Methodology & CIS disclaimer banner
  'methodology.title': 'Methodology & disclaimers',
  'methodology.text':
    'Each versioned rule evaluates collected evidence and returns one of: PASS, FAIL, WARNING, ' +
    'NOT_APPLICABLE, NOT_ASSESSED or ERROR. Failures deduct points from a 0–100 posture score using ' +
    'fixed weights (CRITICAL −25, HIGH −15, MEDIUM −7, LOW −3, INFO −0); WARNING deducts half weight. ' +
    'The score starts at 100 and is floored at 0. Rules that could not be assessed do NOT deduct points; ' +
    'instead they reduce assessment coverage, which is reported alongside the score. Grade thresholds: ' +
    'A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.',
  'methodology.disclaimer1':
    'VulnCheck Local performs local, read-only, passive auditing. It never modifies systems, never disables services, never changes firewall or account configuration, and never collects credentials.',
  'methodology.disclaimer2':
    'The security posture score is an internal, reproducible indicator — it is NOT an official compliance score.',
  'methodology.disclaimer3':
    'The rule set is inspired by publicly documented CIS Benchmark concepts where technical requirements are documented. VulnCheck Local is not CIS-certified and this assessment is not a CIS compliance claim.',
  'methodology.disclaimer4':
    'A failed or unsupported inspection is always reported as NOT_ASSESSED / ERROR and never counted as secure.',

  // Category group titles
  'category.FIREWALL': 'Firewall',
  'category.ACCOUNTS': 'Account Security',
  'category.UPDATES': 'System Updates',
  'category.NETWORK': 'Network Exposure',
  'category.ENDPOINT': 'Endpoint Protection',
  'category.SERVICES': 'Service Configuration',
  'category.BACKUP': 'Backup & Recovery',
  'category.empty': 'No rules recorded for this category.',

  // Pass/fail summary words (rendered as "{count} {label}")
  'summary.pass': 'pass',
  'summary.fail': 'fail',
  'summary.warn': 'warn',
  'summary.total': 'total',

  // Expanded-row labels
  'evidence.label': 'Evidence',
  'evidence.empty': 'No evidence recorded',
};

export default strings;
