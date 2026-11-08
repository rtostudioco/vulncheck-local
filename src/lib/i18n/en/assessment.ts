/** EN strings — assessment namespace (methodology, progress, modules A–H). */
const strings: Record<string, string> = {
  // Methodology card
  'methodology.title': 'How this assessment works',
  'methodology.description': 'Evidence-based rule evaluation with a documented scoring model',
  'methodology.text':
    'Each versioned rule evaluates collected evidence and returns one of: PASS, FAIL, WARNING, ' +
    'NOT_APPLICABLE, NOT_ASSESSED or ERROR. Failures deduct points from a 0–100 posture score using ' +
    'fixed weights (CRITICAL −25, HIGH −15, MEDIUM −7, LOW −3, INFO −0); WARNING deducts half weight. ' +
    'The score starts at 100 and is floored at 0. Rules that could not be assessed do NOT deduct points; ' +
    'instead they reduce assessment coverage, which is reported alongside the score. Grade thresholds: ' +
    'A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.',

  // Read-only guarantee alert
  'readonly.title': 'Read-only guarantee',
  'readonly.disclaimer':
    'VulnCheck Local performs local, read-only, passive auditing. It never modifies systems, never ' +
    'disables services, never changes firewall or account configuration, and never collects credentials.',
  'readonly.evidenceBased':
    'Every check is evidence-based: when evidence cannot be collected the rule is reported as ' +
    'NOT_ASSESSED or ERROR and is never counted as secure.',

  // Running progress card
  'progress.title': 'Audit in progress',
  'progress.description': 'Modules run sequentially; progress and the current step update live.',
  'progress.ariaLabel': 'Audit progress',
  'progress.starting': 'Starting audit…',

  // Completion summary chips
  'summary.latestAudit': 'Latest audit:',
  'summary.score': 'Score {score}',
  'summary.findings': '{count} findings',
  'summary.coverage': 'Coverage {value}',

  // Audit modules card
  'modules.title': 'Audit modules',
  'modules.description':
    'Eight read-only collectors cover inventory, firewall, accounts, network, updates, endpoint, services and backup',
  'modules.notCollected': 'NOT COLLECTED',
  'modules.source': 'source: {source}',
  'modules.notCollectedShort': 'not collected',

  // Module names/descriptions (static definitions, keyed by module key)
  'module.inventory.name': 'System Inventory',
  'module.inventory.description': 'Hardware, operating system, software and network inventory.',
  'module.firewall.name': 'Firewall Auditor',
  'module.firewall.description':
    'Firewall product, status, profiles and exceptions (Defender Firewall / UFW / firewalld / nftables).',
  'module.accounts.name': 'User & Access Auditor',
  'module.accounts.description':
    'Local accounts, administrative privileges, password policy indicators, remote access. Never collects credentials.',
  'module.network.name': 'Network Exposure Auditor',
  'module.network.description':
    'Listening TCP/UDP ports, interfaces, active connections, unnecessary exposed services. Passive, local-only.',
  'module.updates.name': 'System Update Auditor',
  'module.updates.description':
    'Pending updates, security updates, automatic update configuration. Verified status is distinguished from unobtainable status.',
  'module.endpoint.name': 'Antivirus & Protection',
  'module.endpoint.description':
    'Defender / ClamAV detection. Protection is never claimed active unless verifiably running.',
  'module.services.name': 'Service Auditor',
  'module.services.description':
    'Running services, startup configuration indicators, legacy remote-administration services. Read-only; never disables anything.',
  'module.backup.name': 'Backup & Recovery Auditor',
  'module.backup.description':
    'Backup software, scheduled jobs, snapshot indicators. A backup is never claimed valid without verification.',
};

export default strings;
