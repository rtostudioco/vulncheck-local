/** EN strings — findings namespace (list, filters, detail blocks, AI actions). */
const strings: Record<string, string> = {
  // Section header
  'title': 'Vulnerability findings',
  'description': 'Every rule result with evidence, risk explanation and remediation',

  // Empty states
  'empty.title': 'No findings available',
  'empty.description': 'Run an audit to evaluate the versioned rule set against this machine and record findings.',
  'empty.filteredTitle': 'No findings match the current filters',
  'empty.filteredDescription': 'Adjust or clear the filters to see more results.',

  // Filter bar
  'filters.severity': 'Severity',
  'filters.all': 'All',
  'filters.category': 'Category',
  'filters.byCategory': 'Filter by category',
  'filters.allCategories': 'All categories',
  'filters.status': 'Status',
  'filters.byStatus': 'Filter by status',
  'filters.allStatuses': 'All statuses',
  'filters.showing': 'Showing {shown} of {total} findings',
  'filters.clear': 'Clear filters',

  // Category labels (static UI labels for the category filter)
  'category.FIREWALL': 'Firewall',
  'category.ACCOUNTS': 'Account Security',
  'category.UPDATES': 'System Updates',
  'category.NETWORK': 'Network Exposure',
  'category.ENDPOINT': 'Endpoint Protection',
  'category.SERVICES': 'Service Configuration',
  'category.BACKUP': 'Backup & Recovery',

  // Finding detail blocks
  'detail.evidence': 'Evidence',
  'detail.noEvidence': 'No evidence recorded',
  'detail.risk': 'Why this matters',
  'detail.remediation': 'Recommended remediation',
  'detail.verification': 'Verification',

  // Finding row chrome
  'row.osTarget': 'OS target: {os}',

  // AI explanation
  'ai.title': 'AI explanation',
  'ai.explain': 'Explain with AI',
  'ai.loading': 'Explaining…',
  'ai.enableInSettings': 'Enable AI explanations in Settings',
  'ai.disabledError': 'AI explanations are disabled. Enable them in Settings first.',
  'ai.requestFailed': 'The AI explanation request failed.',
  'ai.failedTitle': 'AI explanation failed',
};

export default strings;
