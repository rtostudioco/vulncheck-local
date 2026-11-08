/** EN strings — remediation namespace (Remediation section). */
const strings: Record<string, string> = {
  // Section card
  'title': 'Remediation plan',
  'description.one': '1 item requires attention, ordered by severity',
  'description.other': '{count} items require attention, ordered by severity',

  // Empty state (no data yet)
  'empty.title': 'No remediation data',
  'empty.description':
    'Run an audit to generate actionable remediation guidance for failed and warning checks.',

  // Empty state (nothing to remediate)
  'empty.allPassed.title': 'No remediations required — all assessable checks passed',
  'empty.allPassed.description':
    'Every rule that could be assessed passed, or was not applicable to this machine.',

  // Remediation card block labels
  'card.problem': 'Problem',
  'card.whyItMatters': 'Why it matters',
  'card.solution': 'Recommended solution',
  'card.verify': 'How to verify',
  'card.os': 'OS: {value}',
};

export default strings;
