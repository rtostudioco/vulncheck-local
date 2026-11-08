/** EN strings — network namespace (Network Exposure section). */
const strings: Record<string, string> = {
  // Bind-scope badge labels
  'bindScope.ALL': 'All interfaces',
  'bindScope.LOCAL': 'Local only',
  'bindScope.OTHER': 'Other',

  // Empty state (no data yet)
  'empty.title': 'No network exposure data',
  'empty.description':
    'Run an audit to passively sample listening sockets and interface addresses.',

  // Listening ports card
  'ports.title': 'Listening ports',
  'ports.description': 'Socket tables only — sorted by assessed risk',
  'ports.empty': 'No listening sockets were detected.',

  // Listening ports table headers
  'table.proto': 'Proto',
  'table.port': 'Port',
  'table.address': 'Address',
  'table.bindScope': 'Bind scope',
  'table.service': 'Service',
  'table.risk': 'Risk',
  'table.note': 'Note',

  // Exposure summary stat cards
  'stat.listeningPorts': 'Listening ports',
  'stat.interfaces': 'Interfaces',
  'stat.boundAll': 'Bound to all interfaces',
  'stat.established': 'Established connections',
  'stat.establishedHint':
    'sampled passively during the audit; individual connections are not persisted',
  'summary.title': 'Exposure summary',
  'summary.description': 'Quick counters for the sampled sockets',

  // Interfaces card
  'interfaces.title': 'Interfaces',
  'interfaces.description': 'Recap of addresses observed during the audit',
  'interfaces.empty': 'No interface data collected.',
  'interfaces.internal': 'Internal',
  'interfaces.external': 'External',
  'interfaces.ipv4': 'IPv4: {value}',
  'interfaces.ipv6': 'IPv6: {value}',
  'interfaces.mac': 'MAC: {value}',

  // Passive-detection notice
  'passive.title': 'Passive detection',
  'passive.description':
    'Detection is passive (socket tables only). No scanning, probing or exploitation is performed.',
};

export default strings;
