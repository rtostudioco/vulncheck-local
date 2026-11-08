/** EN strings — inventory namespace. */
const strings: Record<string, string> = {
  // Empty state
  'emptyTitle': 'No inventory available',
  'emptyDescription': 'Run an audit to collect hardware, operating system, software and network inventory.',

  // Host information
  'host': 'Host information',
  'hostname': 'Hostname',
  'osName': 'OS name',
  'osVersion': 'OS version',
  'osBuild': 'OS build',
  'kernel': 'Kernel',
  'architecture': 'Architecture',
  'cpuModel': 'CPU model',
  'cpuCores': 'CPU cores',
  'totalRam': 'Total RAM',
  'usedRam': 'Used RAM',
  'uptime': 'Uptime',
  'primaryIp': 'Primary IP',

  // Disks
  'disks': 'Disks',
  'disksDescription': 'Mounted filesystems and usage',
  'disksEmpty': 'No disk information collected.',
  'device': 'Device',
  'type': 'Type',
  'size': 'Size',
  'used': 'Used',
  'mount': 'Mount',
  'usage': 'Usage',

  // Network interfaces
  'interfaces': 'Network interfaces',
  'interfacesDescription': 'Local interface addresses',
  'interfacesEmpty': 'No interface information collected.',
  'name': 'Name',
  'ipv4': 'IPv4',
  'ipv6': 'IPv6',
  'mac': 'MAC',
  'scope': 'Scope',
  'internal': 'Internal',
  'external': 'External',

  // Installed software
  'software': 'Installed software',
  'softwareNoCount': 'Package count not collected',
  'softwareCount': '{count} packages detected',
  'softwareEmpty': 'No package list collected.',
  'packagesAria': 'Detected packages',
  'capNote': 'Inventory capped for storage; the package list may be truncated.',
};

export default strings;
