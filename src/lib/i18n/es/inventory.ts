/** ES strings — inventory namespace (es-419 neutral, IT-security register). */
const strings: Record<string, string> = {
  // Empty state
  'emptyTitle': 'No hay inventario disponible',
  'emptyDescription': 'Ejecute una auditoría para recopilar el inventario de hardware, sistema operativo, software y red.',

  // Host information
  'host': 'Información del host',
  'hostname': 'Nombre de host',
  'osName': 'Nombre del SO',
  'osVersion': 'Versión del SO',
  'osBuild': 'Compilación del SO',
  'kernel': 'Kernel',
  'architecture': 'Arquitectura',
  'cpuModel': 'Modelo de CPU',
  'cpuCores': 'Núcleos de CPU',
  'totalRam': 'RAM total',
  'usedRam': 'RAM en uso',
  'uptime': 'Tiempo de actividad',
  'primaryIp': 'IP principal',

  // Disks
  'disks': 'Discos',
  'disksDescription': 'Sistemas de archivos montados y su uso',
  'disksEmpty': 'No se recopiló información de discos.',
  'device': 'Dispositivo',
  'type': 'Tipo',
  'size': 'Tamaño',
  'used': 'Usado',
  'mount': 'Montaje',
  'usage': 'Uso',

  // Network interfaces
  'interfaces': 'Interfaces de red',
  'interfacesDescription': 'Direcciones de las interfaces locales',
  'interfacesEmpty': 'No se recopiló información de interfaces.',
  'name': 'Nombre',
  'ipv4': 'IPv4',
  'ipv6': 'IPv6',
  'mac': 'MAC',
  'scope': 'Alcance',
  'internal': 'Interna',
  'external': 'Externa',

  // Installed software
  'software': 'Paquetes instalados',
  'softwareNoCount': 'Número de paquetes no recopilado',
  'softwareCount': '{count} paquetes detectados',
  'softwareEmpty': 'No se recopiló la lista de paquetes.',
  'packagesAria': 'Paquetes detectados',
  'capNote': 'El inventario está limitado por almacenamiento; la lista de paquetes puede estar truncada.',
};

export default strings;
