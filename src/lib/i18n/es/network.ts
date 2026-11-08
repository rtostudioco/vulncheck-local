/** ES strings — network namespace (Network Exposure section). */
const strings: Record<string, string> = {
  // Etiquetas de la insignia de ámbito de enlace
  'bindScope.ALL': 'Todas las interfaces',
  'bindScope.LOCAL': 'Solo local',
  'bindScope.OTHER': 'Otro',

  // Estado vacío (aún sin datos)
  'empty.title': 'Sin datos de exposición de red',
  'empty.description':
    'Ejecuta una auditoría para muestrear de forma pasiva los sockets en escucha y las direcciones de las interfaces.',

  // Tarjeta de puertos en escucha
  'ports.title': 'Puertos en escucha',
  'ports.description': 'Solo tablas de sockets: ordenados por riesgo evaluado',
  'ports.empty': 'No se detectaron sockets en escucha.',

  // Encabezados de la tabla de puertos en escucha
  'table.proto': 'Protocolo',
  'table.port': 'Puerto',
  'table.address': 'Dirección',
  'table.bindScope': 'Ámbito de enlace',
  'table.service': 'Servicio',
  'table.risk': 'Riesgo',
  'table.note': 'Nota',

  // Tarjetas de resumen de exposición
  'stat.listeningPorts': 'Puertos en escucha',
  'stat.interfaces': 'Interfaces',
  'stat.boundAll': 'Enlazado a todas las interfaces',
  'stat.established': 'Conexiones establecidas',
  'stat.establishedHint':
    'muestreadas de forma pasiva durante la auditoría; las conexiones individuales no se conservan',
  'summary.title': 'Resumen de exposición',
  'summary.description': 'Contadores rápidos de los sockets muestreados',

  // Tarjeta de interfaces
  'interfaces.title': 'Interfaces',
  'interfaces.description': 'Resumen de las direcciones observadas durante la auditoría',
  'interfaces.empty': 'No se recopilaron datos de interfaces.',
  'interfaces.internal': 'Interna',
  'interfaces.external': 'Externa',
  'interfaces.ipv4': 'IPv4: {value}',
  'interfaces.ipv6': 'IPv6: {value}',
  'interfaces.mac': 'MAC: {value}',

  // Aviso de detección pasiva
  'passive.title': 'Detección pasiva',
  'passive.description':
    'La detección es pasiva (solo tablas de sockets). No se realizan escaneos remotos, sondeos ni explotación.',
};

export default strings;
