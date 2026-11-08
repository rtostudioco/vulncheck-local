/** ES strings — assessment namespace (methodology, progress, modules A–H). */
const strings: Record<string, string> = {
  // Methodology card
  'methodology.title': 'Cómo funciona esta evaluación',
  'methodology.description': 'Evaluación de reglas basada en evidencia con un modelo de puntuación documentado',
  'methodology.text':
    'Cada regla versionada evalúa la evidencia recopilada y devuelve uno de estos resultados: PASS, FAIL, WARNING, ' +
    'NOT_APPLICABLE, NOT_ASSESSED o ERROR. Los fallos descuentan puntos de una puntuación de postura de 0–100 con ' +
    'ponderaciones fijas (CRITICAL −25, HIGH −15, MEDIUM −7, LOW −3, INFO −0); WARNING descuenta la mitad de su peso. ' +
    'La puntuación comienza en 100 y tiene un piso de 0. Las reglas que no pudieron evaluarse NO descuentan puntos; ' +
    'en su lugar, reducen la cobertura de la evaluación, la cual se informa junto con la puntuación. Umbrales de calificación: ' +
    'A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.',

  // Read-only guarantee alert
  'readonly.title': 'Garantía de solo lectura',
  'readonly.disclaimer':
    'VulnCheck Local realiza auditorías locales, pasivas y de solo lectura. Nunca modifica sistemas, nunca ' +
    'deshabilita servicios, nunca cambia la configuración del firewall ni de las cuentas, y nunca recopila credenciales.',
  'readonly.evidenceBased':
    'Cada verificación se basa en evidencia: cuando no se puede recopilar evidencia, la regla se reporta como ' +
    'NOT_ASSESSED o ERROR y nunca se cuenta como segura.',

  // Running progress card
  'progress.title': 'Auditoría en curso',
  'progress.description': 'Los módulos se ejecutan en secuencia; el progreso y el paso actual se actualizan en vivo.',
  'progress.ariaLabel': 'Progreso de la auditoría',
  'progress.starting': 'Iniciando auditoría…',

  // Completion summary chips
  'summary.latestAudit': 'Última auditoría:',
  'summary.score': 'Puntuación {score}',
  'summary.findings': '{count} hallazgos',
  'summary.coverage': 'Cobertura {value}',

  // Audit modules card
  'modules.title': 'Módulos de auditoría',
  'modules.description':
    'Ocho recolectores de solo lectura cubren inventario, firewall, cuentas, red, actualizaciones, endpoint, servicios y respaldo',
  'modules.notCollected': 'SIN RECOLECTAR',
  'modules.source': 'origen: {source}',
  'modules.notCollectedShort': 'sin recopilar',

  // Module names/descriptions (static definitions, keyed by module key)
  'module.inventory.name': 'Inventario del sistema',
  'module.inventory.description': 'Inventario de hardware, sistema operativo, software y red.',
  'module.firewall.name': 'Auditor de firewall',
  'module.firewall.description':
    'Producto de firewall, estado, perfiles y excepciones (Defender Firewall / UFW / firewalld / nftables).',
  'module.accounts.name': 'Auditor de usuarios y accesos',
  'module.accounts.description':
    'Cuentas locales, privilegios administrativos, indicadores de política de contraseñas, acceso remoto. Nunca recopila credenciales.',
  'module.network.name': 'Auditor de exposición de red',
  'module.network.description':
    'Puertos TCP/UDP en escucha, interfaces, conexiones activas y servicios expuestos innecesarios. Pasivo y solo local.',
  'module.updates.name': 'Auditor de actualizaciones del sistema',
  'module.updates.description':
    'Actualizaciones pendientes, actualizaciones de seguridad y configuración de actualizaciones automáticas. El estado verificado se distingue del estado no obtenible.',
  'module.endpoint.name': 'Antivirus y protección',
  'module.endpoint.description':
    'Detección de Defender / ClamAV. La protección nunca se declara activa salvo que se verifique que está en ejecución.',
  'module.services.name': 'Auditor de servicios',
  'module.services.description':
    'Servicios en ejecución, indicadores de configuración de inicio y servicios heredados de administración remota. Solo lectura; nunca deshabilita nada.',
  'module.backup.name': 'Auditor de respaldo y recuperación',
  'module.backup.description':
    'Software de respaldo, trabajos programados e indicadores de instantáneas. Un respaldo nunca se declara válido sin verificación.',
};

export default strings;
