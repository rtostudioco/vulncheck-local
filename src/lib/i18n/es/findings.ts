/** ES strings — findings namespace (list, filters, detail blocks, AI actions). */
const strings: Record<string, string> = {
  // Section header
  'title': 'Hallazgos de vulnerabilidades',
  'description': 'Cada resultado de regla con evidencia, explicación de riesgo y remediación',

  // Empty states
  'empty.title': 'No hay hallazgos',
  'empty.description': 'Ejecute una auditoría para evaluar el conjunto de reglas versionado en este equipo y registrar los hallazgos.',
  'empty.filteredTitle': 'Ningún hallazgo coincide con los filtros actuales',
  'empty.filteredDescription': 'Ajuste o limpie los filtros para ver más resultados.',

  // Filter bar
  'filters.severity': 'Severidad',
  'filters.all': 'Todas',
  'filters.category': 'Categoría',
  'filters.byCategory': 'Filtrar por categoría',
  'filters.allCategories': 'Todas las categorías',
  'filters.status': 'Estado',
  'filters.byStatus': 'Filtrar por estado',
  'filters.allStatuses': 'Todos los estados',
  'filters.showing': 'Mostrando {shown} de {total} hallazgos',
  'filters.clear': 'Limpiar filtros',

  // Category labels (static UI labels for the category filter)
  'category.FIREWALL': 'Firewall',
  'category.ACCOUNTS': 'Seguridad de cuentas',
  'category.UPDATES': 'Actualizaciones del sistema',
  'category.NETWORK': 'Exposición de red',
  'category.ENDPOINT': 'Protección de endpoint',
  'category.SERVICES': 'Configuración de servicios',
  'category.BACKUP': 'Respaldo y recuperación',

  // Finding detail blocks
  'detail.evidence': 'Evidencia',
  'detail.noEvidence': 'Sin evidencia registrada',
  'detail.risk': 'Por qué importa',
  'detail.remediation': 'Remediación recomendada',
  'detail.verification': 'Verificación',

  // Finding row chrome
  'row.osTarget': 'SO objetivo: {os}',

  // AI explanation
  'ai.title': 'Explicación con IA',
  'ai.explain': 'Explicar con IA',
  'ai.loading': 'Explicando…',
  'ai.enableInSettings': 'Habilite las explicaciones con IA en Configuración',
  'ai.disabledError': 'Las explicaciones con IA están deshabilitadas. Actívelas primero en Configuración.',
  'ai.requestFailed': 'La solicitud de explicación con IA falló.',
  'ai.failedTitle': 'Error en la explicación con IA',
};

export default strings;
