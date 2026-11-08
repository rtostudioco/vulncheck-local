/** ES strings — history namespace (audit history section). */
const strings: Record<string, string> = {
  'title': 'Historial de auditorías',
  'subtitle': 'Más recientes primero — se conservan hasta 25 sesiones',

  'empty.title': 'No hay sesiones todavía',
  'empty.description': 'Las auditorías completadas aparecen aquí con su puntuación, calificación y cobertura.',

  'col.date': 'Fecha',
  'col.platform': 'Plataforma',
  'col.score': 'Puntuación',
  'col.grade': 'Calificación',
  'col.findings': 'Hallazgos',
  'col.coverage': 'Cobertura',
  'col.status': 'Estado',
  'col.actions': 'Acciones',

  'action.load': 'Cargar',

  'delete.title': '¿Eliminar esta auditoría?',
  'delete.description':
    'La sesión, sus hallazgos y su puntuación se eliminarán permanentemente del almacenamiento local. Esta acción no se puede deshacer.',
  'delete.cancel': 'Cancelar',
  'delete.confirm': 'Eliminar',

  'aria.deleteSession': 'Eliminar sesión del {date}',

  'retention': 'Las sesiones se almacenan localmente en SQLite. Retención: {days} días (ajustable en Configuración).',
};

export default strings;
