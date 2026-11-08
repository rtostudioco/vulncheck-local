/** ES strings — overview namespace (es-419 neutral, IT-security register). */
const strings: Record<string, string> = {
  // Audit in progress card
  'auditInProgressTitle': 'Auditoría en curso',
  'auditInProgressDescription': 'Recopilando evidencias y evaluando reglas. Esta vista se actualiza automáticamente.',
  'auditProgressAria': 'Progreso de la auditoría',
  'working': 'Trabajando…',

  // Empty / failed state
  'emptyTitle': 'Aún no se ha realizado ninguna auditoría',
  'emptyDescription': 'Ejecute su primera auditoría de seguridad local para puntuar este equipo, mostrar hallazgos y generar informes exportables.',
  'emptyFailedDescription': 'La última auditoría no se completó correctamente. Inicie una nueva auditoría para evaluar esta máquina.',
  'runFirstAudit': 'Ejecutar primera auditoría',

  // Hero — security posture
  'heroTitle': 'Postura de seguridad',
  'heroDescription': 'Resultado de la auditoría completada más reciente',
  'grade': 'Calificación',
  'coverage': 'Cobertura de evaluación',
  'findings': 'Hallazgos',
  'lastAudit': 'Última auditoría',
  'hostname': 'Nombre de host',
  'platform': 'Plataforma',

  // Severity summary
  'severityTitle': 'Resumen por severidad',
  'severityDescription': 'Haga clic en una severidad para abrir los hallazgos correspondientes',
  'viewFindingsAria': 'Ver hallazgos ({sev})',

  // Category posture
  'categoryTitle': 'Postura por categoría',
  'categoryDescription': 'Porcentaje de aprobación de las reglas evaluadas por categoría',
  'categoryAria': '{cat}: {pct}% aprobado',
  'failBadge': '{count} fallos',

  // Module health
  'moduleHealthTitle': 'Estado de los módulos',
  'moduleHealthDescription': 'Recopiladores de evidencia utilizados por la última auditoría',
  'moduleHealthEmpty': 'No hay datos de módulos disponibles.',
  'moduleStateSource': 'Estado: {state} · Fuente: {source}',

  // Limitations alert
  'limitationsTitle': 'Limitaciones de la evaluación',
};

export default strings;
