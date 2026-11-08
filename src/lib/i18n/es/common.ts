/** ES shared strings: severity names, check statuses, audit states. */
const strings: Record<string, string> = {
  'severity.CRITICAL': 'Crítico',
  'severity.HIGH': 'Alto',
  'severity.MEDIUM': 'Medio',
  'severity.LOW': 'Bajo',
  'severity.INFO': 'Informativo',

  'status.PASS': 'Aprobado',
  'status.FAIL': 'Fallido',
  'status.WARNING': 'Advertencia',
  'status.NOT_APPLICABLE': 'No aplica',
  'status.NOT_ASSESSED': 'No evaluado',
  'status.ERROR': 'Error',

  'audit.RUNNING': 'En ejecución',
  'audit.COMPLETED': 'Completada',
  'audit.FAILED': 'Fallida',

  'lang.label': 'Idioma',

  // Navigation items
  'nav.overview': 'Resumen',
  'nav.inventory': 'Inventario del sistema',
  'nav.assessment': 'Evaluación de seguridad',
  'nav.findings': 'Hallazgos de vulnerabilidades',
  'nav.network': 'Exposición de red',
  'nav.compliance': 'Cumplimiento',
  'nav.remediation': 'Remediación',
  'nav.history': 'Historial de auditorías',
  'nav.reports': 'Informes',
  'nav.settings': 'Ajustes',

  // Shell (header, nav, alerts, footer)
  'shell.openNav': 'Abrir menú de navegación',
  'shell.navAria': 'Secciones del panel',
  'shell.nav.description': 'Secciones de auditoría de seguridad',
  'shell.runAudit': 'Ejecutar nueva auditoría',
  'shell.auditing': 'Auditando…',
  'shell.retry': 'Reintentar',
  'shell.error.meta': 'No se pudo cargar los metadatos de la aplicación',
  'shell.error.detail': 'No se pudo cargar el detalle de la sesión',
  'shell.error.poll': 'No se pudo consultar el estado de la auditoría',
  'shell.error.sessionStore': 'No se pudo leer el almacén local de sesiones',
  'shell.error.startAudit': 'No se pudo iniciar la auditoría',
  'shell.error.deleteSession': 'No fue posible eliminar la sesión',
  'shell.footer.guarantee':
    'VulnCheck Local v{version} — Auditoría de seguridad local. Inspección de solo lectura: sin cambios en el sistema ni recopilación de credenciales. Los datos nunca salen de esta máquina salvo que las explicaciones con IA se activen explícitamente en Ajustes.',
  'shell.footer.engine': 'Motor {version} · {rules} reglas versionadas',
  'shell.credit': '© {year} Ramon Taboada Olivella · RTO Studio',

  // Shell toasts (zustand store)
  'shell.toast.auditStarted': 'Auditoría iniciada',
  'shell.toast.auditStartedDesc':
    'Recopilando evidencia y evaluando reglas. El progreso en vivo se muestra en Evaluación de seguridad.',
  'shell.toast.auditCompleted': 'Auditoría completada',
  'shell.toast.auditCompletedDesc': 'Puntuación {score} · {count} hallazgos registrados',
  'shell.toast.auditFailed': 'Auditoría fallida',
  'shell.toast.auditFailedDesc':
    'La auditoría terminó con estado FALLIDA. Los errores de inspección se muestran por módulo en Evaluación de seguridad.',
  'shell.toast.alreadyRunning': 'Ya hay una auditoría en ejecución',
  'shell.toast.alreadyRunningDesc': 'Espera a que termine la auditoría actual antes de iniciar otra.',
  'shell.toast.startFailed': 'No se pudo iniciar la auditoría',
  'shell.toast.pollLost': 'Se perdió el seguimiento de la auditoría en ejecución',
  'shell.toast.loadSessionsFailed': 'No se pudieron cargar las sesiones de auditoría',
  'shell.toast.refreshFailed': 'No se pudieron actualizar las sesiones',
  'shell.toast.sessionDeleted': 'Sesión eliminada',
  'shell.toast.deleteFailed': 'No se pudo eliminar la sesión',
  'shell.toast.deletedOne': 'Se eliminó {count} sesión',
  'shell.toast.deletedMany': 'Se eliminaron {count} sesiones',
  'shell.toast.deleteFailedOne': 'No se pudo eliminar {count} sesión.',
  'shell.toast.deleteFailedMany': 'No se pudieron eliminar {count} sesiones.',
  'shell.toast.historyCleared': 'Historial de auditorías borrado.',

  // Audit module states
  'moduleState.OK': 'OK',
  'moduleState.PARTIAL': 'Parcial',
  'moduleState.UNAVAILABLE': 'No disponible',
  'moduleState.ERROR': 'Error',
};

export default strings;
