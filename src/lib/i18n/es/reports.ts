/** ES strings — reports namespace (export reports + report history). */
const strings: Record<string, string> = {
  'title': 'Reportes',
  'subtitle.ready': 'Genera un reporte para la auditoría completada seleccionada',
  'subtitle.select':
    'Selecciona una auditoría completada (desde el Historial de auditorías) para habilitar las descargas',
  'note.disabled': 'Ejecuta una auditoría o carga una sesión completada para habilitar la descarga de reportes.',

  'format.pdf.title': 'Reporte PDF',
  'format.pdf.description':
    'Reporte profesional multipágina: resumen ejecutivo, hallazgos por severidad, evidencia, remediación y limitaciones',
  'format.json.title': 'Exportación JSON',
  'format.json.description': 'Detalle completo de la sesión en formato legible por máquinas',
  'format.csv.title': 'Exportación CSV',
  'format.csv.description': 'Tabla de hallazgos para hojas de cálculo',

  'action.download': 'Descargar {format}',
  'action.refresh': 'Actualizar',

  'toast.started.title': 'Generación de reporte iniciada',
  'toast.started.description': 'La descarga comenzará automáticamente cuando el reporte esté listo.',
  'toast.failed.title': 'Error al descargar',
  'toast.failed.description': 'No se pudo generar el reporte.',

  'history.title': 'Historial de exportaciones',
  'history.subtitle': 'Reportes generados previamente en este equipo',

  'error.title': 'No se pudo cargar el historial de reportes',
  'error.fallback': 'Error al cargar el historial de reportes',

  'col.generated': 'Generado',
  'col.format': 'Formato',
  'col.file': 'Archivo',
  'col.sessionDate': 'Fecha de sesión',
  'col.score': 'Puntuación',

  'empty.title': 'Aún no hay reportes generados',
  'empty.description': 'Los reportes PDF, JSON y CSV descargados se listan aquí.',

  'aria.refresh': 'Actualizar historial de reportes',
};

export default strings;
