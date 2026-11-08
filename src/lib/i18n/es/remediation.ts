/** ES strings — remediation namespace (Remediation section). */
const strings: Record<string, string> = {
  // Tarjeta de sección
  'title': 'Plan de remediación',
  'description.one': '1 elemento requiere atención, ordenado por severidad',
  'description.other': '{count} elementos requieren atención, ordenados por severidad',

  // Estado vacío (aún sin datos)
  'empty.title': 'Sin datos de remediación',
  'empty.description':
    'Ejecuta una auditoría para generar recomendaciones de remediación para las verificaciones fallidas y con advertencia.',

  // Estado vacío (nada por remediación)
  'empty.allPassed.title': 'No se requieren remediaciones: todas las verificaciones evaluables pasaron',
  'empty.allPassed.description':
    'Toda regla que pudo evaluarse pasó, o no era aplicable a esta máquina.',

  // Etiquetas de los bloques de la tarjeta de remediación
  'card.problem': 'Problema',
  'card.whyItMatters': 'Por qué importa',
  'card.solution': 'Cómo corregirlo',
  'card.verify': 'Cómo verificarlo',
  'card.os': 'SO: {value}',
};

export default strings;
