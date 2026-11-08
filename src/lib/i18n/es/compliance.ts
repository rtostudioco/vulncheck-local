/** ES strings — compliance namespace (Compliance section). */
const strings: Record<string, string> = {
  // Tarjeta de sección
  'title': 'Evaluación de cumplimiento',
  'description':
    'Resultados de reglas agrupados por categoría — inspirado en conceptos CIS, no es una certificación CIS',

  // Estado vacío (aún sin datos)
  'empty.title': 'Sin datos de cumplimiento',
  'empty.description':
    'Ejecuta una auditoría para evaluar los resultados de reglas por categoría con referencias y evidencia.',

  // Banner de metodología y aviso CIS
  'methodology.title': 'Metodología y avisos',
  'methodology.text':
    'Cada regla versionada evalúa la evidencia recopilada y devuelve uno de estos resultados: PASS, FAIL, ' +
    'WARNING, NOT_APPLICABLE, NOT_ASSESSED o ERROR. Los fallos descuentan puntos de una puntuación de ' +
    'postura de 0–100 con pesos fijos (CRITICAL −25, HIGH −15, MEDIUM −7, LOW −3, INFO −0); WARNING ' +
    'descuenta la mitad del peso. La puntuación comienza en 100 y tiene un mínimo de 0. Las reglas que no ' +
    'pudieron evaluarse NO descuentan puntos; en su lugar, reducen la cobertura de evaluación, que se ' +
    'informa junto con la puntuación. Umbrales de calificación: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.',
  'methodology.disclaimer1':
    'VulnCheck Local realiza auditorías locales, de solo lectura y pasivas. Nunca modifica sistemas, nunca deshabilita servicios, nunca cambia la configuración del cortafuegos ni de las cuentas, y nunca recopila credenciales.',
  'methodology.disclaimer2':
    'La puntuación de postura de seguridad es un indicador interno y reproducible — NO es una puntuación oficial de cumplimiento.',
  'methodology.disclaimer3':
    'El conjunto de reglas está inspirado en conceptos documentados públicamente de los CIS Benchmarks, donde se documentan los requisitos técnicos. VulnCheck Local no está certificado por CIS y esta evaluación no constituye una declaración de cumplimiento CIS.',
  'methodology.disclaimer4':
    'Una inspección fallida o no compatible siempre se reporta como NOT_ASSESSED / ERROR y nunca se considera segura.',

  // Títulos de los grupos por categoría
  'category.FIREWALL': 'Cortafuegos',
  'category.ACCOUNTS': 'Seguridad de cuentas',
  'category.UPDATES': 'Actualizaciones del sistema',
  'category.NETWORK': 'Exposición de red',
  'category.ENDPOINT': 'Protección de endpoints',
  'category.SERVICES': 'Configuración de servicios',
  'category.BACKUP': 'Copias de seguridad y recuperación',
  'category.empty': 'No hay reglas registradas para esta categoría.',

  // Palabras de resumen aprobados/fallidos (se muestran como "{count} {label}")
  'summary.pass': 'aprobados',
  'summary.fail': 'fallidos',
  'summary.warn': 'advertencias',
  'summary.total': 'total',

  // Etiquetas de la fila expandida
  'evidence.label': 'Evidencia',
  'evidence.empty': 'Sin evidencia registrada',
};

export default strings;
