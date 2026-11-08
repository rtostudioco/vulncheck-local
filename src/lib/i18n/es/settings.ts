/** ES strings — settings namespace. */
const strings: Record<string, string> = {
  // Language card
  'language.desc': 'Idioma de la interfaz del panel.',

  // AI consent card
  'ai.title': 'Explicaciones con IA',
  'ai.subtitle': 'Opcional, desactivado de forma predeterminada',
  'ai.allow': 'Permitir explicaciones con IA para hallazgos individuales',
  'ai.hint': 'Cuando se activa, aparece un botón Explicar en cada hallazgo de Hallazgos de vulnerabilidades.',
  'ai.switchAria': 'Activar explicaciones con IA',

  // Retention card
  'retention.title': 'Retención de datos',
  'retention.subtitle': 'Cuánto tiempo se conservan las sesiones locales',
  'retention.label': 'Periodo de retención (días)',
  'retention.save': 'Guardar',
  'retention.range': 'Rango permitido: de {min} a {max} días. Las sesiones se almacenan localmente en SQLite.',

  // About card
  'about.title': 'Acerca de VulnCheck Local',
  'about.subtitle': 'Datos del motor y de la evaluación',
  'about.engineVersion': 'Versión del motor',
  'about.rules': 'Reglas versionadas',
  'about.platform': 'Plataforma detectada',
  'about.readOnly':
    'Inspección de solo lectura: sin cambios en el sistema ni recopilación de credenciales. Los datos nunca salen de esta máquina salvo que las explicaciones con IA se activen explícitamente.',
  'createdBy': 'Creado por Ramon Taboada Olivella',
  'studio': 'RTO Studio',

  // Project package card
  'download.title': 'Paquete del proyecto',
  'download.subtitle': 'Código fuente completo, listo para publicar',
  'download.desc':
    'Proyecto completo en un ZIP: código fuente, documentación, licencia y un repositorio git preparado (rama main, commit y tag v1.1.0 incluidos).',
  'download.btn': 'Descargar ZIP',
  'download.btnAria': 'Descargar paquete ZIP del proyecto',

  // Danger zone card
  'danger.title': 'Zona de riesgo',
  'danger.subtitle': 'Acciones de mantenimiento irreversibles',
  'danger.deleteAll': 'Eliminar todo el historial de auditorías',
  'danger.deleteAllHint.one':
    'Elimina de forma permanente {count} sesión registrada, incluidos los hallazgos y las puntuaciones. Los informes ya descargados no se ven afectados.',
  'danger.deleteAllHint.other':
    'Elimina de forma permanente {count} sesiones registradas, incluidos los hallazgos y las puntuaciones. Los informes ya descargados no se ven afectados.',
  'danger.deleteAllBtn': 'Eliminar todo el historial',
  'danger.confirmTitle': '¿Eliminar todo el historial de auditorías?',
  'danger.confirmDesc':
    'Todas las sesiones, hallazgos y puntuaciones almacenados en esta máquina se eliminarán de forma permanente. Esta acción no se puede deshacer.',
  'danger.cancel': 'Cancelar',
  'danger.confirm': 'Eliminar todo',

  // Toasts
  'toast.aiOn.title': 'Explicaciones con IA activadas',
  'toast.aiOn.desc': 'Ya puedes solicitar explicaciones por hallazgo en Hallazgos de vulnerabilidades.',
  'toast.aiOff.title': 'Explicaciones con IA desactivadas',
  'toast.aiOff.desc': 'No se enviarán datos de hallazgos al proveedor de IA.',
  'toast.aiFailed.title': 'No se pudo actualizar el consentimiento de IA',
  'toast.saveFailed.desc': 'No se pudo guardar la configuración.',
  'toast.invalidRetention.title': 'Valor de retención no válido',
  'toast.invalidRetention.desc': 'La retención debe ser un número entero entre {min} y {max} días.',
  'toast.retentionSaved.title': 'Retención actualizada',
  'toast.retentionSaved.desc': 'Las sesiones de más de {count} días se limpiarán automáticamente.',
  'toast.retentionFailed.title': 'No se pudo actualizar la retención',
  'ai.consentText': 'Las explicaciones con IA son opcionales y están desactivadas de forma predeterminada. Al activarlas, el botón Explicar de cada hallazgo envía únicamente los metadatos de ese hallazgo (categoría, título, descripción y un extracto de evidencia sanitizado y truncado) al proveedor de IA configurado. El inventario completo del sistema, los nombres de host, las direcciones y los conjuntos de evidencia nunca se transmiten automáticamente.',
  'about.methodologyText': 'Cada regla versionada evalúa la evidencia recopilada y devuelve uno de estos estados: PASS, FAIL, WARNING, NOT_APPLICABLE, NOT_ASSESSED o ERROR. Los fallos descuentan puntos de una puntuación de postura de 0\u2013100 con pesos fijos (CRITICAL \u221225, HIGH \u221215, MEDIUM \u22127, LOW \u22123, INFO \u22120); WARNING descuenta la mitad. La puntuación inicia en 100 y tiene piso 0. Las reglas que no pudieron evaluarse NO descuentan puntos; en su lugar reducen la cobertura de evaluación, que se informa junto a la puntuación. Umbrales de calificación: A \u2265 90, B \u2265 80, C \u2265 65, D \u2265 50, F < 50.',
  'about.disclaimer.1': 'VulnCheck Local realiza auditorías locales, de solo lectura y pasivas. Nunca modifica sistemas, nunca deshabilita servicios, nunca cambia la configuración de firewall o cuentas y nunca recopila credenciales.',
  'about.disclaimer.2': 'La puntuación de postura de seguridad es un indicador interno y reproducible: NO es una puntuación de cumplimiento oficial.',
  'about.disclaimer.3': 'El conjunto de reglas está inspirado en conceptos documentados públicamente de CIS Benchmarks donde los requisitos técnicos están documentados. VulnCheck Local no está certificado por CIS y esta evaluación no es una declaración de cumplimiento CIS.',
  'about.disclaimer.4': 'Una inspección fallida o no soportada siempre se reporta como NOT_ASSESSED / ERROR y nunca se cuenta como segura.',
};


export default strings;
