# Informe de Análisis de Código QR

**Archivo analizado:** `qr_suplantacion.png`  
**Fecha de análisis (UTC):** 2026-08-30T11:35:12.150907+00:00  
**Códigos QR detectados:** 1

## Código 1

**Contenido decodificado:** `https://dgt-multas-pago.es/tasa?id=88213`

🔴 **Nivel de riesgo: ALTO** (puntuación 6)

**Dominio de destino:** `dgt-multas-pago.es`

**Hallazgos:**
- El dominio menciona 'dgt' pero no coincide con ningún dominio oficial conocido (dgt.es, sede.dgt.gob.es). Posible suplantación de marca.
- Contiene términos asociados a presión/urgencia: tasa, multa, pago.

## ⚖️ Recomendaciones

- No introduzcas datos personales, bancarios o contraseñas tras escanear un QR en la vía pública (parquímetros, terrazas, papeletas de multa) sin verificar el dominio.
- Comprueba siempre la URL completa antes de continuar — iOS y Android ya muestran una vista previa del enlace antes de abrirlo.
- Ante la duda, accede al servicio oficial escribiendo la dirección directamente en el navegador, no a través del QR.

## Límites de este análisis

- Este análisis es **heurístico y estructural**, no consulta listas negras de phishing en tiempo real ni analiza el contenido de la web de destino.
- Una puntuación baja **no garantiza** que el enlace sea seguro; una puntuación alta no es una prueba definitiva de phishing, solo un conjunto de señales de alerta.

---

*Generado con qr_forense.py v1.0.0 — https://github.com/AnkbNikas/quishing-detector*