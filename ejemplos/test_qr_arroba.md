# Informe de Análisis de Código QR

**Archivo analizado:** `qr_arroba.png`  
**Fecha de análisis (UTC):** 2026-08-30T11:35:11.744933+00:00  
**Códigos QR detectados:** 1

## Código 1

**Contenido decodificado:** `https://dgt.es@pagos-seguros.top/verifica`

🔴 **Nivel de riesgo: ALTO** (puntuación 6)

**Dominio de destino:** `pagos-seguros.top`

**Hallazgos:**
- Contiene '@' en la URL — todo lo anterior al símbolo se ignora al navegar; técnica clásica para simular un dominio de confianza.
- Dominio de nivel superior (.top) usado con frecuencia en campañas de phishing por su bajo coste y falta de verificación de identidad.
- Contiene términos asociados a presión/urgencia: pago, verifica.

## ⚖️ Recomendaciones

- No introduzcas datos personales, bancarios o contraseñas tras escanear un QR en la vía pública (parquímetros, terrazas, papeletas de multa) sin verificar el dominio.
- Comprueba siempre la URL completa antes de continuar — iOS y Android ya muestran una vista previa del enlace antes de abrirlo.
- Ante la duda, accede al servicio oficial escribiendo la dirección directamente en el navegador, no a través del QR.

## Límites de este análisis

- Este análisis es **heurístico y estructural**, no consulta listas negras de phishing en tiempo real ni analiza el contenido de la web de destino.
- Una puntuación baja **no garantiza** que el enlace sea seguro; una puntuación alta no es una prueba definitiva de phishing, solo un conjunto de señales de alerta.

---

*Generado con qr_forense.py v1.0.0 — https://github.com/AnkbNikas/quishing-detector*