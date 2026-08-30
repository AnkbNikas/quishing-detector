# Informe de Análisis de Código QR

**Archivo analizado:** `qr_acortador.png`  
**Fecha de análisis (UTC):** 2026-08-30T11:35:11.607772+00:00  
**Códigos QR detectados:** 1

## Código 1

**Contenido decodificado:** `https://bit.ly/3xK9pQz`

🟢 **Nivel de riesgo: BAJO** (puntuación 2)

**Dominio de destino:** `bit.ly`

**Hallazgos:**
- Usa un acortador de enlaces (bit.ly) — oculta el destino final. Los QR no deberían necesitar acortar nada: el propio QR ya es la capa de indirección.

## ⚖️ Recomendaciones

- No introduzcas datos personales, bancarios o contraseñas tras escanear un QR en la vía pública (parquímetros, terrazas, papeletas de multa) sin verificar el dominio.
- Comprueba siempre la URL completa antes de continuar — iOS y Android ya muestran una vista previa del enlace antes de abrirlo.
- Ante la duda, accede al servicio oficial escribiendo la dirección directamente en el navegador, no a través del QR.

## Límites de este análisis

- Este análisis es **heurístico y estructural**, no consulta listas negras de phishing en tiempo real ni analiza el contenido de la web de destino.
- Una puntuación baja **no garantiza** que el enlace sea seguro; una puntuación alta no es una prueba definitiva de phishing, solo un conjunto de señales de alerta.

---

*Generado con qr_forense.py v1.0.0 — https://github.com/AnkbNikas/quishing-detector*