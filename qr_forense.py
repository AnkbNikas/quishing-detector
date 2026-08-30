#!/usr/bin/env python3
"""
qr_forense.py — Analizador de riesgo de phishing en códigos QR ("quishing")

Decodifica un código QR a partir de una imagen y analiza el contenido en
busca de indicios de phishing, SIN visitar nunca la URL (análisis
100% estático y offline por defecto).

España concentra el 17% de las estafas de código QR a nivel mundial
(ESET Threat Report H1 2026) — pegatinas falsas sobre parquímetros,
cartas de restaurante y avisos de paquetería son los vectores más comunes.

Autora: Nieves Casquero — Perito Informático de Parte (Colegiada AEPEJU)
Licencia: MIT
"""

import argparse
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import cv2

VERSION = "1.0.0"

ACORTADORES = {
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd", "goo.gl", "ow.ly",
    "shorturl.at", "rebrand.ly", "buff.ly", "tiny.cc", "s.id", "rb.gy",
}

TLDS_SOSPECHOSOS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "work",
    "surf", "loan", "gd", "cam", "icu", "cyou",
}

MARCAS_HABITUALMENTE_SUPLANTADAS = {
    "correos": ["correos.es"],
    "dgt": ["dgt.es", "sede.dgt.gob.es"],
    "paypal": ["paypal.com", "paypal.es"],
    "bbva": ["bbva.es"],
    "santander": ["bancosantander.es", "santander.es"],
    "caixabank": ["caixabank.es"],
    "correosexpress": ["correosexpress.com"],
    "seur": ["seur.com"],
    "dhl": ["dhl.com", "dhl.es"],
    "sabadell": ["bancsabadell.com", "bancosabadell.com"],
    "endesa": ["endesa.com"],
    "iberdrola": ["iberdrola.es", "iberdrola.com"],
    "renfe": ["renfe.com"],
    "dgtmultas": ["dgt.es"],
    "wallapop": ["wallapop.com"],
}


def decodificar_qr(path: Path):
    img = cv2.imread(str(path))
    if img is None:
        raise ValueError("No se ha podido leer la imagen. Formatos soportados: JPG, PNG, BMP.")

    detector = cv2.QRCodeDetector()
    retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
    resultados = [d for d in decoded_info if d] if retval else []

    if not resultados:
        data, _, _ = detector.detectAndDecode(img)
        if data:
            resultados = [data]

    return resultados


def es_url(texto: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", texto)) or texto.lower().startswith("www.")


def analizar_url(url: str):
    hallazgos = []
    puntuacion = 0

    url_normalizada = url if "://" in url else "http://" + url
    partes = urllib.parse.urlsplit(url_normalizada)
    host = partes.hostname or ""

    # 1. Truco @ (todo lo anterior al @ se ignora en la barra de navegación)
    if "@" in partes.netloc:
        hallazgos.append("Contiene '@' en la URL — todo lo anterior al símbolo se ignora al navegar; "
                         "técnica clásica para simular un dominio de confianza.")
        puntuacion += 4

    # 2. IP en vez de dominio
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        hallazgos.append(f"El destino es una dirección IP ({host}) en lugar de un nombre de dominio.")
        puntuacion += 3

    # 3. Punycode / homógrafos
    if host.startswith("xn--") or ".xn--" in host:
        hallazgos.append("El dominio usa codificación Punycode (xn--) — puede ocultar caracteres "
                         "que imitan visualmente a un dominio legítimo (ataque homógrafo).")
        puntuacion += 3

    # 4. Acortadores
    dominio_base = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    if host in ACORTADORES or dominio_base in ACORTADORES:
        hallazgos.append(f"Usa un acortador de enlaces ({host}) — oculta el destino final. "
                         "Los QR no deberían necesitar acortar nada: el propio QR ya es la capa de indirección.")
        puntuacion += 2

    # 5. TLD sospechoso
    tld = host.split(".")[-1] if "." in host else ""
    if tld in TLDS_SOSPECHOSOS:
        hallazgos.append(f"Dominio de nivel superior (.{tld}) usado con frecuencia en campañas de phishing "
                         "por su bajo coste y falta de verificación de identidad.")
        puntuacion += 1

    # 6. Suplantación de marca conocida
    host_sin_tld = host.lower()
    for marca, dominios_oficiales in MARCAS_HABITUALMENTE_SUPLANTADAS.items():
        if marca in host_sin_tld and not any(host_sin_tld == d or host_sin_tld.endswith("." + d) for d in dominios_oficiales):
            hallazgos.append(f"El dominio menciona '{marca}' pero no coincide con ningún dominio oficial "
                             f"conocido ({', '.join(dominios_oficiales)}). Posible suplantación de marca.")
            puntuacion += 5

    # 7. Exceso de subdominios / guiones / dígitos
    if host.count(".") >= 4:
        hallazgos.append(f"El dominio tiene un número inusualmente alto de subniveles ({host}).")
        puntuacion += 1
    if host.count("-") >= 3:
        hallazgos.append(f"El dominio contiene numerosos guiones ({host}), un patrón común en dominios "
                         "generados automáticamente para phishing.")
        puntuacion += 1

    # 8. Palabras de urgencia/pago en la ruta (parking, multas, paquetería...)
    ruta_completa = (partes.path + "?" + partes.query).lower()
    palabras_alerta = ["pago", "payment", "multa", "fine", "verify", "verifica", "urgente",
                       "suspend", "bloqueo", "actualiza", "confirm", "aduana", "tasa"]
    encontradas = [p for p in palabras_alerta if p in ruta_completa or p in host_sin_tld]
    if encontradas:
        hallazgos.append(f"Contiene términos asociados a presión/urgencia: {', '.join(set(encontradas))}.")
        puntuacion += 1

    if not hallazgos:
        hallazgos.append("No se han detectado patrones sospechosos estructurales en la URL.")

    return {
        "url": url,
        "dominio": host,
        "hallazgos": hallazgos,
        "puntuacion_riesgo": puntuacion,
    }


def consultar_whois(host: str):
    """Función opcional: requiere conexión a internet en el equipo donde se
    ejecute. Si no hay red o el paquete no está instalado, se omite sin
    interrumpir el análisis."""
    try:
        import whois
        w = whois.whois(host)
        fecha_creacion = w.creation_date
        if isinstance(fecha_creacion, list):
            fecha_creacion = fecha_creacion[0]
        if fecha_creacion is None:
            return None
        antiguedad_dias = (datetime.now() - fecha_creacion.replace(tzinfo=None)).days
        return {"fecha_creacion": str(fecha_creacion), "antiguedad_dias": antiguedad_dias}
    except Exception:
        return None


def clasificar_riesgo(puntuacion: int) -> str:
    if puntuacion >= 6:
        return "ALTO"
    if puntuacion >= 3:
        return "MEDIO"
    return "BAJO"


def construir_informe(path, contenidos, analisis_urls, whois_info):
    lines = []
    lines.append("# Informe de Análisis de Código QR\n")
    lines.append(f"**Archivo analizado:** `{path.name}`  ")
    lines.append(f"**Fecha de análisis (UTC):** {datetime.now(timezone.utc).isoformat()}  ")
    lines.append(f"**Códigos QR detectados:** {len(contenidos)}\n")

    if not contenidos:
        lines.append("⚠️ No se ha podido decodificar ningún código QR en la imagen.")
        return "\n".join(lines)

    for i, contenido in enumerate(contenidos, start=1):
        lines.append(f"## Código {i}\n")
        lines.append(f"**Contenido decodificado:** `{contenido}`\n")

        if contenido in analisis_urls:
            analisis = analisis_urls[contenido]
            riesgo = clasificar_riesgo(analisis["puntuacion_riesgo"])
            emoji = {"ALTO": "🔴", "MEDIO": "🟠", "BAJO": "🟢"}[riesgo]
            lines.append(f"{emoji} **Nivel de riesgo: {riesgo}** (puntuación {analisis['puntuacion_riesgo']})\n")
            lines.append(f"**Dominio de destino:** `{analisis['dominio']}`\n")
            lines.append("**Hallazgos:**")
            for h in analisis["hallazgos"]:
                lines.append(f"- {h}")

            wi = whois_info.get(contenido)
            if wi:
                lines.append(f"\n**Antigüedad del dominio (WHOIS):** {wi['antiguedad_dias']} días "
                             f"(creado: {wi['fecha_creacion']})")
                if wi["antiguedad_dias"] < 90:
                    lines.append("🔴 Dominio registrado muy recientemente — indicio adicional de riesgo.")
        else:
            lines.append("_Contenido no interpretado como URL (texto plano, red WiFi, tarjeta de "
                         "contacto u otro formato). No se aplica el análisis de phishing._")
        lines.append("")

    lines.append("## ⚖️ Recomendaciones\n")
    lines.append("- No introduzcas datos personales, bancarios o contraseñas tras escanear un QR "
                 "en la vía pública (parquímetros, terrazas, papeletas de multa) sin verificar el dominio.")
    lines.append("- Comprueba siempre la URL completa antes de continuar — iOS y Android ya muestran "
                 "una vista previa del enlace antes de abrirlo.")
    lines.append("- Ante la duda, accede al servicio oficial escribiendo la dirección directamente "
                 "en el navegador, no a través del QR.")

    lines.append("\n## Límites de este análisis\n")
    lines.append("- Este análisis es **heurístico y estructural**, no consulta listas negras de "
                 "phishing en tiempo real ni analiza el contenido de la web de destino.")
    lines.append("- Una puntuación baja **no garantiza** que el enlace sea seguro; una puntuación alta "
                 "no es una prueba definitiva de phishing, solo un conjunto de señales de alerta.")

    lines.append("\n---\n")
    lines.append(f"*Generado con qr_forense.py v{VERSION} — "
                 "https://github.com/AnkbNikas/quishing-detector*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        prog="qr_forense",
        description="Analiza el riesgo de phishing (quishing) de un código QR sin visitarlo nunca."
    )
    parser.add_argument("imagen", help="Imagen (JPG/PNG) que contiene el código QR")
    parser.add_argument("--salida", default="informe_qr", help="Nombre base de los ficheros de salida")
    parser.add_argument("--whois", action="store_true",
                         help="Consulta la antigüedad del dominio vía WHOIS (requiere internet)")
    args = parser.parse_args()

    path = Path(args.imagen)
    if not path.exists():
        print(f"Error: el archivo '{args.imagen}' no existe.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Leyendo código QR de: {path}")
    contenidos = decodificar_qr(path)

    if not contenidos:
        print("[!] No se ha podido decodificar ningún código QR en la imagen.")

    analisis_urls = {}
    whois_info = {}
    for contenido in contenidos:
        print(f"[*] Contenido detectado: {contenido}")
        if es_url(contenido):
            analisis_urls[contenido] = analizar_url(contenido)
            riesgo = clasificar_riesgo(analisis_urls[contenido]["puntuacion_riesgo"])
            print(f"    -> Riesgo: {riesgo}")
            if args.whois:
                host = analisis_urls[contenido]["dominio"]
                print(f"[*] Consultando WHOIS de {host}...")
                info = consultar_whois(host)
                if info:
                    whois_info[contenido] = info
                else:
                    print("    -> No se pudo obtener información WHOIS (sin red o dominio no soportado).")

    informe = construir_informe(path, contenidos, analisis_urls, whois_info)

    md_path = Path(f"{args.salida}.md")
    md_path.write_text(informe, encoding="utf-8")

    json_path = Path(f"{args.salida}.json")
    json_path.write_text(json.dumps({
        "archivo": str(path),
        "contenidos_detectados": contenidos,
        "analisis_urls": analisis_urls,
        "whois": whois_info,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Informe Markdown: {md_path}")
    print(f"[+] Datos JSON:       {json_path}")


if __name__ == "__main__":
    main()
