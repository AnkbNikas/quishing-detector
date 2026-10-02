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

VERSION = "1.0.0"

ACORTADORES = {
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd", "goo.gl", "ow.ly",
    "shorturl.at", "rebrand.ly", "buff.ly", "tiny.cc", "s.id", "rb.gy",
}

TLDS_SOSPECHOSOS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "work",
    "surf", "loan", "gd", "cam", "icu", "cyou",
}

# Esquemas que no navegan a una página web, sino que ejecutan código
# (javascript, vbscript), cargan contenido arbitrario sin red (data, blob),
# acceden al sistema de archivos (file) o lanzan una app con permisos
# propios (intent, en Android) — el riesgo no depende del dominio ni existe
# un "dominio" que comprobar.
ESQUEMAS_PELIGROSOS = {"javascript", "data", "vbscript", "file", "blob", "intent"}

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


def es_ip_decimal(host: str) -> bool:
    """Un entero de 32 bits sin signo escrito en decimal (p. ej. 2130706433,
    equivalente a 127.0.0.1)."""
    return bool(re.match(r"^\d+$", host)) and int(host) <= 0xFFFFFFFF


def es_ip_hexadecimal(host: str) -> bool:
    """Un entero de 32 bits sin signo escrito en hexadecimal con el prefijo
    '0x' (p. ej. 0x7f000001, equivalente a 127.0.0.1)."""
    return bool(re.match(r"^0[xX][0-9a-fA-F]+$", host)) and int(host, 16) <= 0xFFFFFFFF


def es_ip_octal(host: str) -> bool:
    """Cuatro octetos en octal, cada uno con un cero inicial (p. ej.
    0177.0.0.01, equivalente a 127.0.0.1). No se usa para los octetos
    normales de uno a tres dígitos sin cero inicial: esos ya los detecta la
    comprobación 2 en decimal."""
    octetos = host.split(".")
    return len(octetos) == 4 and all(re.match(r"^0[0-7]*$", octeto) for octeto in octetos)


def es_ipv6_literal(host: str) -> bool:
    """urlsplit() devuelve el host de una URL con una dirección IPv6 entre
    corchetes (p. ej. http://[::1]/) sin los corchetes, así que un ':' en
    el host solo puede significar eso."""
    return ":" in host


def ip_disfrazada_a_puntos(host: str) -> str:
    """Convierte una IP decimal, hexadecimal u octal disfrazada a su forma
    habitual con puntos, para mostrarla en el hallazgo."""
    if es_ip_octal(host):
        return ".".join(str(int(octeto, 8)) for octeto in host.split("."))
    valor = int(host, 16) if es_ip_hexadecimal(host) else int(host)
    return ".".join(str((valor >> desplazamiento) & 0xFF) for desplazamiento in (24, 16, 8, 0))


def decodificar_qr(path: Path):
    try:
        import cv2
    except ImportError as exc:
        raise RuntimeError(
            "OpenCV (paquete 'opencv-python') no está instalado. "
            "Instálalo con: pip install opencv-python"
        ) from exc

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


def normalizar_contenido_qr(texto: str) -> str:
    """Elimina los espacios en blanco del principio y el final del contenido
    decodificado del QR, antes de clasificarlo como URL o analizarlo."""
    return texto.strip()


def esquema_de(texto: str) -> str:
    """Devuelve el esquema de texto (lo anterior al primer ':'), en
    minúsculas, o una cadena vacía si no tiene ninguno."""
    coincide = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", texto)
    return coincide.group(1).lower() if coincide else ""


def es_url(texto: str) -> bool:
    return (bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", texto))
            or texto.lower().startswith("www.")
            or esquema_de(texto) in ESQUEMAS_PELIGROSOS)


def analizar_url(url: str):
    hallazgos = []
    puntuacion = 0

    # Esquemas peligrosos (javascript:, data:, vbscript:, file:, blob:,
    # intent:): no tienen autoridad ni host que analizar, así que se
    # puntúan aparte y se devuelve antes de normalizar nada.
    esquema_peligroso = esquema_de(url)
    if esquema_peligroso in ESQUEMAS_PELIGROSOS:
        return {
            "url": url,
            "dominio": "",
            "hallazgos": [f"Usa el esquema '{esquema_peligroso}:', que puede ejecutar código o cargar "
                         "contenido arbitrario en el dispositivo en vez de navegar a una página web."],
            "puntuacion_riesgo": 6,
        }

    url_normalizada = url if "://" in url else "http://" + url

    # Los navegadores leen "\" como "/" dentro de la autoridad de las URLs
    # http(s). Si no se corrige, urlsplit() puede quedarse con un host
    # distinto al que realmente visitaría el usuario — por ejemplo,
    # "https://evil.top\@dgt.es/" termina en el dominio oficial "dgt.es" en
    # vez de en "evil.top".
    contiene_backslash_antes_del_host = False
    coincide_esquema = re.match(r"^(https?)://(.*)$", url_normalizada, re.IGNORECASE)
    if coincide_esquema:
        esquema, resto = coincide_esquema.groups()
        autoridad_cruda = re.match(r"^[^/?#]*", resto).group(0)
        if "\\" in autoridad_cruda:
            contiene_backslash_antes_del_host = True
        url_normalizada = f"{esquema}://{resto.replace(chr(92), '/')}"

    try:
        partes = urllib.parse.urlsplit(url_normalizada)
        host = partes.hostname or ""
    except ValueError as exc:
        return {
            "url": url,
            "dominio": "",
            "hallazgos": [f"URL malformada o no analizable: {exc}"],
            "puntuacion_riesgo": 0,
        }

    if not host:
        return {
            "url": url,
            "dominio": "",
            "hallazgos": ["URL malformada o no analizable: no contiene ningún host."],
            "puntuacion_riesgo": 0,
        }

    # Host con secuencias de escape porcentual (p. ej. "%70aypal.evil.com",
    # "bit.l%79"): se decodifica antes de las comprobaciones de host, igual
    # que hacen los navegadores con las secuencias %XX de la URL.
    host_sin_decodificar = host
    host = urllib.parse.unquote(host)
    contiene_escapes_en_host = host != host_sin_decodificar

    # Un único punto final en el host ("bit.ly.", "evil.top.") es la forma
    # habitual de referirse a la raíz del DNS; se analiza como si no
    # estuviera, igual que hacen los navegadores.
    if host.endswith(".") and host != ".":
        host = host[:-1]

    # Host en Unicode (homógrafos, cirílico, ancho completo...): se
    # convierte a su forma Punycode con el códec "idna" de la librería
    # estándar (IDNA 2003) antes de las comprobaciones de host, para que un
    # dominio como "pаypal.com" (con una "а" cirílica) llegue a la
    # comprobación de Punycode igual que si ya viniera escrito "xn--...".
    # Si la codificación falla, se sigue analizando con el host ya
    # decodificado, sin interrumpir el análisis.
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    if contiene_escapes_en_host:
        hallazgos.append("El host contenía secuencias de escape porcentual — se ha decodificado "
                         f"a «{host}» antes de analizarlo, igual que hacen los navegadores.")

    if contiene_backslash_antes_del_host:
        hallazgos.append("Contiene '\\' antes del host — los navegadores lo interpretan como '/', "
                         "lo que trunca la autoridad igual que el truco de '@'.")
        puntuacion += 4

    # 1. Truco @ (todo lo anterior al @ se ignora en la barra de navegación)
    if "@" in partes.netloc:
        hallazgos.append("Contiene '@' en la URL — todo lo anterior al símbolo se ignora al navegar; "
                         "técnica clásica para simular un dominio de confianza.")
        puntuacion += 4

    # 2. IP en vez de dominio
    es_ip_en_puntos = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    if es_ip_en_puntos:
        hallazgos.append(f"El destino es una dirección IP ({host}) en lugar de un nombre de dominio.")
        puntuacion += 3

    # 9. IP disfrazada en decimal, hexadecimal, octal o como literal IPv6,
    # para no dejar sin puntuar las formas alternativas de escribir una IP
    # que evitan la comprobación 2. No se suma a la 2: una IP solo puede
    # tener una de las dos formas (en puntos o disfrazada), nunca ambas.
    es_ip_disfrazada = not es_ip_en_puntos and (
        es_ip_decimal(host) or es_ip_hexadecimal(host) or es_ip_octal(host) or es_ipv6_literal(host)
    )
    if es_ip_disfrazada:
        if es_ipv6_literal(host):
            hallazgos.append(f"El destino es una dirección IPv6 ({host}) en lugar de un nombre de dominio.")
        else:
            hallazgos.append(f"El destino es una IP disfrazada como '{host}' — equivale a "
                             f"{ip_disfrazada_a_puntos(host)} en lugar de un nombre de dominio.")
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
    # La ruta y la query se decodifican antes de buscar las palabras, igual
    # que el host, para detectar términos ocultos tras un escape porcentual
    # (p. ej. "/%70ago" en vez de "/pago").
    ruta_completa = urllib.parse.unquote(partes.path + "?" + partes.query).lower()
    palabras_alerta = ["pago", "payment", "multa", "fine", "verify", "verifica", "urgente",
                       "suspend", "bloqueo", "actualiza", "confirm", "aduana", "tasa"]
    encontradas = [p for p in palabras_alerta if p in ruta_completa or p in host_sin_tld]
    if encontradas:
        # encontradas ya respeta el orden de palabras_alerta, así que el
        # resultado es el mismo en cada ejecución (antes se perdía ese orden
        # al pasar por un set(), cuyo recorrido depende del hash aleatorio).
        hallazgos.append(f"Contiene términos asociados a presión/urgencia: {', '.join(encontradas)}.")
        puntuacion += 1

    # 10. Esquema sin cifrar (http). No se puntúa si el propio script fue
    # quien añadió "http://" por no haber ningún esquema en el contenido
    # original (una URL "www.ejemplo.com" o sin www tampoco diría nada
    # sobre el cifrado), ni si el destino ya es una IP, puntuada aparte en
    # la comprobación 2 o la 9.
    if (partes.scheme.lower() == "http" and bool(re.match(r"^http://", url, re.IGNORECASE))
            and not es_ip_en_puntos and not es_ip_disfrazada):
        hallazgos.append("Usa 'http://' sin cifrar — los datos viajan sin proteger y cualquiera en la "
                         "misma red puede leerlos o modificarlos.")
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
    contenidos = [normalizar_contenido_qr(c) for c in decodificar_qr(path)]

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
