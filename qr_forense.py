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
import types
import unicodedata
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

# Palabras de urgencia/pago en otros idiomas, en un bloque independiente por
# idioma (código ISO 639-1), para extender la comprobación 8 a avisos
# fraudulentos que no están en español. Cada palabra es un hecho tomado de
# una fuente lexicográfica de ese idioma, nunca una cita textual de su
# definición.
PALABRAS_ALERTA_POR_IDIOMA = {
    # Checo. Fuente: Internetová jazyková příručka, Ústav pro jazyk český AV
    # ČR (prirucka.ujc.cas.cz), consultada el 2026-09-24.
    "cs": [
        # nedoplatek: importe pendiente de pago, lo que queda por abonar
        # (entrada "nedoplatek", SSČ y SSJČ).
        "nedoplatek",
        # neuhrazen: raíz de "neuhrazený" (no abonado, impagado; negación de
        # la entrada "uhrazený"), para que también coincida con sus formas
        # flexionadas (p. ej. "neuhrazená", "neuhrazeno"), no solo con la
        # forma de diccionario.
        "neuhrazen",
        # zablokovan: raíz de "zablokovaný" (bloqueado; entrada
        # "zablokovaný"), para que también coincida con sus formas
        # flexionadas (p. ej. "zablokovaná", "zablokováno"), no solo con la
        # forma de diccionario.
        "zablokovan",
    ],
    # Danés. Fuentes: Den Danske Ordbog, Det Danske Sprog- og
    # Litteraturselskab (ordnet.dk/ddo), consultada el 2026-09-24; y
    # Forbrugerombudsmanden, forbrug.dk, "Betalingsfrister - regninger",
    # consultada el 2026-09-24.
    "da": [
        # betalingsfrist: plazo de pago de una factura (fuente
        # Forbrugerombudsmanden anterior).
        "betalingsfrist",
        # forfaldsdato: fecha de vencimiento de una factura (misma fuente).
        "forfaldsdato",
        # rykkergebyr: recargo por una carta de aviso de pago (entrada
        # "rykkergebyr", ordnet.dk/ddo).
        "rykkergebyr",
        # spærret: bloqueado, p. ej. una cuenta o una tarjeta (entrada
        # "spærre", ordnet.dk/ddo).
        "spærret",
        # ubetalt: impagado (entrada "ubetalt", ordnet.dk/ddo).
        "ubetalt",
    ],
    # Alemán. Fuente: DWDS (Digitales Wörterbuch der deutschen Sprache),
    # dwds.de, consultada el 2026-09-24.
    "de": [
        # bussgeld: Bußgeld, multa administrativa (ß→ss; entrada "Bußgeld",
        # DWDS).
        "bussgeld",
        # gesperrt: bloqueado, p. ej. una cuenta o una tarjeta bancaria
        # (entrada "gesperrt", DWDS).
        "gesperrt",
        # mahngebuehr: Mahngebühr, recargo por un aviso oficial de impago
        # (entrada "Mahngebühr", DWDS), con la "ü" escrita según la grafía
        # alemana "ue".
        "mahngebuehr",
        # mahngebuhr: la misma palabra, con la diéresis simplemente omitida
        # en vez de sustituida por "ue" — ninguna de las dos grafías se
        # reduce a la otra al plegar diacríticos, así que se incluyen ambas.
        "mahngebuhr",
        # saeumniszuschlag: Säumniszuschlag, recargo por demora en el pago
        # de un impuesto (entrada "Säumniszuschlag", DWDS), con la "ä"
        # escrita según la grafía alemana "ae".
        "saeumniszuschlag",
        # saumniszuschlag: la misma palabra, con la diéresis simplemente
        # omitida en vez de sustituida por "ae".
        "saumniszuschlag",
        # zahlungsruckstand: Zahlungsrückstand, atraso en el pago (entrada
        # "Zahlungsrückstand", DWDS), con la diéresis de la "ü" omitida.
        "zahlungsruckstand",
        # zahlungsrueckstand: la misma palabra, con la "ü" escrita según la
        # grafía alemana "ue".
        "zahlungsrueckstand",
        # zahlungsverzug: mora en el pago (entrada "Zahlungsverzug", DWDS).
        "zahlungsverzug",
        # zollgebuehr: Zollgebühr, tasa aduanera (entrada "Zollgebühr",
        # DWDS), con la "ü" escrita según la grafía alemana "ue".
        "zollgebuehr",
        # zollgebuhr: la misma palabra, con la diéresis simplemente omitida.
        "zollgebuhr",
    ],
    # Estonio. Fuente: Eesti keele seletav sõnaraamat (EKSS) 2009, Eesti Keele
    # Instituut (arhiiv.eki.ee/dict/ekss), consultada el 2026-09-24. Ninguna
    # de estas cinco palabras lleva diacrítico en su grafía habitual.
    "et": [
        # blokeeritud: bloqueado (entrada "blokeeritud").
        "blokeeritud",
        # maksmata: impagado, sin pagar (forma abesiva de "maksma" dada en la
        # entrada "maksma").
        "maksmata",
        # tollimaks: arancel, tasa aduanera (entrada "tollimaks").
        "tollimaks",
        # trahv: multa (entrada "trahv").
        "trahv",
        # viivis: recargo por demora en el pago (entrada "viivis").
        "viivis",
    ],
    # Finés. Fuentes: Kilpailu- ja kuluttajavirasto (kkv.fi), Finlex
    # (finlex.fi) junto con Poliisi (poliisi.fi), y Tulli (tulli.fi),
    # consultadas el 2026-09-24. Solo "eräpäivä" lleva diacrítico en su
    # grafía habitual.
    "fi": [
        # eräpäivä: fecha límite de pago de una factura, tras la cual se
        # aplican intereses de demora y recargos de cobro
        # (Kilpailu- ja kuluttajavirasto, kkv.fi).
        "eräpäivä",
        # maksamaton: una factura no abonada dentro de su plazo (misma
        # fuente).
        "maksamaton",
        # rikesakko: multa administrativa fija impuesta por una infracción
        # menor, con derecho a recurrirla ante el tribunal de distrito en el
        # plazo de una semana (Finlex, leyes 754/2010 y 986/2016, junto con
        # Poliisi).
        "rikesakko",
        # tullimaksu: arancel o tasa aduanera sobre mercancías que cruzan la
        # frontera aduanera (Tulli, tulli.fi).
        "tullimaksu",
    ],
    # Francés. Fuentes: CNRTL, Portail lexical (cnrtl.fr), y Larousse,
    # Dictionnaire de français (larousse.fr), consultadas el 2026-09-24. Se
    # excluye DELIBERADAMENTE "pénalité" (sanción, recargo por demora en el
    # pago; entrada "pénalité", Larousse y Le Robert), no por un olvido: es
    # también la palabra corriente para una sanción deportiva (p. ej. un
    # penalti o una pénalité de rugby en una crónica de deporte), un uso
    # habitual y ajeno a los avisos de pago que esta lista busca, con el que
    # colisionaría con demasiada frecuencia en contenido benigno.
    "fr": [
        # douane: aduana (entrada "douane", CNRTL y Larousse).
        "douane",
        # impayé: no abonado, impagado (entrada "impayé", Larousse y CNRTL).
        "impayé",
    ],
    # Croata. Fuente: Hrvatski jezični portal (hjp.znanje.hr), consultada el
    # 2026-09-24. Ninguna de estas tres palabras lleva diacrítico en su
    # grafía habitual.
    "hr": [
        # blokiran: bloqueado (entrada "blokirati").
        "blokiran",
        # kazna: multa, sanción económica impuesta por una infracción
        # (entrada "kazna").
        "kazna",
        # ovrha: ejecución forzosa de una deuda, embargo (entrada "ovrha").
        "ovrha",
    ],
    # Húngaro. Fuente: A magyar nyelv értelmező szótára, vía Arcanum
    # (arcanum.com) y WikiSzótár (wikiszotar.hu), consultada el 2026-09-24.
    "hu": [
        # bírság: multa o sanción económica (entrada "bírság").
        "bírság",
        # felszólítás: requerimiento o aviso oficial para que alguien haga
        # algo (entrada "felszólítás", acepción 2).
        "felszólítás",
        # hátralék: atraso o saldo pendiente de pago (entrada "hátralék").
        "hátralék",
        # vámdíj: arancel aduanero (entrada "vámdíj").
        "vámdíj",
    ],
    # Italiano. Fuente: Treccani, Vocabolario on line (treccani.it/vocabolario),
    # consultada el 2026-09-24. Solo "morosità" lleva diacrítico en su grafía
    # habitual.
    "it": [
        # bloccato: bloqueado, p. ej. una cuenta o un depósito bancario
        # (entrada "bloccare").
        "bloccato",
        # dogana: aduana (entrada "dogana").
        "dogana",
        # ingiunzione: requerimiento, orden de un órgano judicial o
        # administrativo para cumplir una obligación, incluidas las órdenes
        # de pago (entrada "ingiunzione").
        "ingiunzione",
        # morosità: morosidad, impago (entrada "morosità").
        "morosità",
    ],
    # Lituano. Fuentes: Valstybinė mokesčių inspekcija (vmi.lt) y Lietuvos
    # Respublikos finansų ministerija (finmin.lrv.lt), consultadas el
    # 2026-09-24. Solo "užblokuota" lleva diacrítico en su grafía habitual.
    "lt": [
        # delspinigiai: recargo financiero por un impuesto no pagado o pagado
        # con retraso, a un tipo fijado por el ministro de Hacienda (vmi.lt y
        # finmin.lrv.lt, entradas sobre delspinigiai).
        "delspinigiai",
        # nuobauda: sanción impuesta por una infracción administrativa o penal
        # (vmi.lt, baudos por infracciones administrativas).
        "nuobauda",
        # užblokuota: cuenta bloqueada por la inspección tributaria al cobrar
        # una deuda (vmi.lt/evmi/5257).
        "užblokuota",
    ],
    # Neerlandés. Fuentes: Woorden.org (woorden.org) y Van Dale Groot
    # woordenboek der Nederlandse taal, vía Ensie (ensie.nl), consultadas el
    # 2026-09-24. Ninguna de estas seis palabras lleva diacrítico en su
    # grafía habitual.
    "nl": [
        # aanmaning: requerimiento formal de pago, aviso de que una factura
        # sigue sin abonarse (entrada "aanmaning", Woorden.org y Ensie/Van
        # Dale).
        "aanmaning",
        # achterstallig: atrasado, con el pago pendiente o fuera de plazo
        # (entrada "achterstallig", Woorden.org).
        "achterstallig",
        # boete: multa, sanción económica (entrada "boete", Woorden.org).
        "boete",
        # geblokkeerd: bloqueado, p. ej. una cuenta o un servicio (entrada
        # "geblokkeerd", Woorden.org).
        "geblokkeerd",
        # incassokosten: gastos de gestión de cobro por el impago de una
        # factura (entrada "incassokosten", Woorden.org).
        "incassokosten",
        # naheffing: liquidación o recargo tributario complementario,
        # girado a posteriori (entrada "naheffing", Woorden.org).
        "naheffing",
    ],
    # Noruego. Fuentes: Det Norske Akademis ordbok (naob.no) y Bokmålsordboka
    # (ordbokene.no); Forbrukertilsynet (forbrukertilsynet.no) junto con el
    # reglamento de cobro de deudas vía Lovdata (lovdata.no); Finans Norge
    # (finansnorge.no); y Tolletaten (toll.no), consultadas el 2026-09-24.
    # Ninguna de estas cinco palabras lleva diacrítico en su grafía habitual.
    "no": [
        # forfallsdato: fecha de vencimiento en la que debe satisfacerse una
        # obligación contractual (entrada "forfall"/"forfallsdag",
        # Bokmålsordboka y Det Norske Akademis ordbok).
        "forfallsdato",
        # inkasso: cobro de una deuda (entrada "inkasso", Det Norske
        # Akademis ordbok).
        "inkasso",
        # purregebyr: recargo por una carta de aviso de pago enviada al
        # menos catorce días tras el vencimiento (Forbrukertilsynet y el
        # reglamento de cobro de deudas, vía Lovdata).
        "purregebyr",
        # sperret: bloqueado, p. ej. una cuenta, una tarjeta o una conexión
        # (entrada "sperre", Det Norske Akademis ordbok y Finans Norge).
        "sperret",
        # tollavgift: arancel aduanero sobre mercancías que cruzan la
        # frontera aduanera (Tolletaten, toll.no).
        "tollavgift",
    ],
    # Polaco. Fuente: Słownik języka polskiego PWN (sjp.pwn.pl), consultada
    # el 2026-09-24. "nieopłacona" y "zaległość" llevan la "ł", que
    # MAPA_PLEGADO_DIACRITICOS pliega a "l" por no tener descomposición
    # canónica propia en Unicode.
    "pl": [
        # należność: importe pendiente de pago (entrada "należność").
        "należność",
        # nieopłacona: no abonada, impagada (ł→l; entrada "nieopłacony").
        "nieopłacona",
        # zablokowane: bloqueado, p. ej. un pago o una cuenta (entrada
        # "zablokować").
        "zablokowane",
        # zaległość: atraso o deuda pendiente de pago (ł→l; entrada
        # "zaległość").
        "zaległość",
    ],
    # Portugués. Fuente: Dicionário Priberam da Língua Portuguesa
    # (dicionario.priberam.org), consultada el 2026-09-24. Solo "alfândega"
    # lleva diacrítico en su grafía habitual.
    "pt": [
        # alfandega: alfândega, aduana (entrada "alfândega", sentidos 1-3,
        # la oficina, el edificio y los derechos de aduana).
        "alfândega",
        # bloqueado: bloqueado, con alguna obstrucción o restricción
        # (entrada "bloqueado").
        "bloqueado",
    ],
    # Rumano. Fuente: dexonline (dexonline.ro), consultada el 2026-09-24.
    # "neplată", "somație" y "vamală" llevan diacrítico en su grafía
    # habitual; "blocat" y "penalizare" no.
    "ro": [
        # blocat: bloqueado, p. ej. dinero o mercancías que no pueden
        # circular (entrada "blocat").
        "blocat",
        # neplata: neplată, impago de una obligación financiera dentro de
        # plazo (entrada "neplată").
        "neplată",
        # penalizare: sanción, recargo por demora en el pago (entrada
        # "penalizare", acepción 3).
        "penalizare",
        # somatie: somație, requerimiento formal de pago previo al embargo
        # (entrada "somație", sentido jurídico).
        "somație",
        # vamala: vamală, aduanero (entrada "vamal").
        "vamală",
    ],
    # Eslovaco. Fuente: Slov-Lex, sistema de información jurídica de
    # Eslovaquia (slov-lex.sk), consultada el 2026-09-24. El portal del
    # diccionario JULS (slovnik.juls.savba.sk) no respondió con una entrada,
    # así que se cita la fuente jurídica nacional en su lugar. Solo
    # "exekúcia" lleva diacrítico en su grafía habitual.
    "sk": [
        # exekucia: exekúcia, procedimiento judicial de ejecución forzosa de
        # una deuda (Ley n.º 233/1995 Z. z., Exekučný poriadok, slov-lex.sk).
        "exekúcia",
        # nedoplatok: diferencia positiva entre lo adeudado y lo ya abonado;
        # importe pendiente de pago, usado en materia tributaria (tesauro
        # jurídico de slov-lex.sk, término "daňový nedoplatok").
        "nedoplatok",
    ],
    # Esloveno. Fuente: Fran, portal de diccionarios eslovenos (fran.si), que
    # agrupa el SSKJ², el Slovenski pravopis, el diccionario de Pleteršnik y
    # los diccionarios de terminología jurídica y tributaria, junto con el
    # Terminološki slovar prava, consultados el 2026-09-24. Solo "izvršba"
    # lleva diacrítico en su grafía habitual.
    "sl": [
        # izterjava: cobro o recuperación forzosa de una deuda, incluida la
        # vía forzosa ("prisilna izterjava") (fran.si, entrada "izterjava").
        "izterjava",
        # izvršba: ejecución forzosa de una resolución judicial o
        # administrativa, incluida la ejecución tributaria ("davčna
        # izvršba") (fran.si, entrada "izvršba", y Terminološki slovar
        # prava).
        "izvršba",
    ],
    # Sueco. Fuentes: Konsumentverket, "Regler för fakturor och
    # påminnelser" (konsumentverket.se), y Kronofogden, "Vad är inkasso?"
    # (kronofogden.se); Svenska Akademiens ordböcker (svenska.se/so) junto
    # con Konsumenternas (konsumenternas.se); y Tullverket (tullverket.se),
    # consultadas el 2026-09-24.
    "sv": [
        # betalningskrav: requerimiento de pago posterior a un aviso
        # impagado, hasta el "betalningsföreläggande" de Kronofogden
        # (Konsumentverket y Kronofogden).
        "betalningskrav",
        # betalningspåminnelse: aviso de pago enviado cuando una factura no
        # se abona a tiempo, con un recargo ("påminnelseavgift")
        # (Konsumentverket).
        "betalningspåminnelse",
        # förfallodag: fecha límite en la que la empresa debe haber
        # recibido el pago (Konsumentverket).
        "förfallodag",
        # spärrat: bloqueado, p. ej. una cuenta bancaria o una tarjeta
        # (entrada "spärra", Svenska Akademiens ordböcker, y
        # Konsumenternas).
        "spärrat",
        # tullavgift: arancel aduanero aplicado según el código arancelario
        # de la mercancía (Tullverket).
        "tullavgift",
    ],
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


def es_ipv6_literal(host: str) -> bool:
    """urlsplit() devuelve el host de una URL con una dirección IPv6 entre
    corchetes (p. ej. http://[::1]/) sin los corchetes, así que un ':' en
    el host solo puede significar eso."""
    return ":" in host


# Caracteres que ningún navegador acepta dentro de un host, según la
# especificación WHATWG URL (https://url.spec.whatwg.org/#host-miscellaneous):
# delimitadores de la propia URL (barra, interrogante, almohadilla,
# arroba...) y espacios en blanco o de control. No incluye ':', que
# es_ipv6_literal ya comprueba aparte: un literal IPv6 llega hasta aquí sin
# corchetes y con ':' dentro, y eso no lo convierte en un host inválido.
CARACTERES_PROHIBIDOS_EN_HOST = set("\x00\t\n\r #/?@[\\]^|")


def host_contiene_caracter_prohibido(host: str) -> bool:
    """Comprueba si el host, ya decodificado de sus secuencias de escape
    porcentual, contiene algún carácter que ningún navegador acepta como
    parte de un host. Un host que solo llega a tener ese carácter tras
    decodificar un escape porcentual (p. ej. "%2f" -> "/") no es un host
    real, aunque urlsplit() lo haya aceptado antes de decodificarlo."""
    return any(caracter in CARACTERES_PROHIBIDOS_EN_HOST for caracter in host)


def interpretar_ipv4(host: str):
    """Aplica el analizador de direcciones IPv4 de la especificación WHATWG
    URL (https://url.spec.whatwg.org/#concept-ipv4-parser) al host completo,
    para reconocer también las formas abreviadas o mixtas que un navegador
    interpreta como una IP (p. ej. "127.1" o "0x7f.1", ambas equivalentes a
    127.0.0.1), y no solo la dirección completa en puntos o un único
    componente íntegramente decimal, hexadecimal u octal. El último
    componente completa los octetos que falten, igual que en la
    especificación: 1 a 4 componentes separados por puntos, cada uno
    decimal, hexadecimal con prefijo '0x'/'0X' u octal con un único cero
    inicial. Devuelve la IP como entero de 32 bits, o None si el host no es
    una forma de IPv4 válida para esa especificación."""
    componentes = host.split(".")
    if len(componentes) > 1 and componentes[-1] == "":
        componentes = componentes[:-1]
    if not componentes or len(componentes) > 4:
        return None
    numeros = []
    for componente in componentes:
        numero = interpretar_numero_ipv4(componente)
        if numero is None:
            return None
        numeros.append(numero)
    if any(numero > 255 for numero in numeros[:-1]):
        return None
    if numeros[-1] >= 256 ** (5 - len(numeros)):
        return None
    ip = numeros[-1]
    for posicion, numero in enumerate(numeros[:-1]):
        ip += numero << (8 * (3 - posicion))
    return ip


# Más cifras de las que necesitaría nunca un componente válido ya sin ceros a
# la izquierda: 2**32 - 1, el mayor valor que interpretar_ipv4 puede llegar a
# aceptar, ya ocupa como mucho 11 cifras (en octal, su base menos compacta de
# las tres). Por debajo del límite de conversión de cadena a entero que
# Python 3.11+ aplica por motivos de seguridad (PEP 2022; 4300 cifras por
# defecto), para rechazar un componente larguísimo por su longitud, sin
# intentar convertirlo.
LIMITE_CIFRAS_COMPONENTE_IPV4 = 16


def interpretar_numero_ipv4(componente: str):
    """Interpreta un componente entre puntos de un host como un número para
    interpretar_ipv4: decimal si no lleva prefijo, hexadecimal con el
    prefijo '0x'/'0X', u octal con un único '0' inicial (y al menos dos
    caracteres). Devuelve el valor como entero, o None si el componente no
    es válido en ninguna de esas tres bases, o si, ya sin ceros a la
    izquierda, tiene más cifras que LIMITE_CIFRAS_COMPONENTE_IPV4 — ninguna
    forma válida las necesita, y así se evita convertir a entero una cadena
    larguísima. Los ceros a la izquierda se recortan antes de aplicar ese
    límite (y antes de la validación de cifras) porque no cambian el valor
    en ninguna base: un componente como "0x" seguido de treinta ceros y
    "7f" tiene muchas cifras pero sigue valiendo lo mismo que "0x7f", y
    rechazarlo por su longitud bruta sin recortarlos antes dejaría sin
    puntuar esa IP disfrazada."""
    base = 10
    resto = componente
    if len(componente) >= 2 and componente[:2].lower() == "0x":
        base = 16
        resto = componente[2:]
    elif len(componente) >= 2 and componente[0] == "0":
        base = 8
        resto = componente[1:]
    resto = resto.lstrip("0")
    if resto == "":
        return 0
    if len(resto) > LIMITE_CIFRAS_COMPONENTE_IPV4:
        return None
    cifras_validas_por_base = {8: r"^[0-7]+$", 10: r"^[0-9]+$", 16: r"^[0-9a-fA-F]+$"}
    if not re.match(cifras_validas_por_base[base], resto):
        return None
    try:
        return int(resto, base)
    except ValueError:
        return None


def ip_disfrazada_a_puntos(host: str) -> str:
    """Convierte una IP disfrazada en decimal, hexadecimal, octal o en una
    forma abreviada o mixta (p. ej. "127.1") a su forma habitual con puntos,
    para mostrarla en el hallazgo."""
    valor = interpretar_ipv4(host)
    return ".".join(str((valor >> desplazamiento) & 0xFF) for desplazamiento in (24, 16, 8, 0))


# Letras con diacrítico que unicodedata.normalize("NFKD", ...) no separa en
# una letra base más una marca combinante, porque no tienen descomposición
# canónica propia en Unicode (p. ej. "ß" no es "s" + combinante).
MAPA_PLEGADO_DIACRITICOS = {
    "æ": "ae", "ø": "o", "ł": "l", "ß": "ss", "đ": "d", "œ": "oe",
}


def plegar_diacriticos(texto: str) -> str:
    """Quita las tildes, diéresis y demás diacríticos de un texto ya en
    minúsculas, para comparar palabras de urgencia en varios idiomas sin
    depender de cómo se hayan escrito esos diacríticos en el contenido del
    QR. unicodedata.normalize con NFKD separa la mayoría de las letras con
    diacrítico en una letra base más una marca combinante eliminable (p. ej.
    "ä" -> "a" + combinante), pero no cubre "æ", "ø", "ł", "ß", "đ" ni "œ",
    así que esas letras se sustituyen antes con MAPA_PLEGADO_DIACRITICOS."""
    for letra, plegada in MAPA_PLEGADO_DIACRITICOS.items():
        texto = texto.replace(letra, plegada)
    descompuesto = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in descompuesto if not unicodedata.combining(c))


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


def normalizar_barras_tras_el_esquema(texto: str) -> str:
    """Para 'http:' o 'https:' seguido de cualquier secuencia de cero o más
    '/' y '\\' (p. ej. "http:evil.top/login", sin ninguna barra;
    "https:/evil.top/"; "https:///evil.top/"; o la mezcla
    "https:/\\evil.top/"), reescribe el texto con la autoridad introducida
    por "://", igual que hace el analizador de la especificación WHATWG URL
    con los esquemas especiales: para ellos, cualquier secuencia de '/' y
    '\\' tras el esquema introduce la autoridad —incluida la secuencia
    vacía, cuando el esquema va seguido directamente del host— no solo "//"
    exacto. Sin esta normalización, es_url() rechaza la URL antes de que el
    resto del análisis pueda llegar siquiera al host — por ejemplo,
    "http:evil.top/login" se leía con "http" como host al pasar
    directamente por urlsplit(), "https:/dgt-multas.top/pago" no pasaba de
    es_url(), y "https:///dgt-multas.top/pago" llegaba a analizarse con un
    host vacío, en vez de con el mismo host de destino en los tres casos.
    Devuelve el texto sin cambios si no empieza con 'http:' o 'https:'
    (sin distinguir mayúsculas de minúsculas)."""
    # re.DOTALL para que "(.*)" también abarque un salto de línea interno en
    # el contenido del QR; sin él, esta expresión regular no coincidía en
    # absoluto con una URL que llevara uno, y la normalización se omitía
    # igual que si no hubiera ninguna barra tras el esquema.
    coincide = re.match(r"^(https?):([/\\]*)(.*)$", texto, re.IGNORECASE | re.DOTALL)
    if not coincide:
        return texto
    return f"{coincide.group(1).lower()}://{coincide.group(3)}"


def es_url(texto: str) -> bool:
    texto_normalizado = normalizar_barras_tras_el_esquema(texto)
    return (bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", texto_normalizado))
            or texto.lower().startswith("www.")
            or esquema_de(texto) in ESQUEMAS_PELIGROSOS)


def dividir_autoridad_como_un_navegador(esquema: str, resto: str):
    """Reconstruye la autoridad de una URL http(s) exactamente como lo haría
    un navegador, para cuando urllib.parse.urlsplit() rechaza la URL con un
    ValueError que no deja ningún resultado del que partir. Un navegador
    identifica los delimitadores de una URL una sola vez, con los caracteres
    ASCII literales '/', '?' y '#', antes de aplicar cualquier normalización
    Unicode al host — así que esta función hace lo mismo en vez de
    rendirse: la autoridad es todo lo anterior al primer '/', '?' o '#'
    literal de "resto" (lo que sigue a "esquema://"), y dentro de ella el
    host es todo lo posterior al último '@' literal (información de usuario
    y contraseña antes, si la hay). Devuelve un objeto con los mismos
    atributos que usa analizar_url de un SplitResult (scheme, netloc,
    hostname, path, query), o None si ni siquiera esta lectura mínima es
    fiable — un literal IPv6 sin el corchete de cierre. El host devuelto
    puede seguir en Unicode (p. ej. "pаypal.top" con una "а" cirílica):
    analizar_url lo convierte a Punycode después, con el mismo paso que
    aplica al host de la rama normal, en vez de rechazarlo aquí."""
    fin_autoridad = re.search(r"[/?#]", resto)
    if fin_autoridad:
        autoridad = resto[:fin_autoridad.start()]
        resto_tras_autoridad = resto[fin_autoridad.start():]
    else:
        autoridad = resto
        resto_tras_autoridad = ""

    host_con_puerto = autoridad.rsplit("@", 1)[-1]
    if host_con_puerto.startswith("["):
        fin_literal_ipv6 = host_con_puerto.find("]")
        if fin_literal_ipv6 == -1:
            return None
        host = host_con_puerto[1:fin_literal_ipv6]
    else:
        host = host_con_puerto.split(":", 1)[0]

    ruta, _, consulta = resto_tras_autoridad.split("#", 1)[0].partition("?")
    return types.SimpleNamespace(
        scheme=esquema, netloc=autoridad, hostname=host.lower(), path=ruta, query=consulta,
    )


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

    # Para http(s), los navegadores aceptan cualquier secuencia de '/' y '\\'
    # tras el esquema como inicio de la autoridad, no solo "//" exacto (p.
    # ej. "https:/evil.top/", "https:///evil.top/" o la mezcla
    # "https:/\\evil.top/" navegan igual que "https://evil.top/"). Se
    # normaliza antes de nada, para que el resto del análisis — incluida la
    # detección de '\\' dentro de la propia autoridad, justo abajo —
    # trabaje siempre sobre una URL con "://".
    url_con_autoridad_normalizada = normalizar_barras_tras_el_esquema(url)
    if "://" in url_con_autoridad_normalizada:
        url_normalizada = url_con_autoridad_normalizada
    else:
        url_normalizada = "http://" + url_con_autoridad_normalizada

    # Los navegadores leen "\" como "/" dentro de la autoridad de las URLs
    # http(s), pero no en la de otros esquemas (p. ej. ftp://). Si no se
    # corrige para http(s), urlsplit() puede quedarse con un host distinto
    # al que realmente visitaría el usuario — por ejemplo,
    # "https://evil.top\@dgt.es/" termina en el dominio oficial "dgt.es" en
    # vez de en "evil.top".
    contiene_backslash_antes_del_host = False
    # esquema y resto se necesitan también más abajo, en el except de
    # urlsplit(), para CUALQUIER esquema —no solo http(s)— así que se
    # calculan aquí de forma incondicional. A esta altura url_normalizada
    # siempre contiene "://" (la rama anterior se lo añade si el contenido
    # original no traía ninguno), así que coincide_esquema no debería ser
    # nunca None; el valor por defecto es solo una red de seguridad para que
    # analizar_url no pueda lanzar una excepción por "esquema"/"resto" sin
    # asignar. Antes de este cambio, "esquema" y "resto" solo se asignaban
    # dentro de un "if" que solo entraba para http(s), y
    # dividir_autoridad_como_un_navegador(esquema, resto), más abajo,
    # lanzaba UnboundLocalError con cualquier otro esquema (p. ej.
    # "ftp://[::1").
    #
    # re.DOTALL por la misma razón que en normalizar_barras_tras_el_esquema:
    # un salto de línea interno tras la autoridad no debe impedir que esta
    # expresión regular encuentre la propia autoridad.
    coincide_esquema = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$", url_normalizada, re.IGNORECASE | re.DOTALL)
    esquema, resto = coincide_esquema.groups() if coincide_esquema else ("", url_normalizada)
    if esquema.lower() in ("http", "https"):
        autoridad_cruda = re.match(r"^[^/?#]*", resto).group(0)
        if "\\" in autoridad_cruda:
            contiene_backslash_antes_del_host = True
        resto = resto.replace(chr(92), "/")
        url_normalizada = f"{esquema}://{resto}"

    # urlsplit() puede rechazar una URL por lo demás navegable con un
    # ValueError — por ejemplo, por el plegado NFKC que la propia librería
    # estándar aplica al netloc para detectar un carácter Unicode que se
    # pliegue a '@', ':', '#' o '?' sin serlo literalmente (p. ej. '＃', el
    # signo de número de ancho completo U+FF03, en
    # "https://dgt.es＃@evil.top/"), o por un literal IPv6 sin cerrar. Un
    # navegador no vuelve a comprobar delimitadores tras ese plegado: los
    # identifica una sola vez, con los caracteres ASCII literales, antes de
    # aplicar cualquier normalización Unicode al host. Devolver un resultado
    # de 0 puntos aquí escondería ese destino real tras un BAJO que parece
    # seguro, así que se intenta reconstruir la autoridad como lo haría un
    # navegador (dividir_autoridad_como_un_navegador) en vez de rendirse.
    try:
        partes = urllib.parse.urlsplit(url_normalizada)
        host = partes.hostname or ""
    except ValueError:
        partes = dividir_autoridad_como_un_navegador(esquema, resto)
        if partes is None:
            return {
                "url": url,
                "dominio": "",
                "hallazgos": ["URL malformada o no analizable: ni urlsplit() ni una lectura de "
                             "la autoridad equivalente a la de un navegador han podido determinar "
                             "un host."],
                "puntuacion_riesgo": 3,
            }
        host = partes.hostname or ""

    # Un host vacío (p. ej. "https://" o "http:///login") no tiene ninguna
    # autoridad real a la que navegar. Se puntúa igual que una IP disfrazada
    # (+3): ningún navegador llegaría a ningún destino con esta URL, lo que
    # es en sí mismo un patrón habitual de enlace manipulado o incompleto,
    # no un simple fallo de análisis que deba quedar en 0.
    if not host:
        return {
            "url": url,
            "dominio": "",
            "hallazgos": ["URL malformada o no analizable: no contiene ningún host."],
            "puntuacion_riesgo": 3,
        }

    # Host con secuencias de escape porcentual (p. ej. "%70aypal.evil.com",
    # "bit.l%79"): se decodifica antes de las comprobaciones de host, igual
    # que hacen los navegadores con las secuencias %XX de la URL.
    host_sin_decodificar = host
    host = urllib.parse.unquote(host)
    contiene_escapes_en_host = host != host_sin_decodificar

    # Un host puede decodificar a un carácter que ningún navegador acepta
    # como parte de un host (p. ej. "%2f" -> "/"), lo que cambiaría qué
    # parte de la URL es la autoridad y cuál es la ruta si se siguiera
    # analizando como si fuera un dominio real. Se trata como la misma URL
    # malformada que un host vacío, con la misma puntuación, en vez de
    # analizar o mostrar ese carácter como si fuera un destino.
    if host_contiene_caracter_prohibido(host):
        return {
            "url": url,
            "dominio": "",
            "hallazgos": ["URL malformada o no analizable: el host decodificado contiene un "
                         "carácter que ningún navegador acepta en un host."],
            "puntuacion_riesgo": 3,
        }

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
    #
    # host_unicode conserva el host en Unicode, de antes de esta conversión,
    # para la comprobación 8 de más abajo: una palabra de urgencia con
    # diacrítico (p. ej. el danés "spærret") deja de existir como tal en el
    # host una vez convertido a Punycode, así que buscarla ahí nunca la
    # encontraría.
    host_unicode = host
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    # El plegado que aplica el códec "idna" (vía nameprep, que normaliza a
    # NFKC) puede convertir un carácter de ancho completo en su forma ASCII
    # prohibida en un host — p. ej. '＃' (U+FF03, signo de número de ancho
    # completo) se pliega a '#', e igual ocurre con '＠', '／' y '？'. La
    # comprobación de caracteres prohibidos de más arriba corre sobre el host
    # en Unicode, antes de esta conversión, así que no detecta estos casos;
    # sin repetirla aquí, un host así se analizaría como si el carácter
    # prohibido formara parte legítima de él (p. ej. "evil.com#" con
    # puntuación 0) en vez de dar el mismo hallazgo de URL malformada que ya
    # se da cuando el carácter prohibido aparece antes de la conversión.
    if host_contiene_caracter_prohibido(host):
        return {
            "url": url,
            "dominio": "",
            "hallazgos": ["URL malformada o no analizable: el host decodificado contiene un "
                         "carácter que ningún navegador acepta en un host."],
            "puntuacion_riesgo": 3,
        }

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

    # 11. Credenciales (usuario:contraseña) delante del host. Es
    # independiente de la comprobación 1 y se suma a ella: la 1 puntúa el
    # truco de navegación del '@' en sí, y esta puntúa específicamente que
    # la URL expone un usuario y una contraseña en texto plano.
    autoridad_antes_del_host = partes.netloc.rsplit("@", 1)[0] if "@" in partes.netloc else ""
    if ":" in autoridad_antes_del_host:
        hallazgos.append("Incluye credenciales (usuario:contraseña) en texto plano en la propia URL — "
                         "un sitio legítimo nunca las pide así.")
        puntuacion += 1

    # 2. IP en vez de dominio
    es_ip_en_puntos = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    if es_ip_en_puntos:
        hallazgos.append(f"El destino es una dirección IP ({host}) en lugar de un nombre de dominio.")
        puntuacion += 3

    # 9. IP disfrazada en decimal, hexadecimal, octal, en una forma
    # abreviada o mixta (p. ej. "127.1", "0x7f.1") o como literal IPv6, para
    # no dejar sin puntuar las formas alternativas de escribir una IP que
    # evitan la comprobación 2 — con el mismo analizador de la
    # especificación WHATWG URL que usaría un navegador. No se suma a la 2:
    # una IP solo puede tener una de las dos formas (en puntos o
    # disfrazada), nunca ambas.
    es_ip_disfrazada = not es_ip_en_puntos and (
        es_ipv6_literal(host) or interpretar_ipv4(host) is not None
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
    # (p. ej. "/%70ago" en vez de "/pago"). El contenido y cada palabra de la
    # lista se pliegan con plegar_diacriticos antes de compararlos, para que
    # una palabra con diacrítico (p. ej. el checo "zablokovaný") se detecte
    # tanto si el QR la lleva con su diacrítico como sin él.
    ruta_completa = urllib.parse.unquote(partes.path + "?" + partes.query).lower()
    ruta_completa_plegada = plegar_diacriticos(ruta_completa)
    # Se pliega host_unicode (el host de antes de la conversión a
    # Punycode), no host_sin_tld, para que una palabra de urgencia con
    # diacrítico siga encontrándose aunque el dominio reportado ya esté en
    # Punycode (p. ej. "www.spærret.com" -> "www.xn--sprret-...com").
    host_plegado = plegar_diacriticos(host_unicode.lower())
    # palabras_alerta es la lista original de upstream, sin modificar. No se
    # le añaden "morosidad" ni "penalización" (otras palabras españolas de
    # ese mismo campo semántico): extender la lista española es una decisión
    # de upstream sobre su propio idioma, no parte de esta rama, que solo
    # añade bloques de otros idiomas en PALABRAS_ALERTA_POR_IDIOMA.
    palabras_alerta = ["pago", "payment", "multa", "fine", "verify", "verifica", "urgente",
                       "suspend", "bloqueo", "actualiza", "confirm", "aduana", "tasa"]
    palabras_alerta_multilingue = palabras_alerta + [
        palabra for palabras_idioma in PALABRAS_ALERTA_POR_IDIOMA.values() for palabra in palabras_idioma
    ]
    encontradas = [
        p for p in palabras_alerta_multilingue
        if plegar_diacriticos(p) in ruta_completa_plegada or plegar_diacriticos(p) in host_plegado
    ]
    if encontradas:
        # encontradas ya respeta el orden de palabras_alerta_multilingue, así
        # que el resultado es el mismo en cada ejecución (antes se perdía ese
        # orden al pasar por un set(), cuyo recorrido depende del hash
        # aleatorio).
        hallazgos.append(f"Contiene términos asociados a presión/urgencia: {', '.join(encontradas)}.")
        puntuacion += 1

    # 10. Esquema sin cifrar (http). No se puntúa si el propio script fue
    # quien añadió "http://" por no haber ningún esquema en el contenido
    # original (una URL "www.ejemplo.com" o sin www tampoco diría nada
    # sobre el cifrado), ni si el destino ya es una IP, puntuada aparte en
    # la comprobación 2 o la 9. esquema_de(url) se aplica al contenido
    # ORIGINAL, antes de normalizar_barras_tras_el_esquema, así que detecta
    # cualquier forma de "http:" que un navegador reconozca como tal —con
    # "://", con una sola barra, con backslashes o directamente sin ninguna
    # barra ("http:evil.top")— y no solo el literal "http://" exacto.
    if (partes.scheme.lower() == "http" and esquema_de(url) == "http"
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
