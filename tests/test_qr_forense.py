"""Pruebas unitarias para qr_forense.py.

Ejecución (desde la raíz del repositorio):

    python3 -m unittest discover -s tests
"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

import qr_forense

EJEMPLOS_DIR = Path(__file__).resolve().parent.parent / "ejemplos"


def _cargar_ejemplo(nombre_json: str):
    """Lee un informe de ejemplos/ y devuelve (url, análisis_esperado)."""
    datos = json.loads((EJEMPLOS_DIR / nombre_json).read_text(encoding="utf-8"))
    url = datos["contenidos_detectados"][0]
    return url, datos["analisis_urls"][url]


def _palabras_de_urgencia(hallazgo: str):
    """Extrae la lista de palabras del hallazgo de presión/urgencia."""
    prefijo = "Contiene términos asociados a presión/urgencia: "
    assert hallazgo.startswith(prefijo), hallazgo
    return hallazgo[len(prefijo):].rstrip(".").split(", ")


class TestAnalizarUrlEjemplos(unittest.TestCase):
    """Fija la puntuación y los hallazgos de analizar_url para los cinco
    casos de ejemplos/. El hallazgo de urgencia de cada caso se compara por
    conjunto, no por el texto exacto, porque el orden de palabras_alerta no
    tiene por qué coincidir con el de los JSON de ejemplos/, generados con
    una versión anterior que usaba set()."""

    def _comparar_con_ejemplo(self, nombre_json, hallazgo_urgencia_al_final):
        url, esperado = _cargar_ejemplo(nombre_json)
        resultado = qr_forense.analizar_url(url)

        self.assertEqual(resultado["dominio"], esperado["dominio"])
        self.assertEqual(resultado["puntuacion_riesgo"], esperado["puntuacion_riesgo"])
        self.assertEqual(len(resultado["hallazgos"]), len(esperado["hallazgos"]))

        if hallazgo_urgencia_al_final:
            self.assertEqual(resultado["hallazgos"][:-1], esperado["hallazgos"][:-1])
            self.assertCountEqual(
                _palabras_de_urgencia(resultado["hallazgos"][-1]),
                _palabras_de_urgencia(esperado["hallazgos"][-1]),
            )
        else:
            self.assertEqual(resultado["hallazgos"], esperado["hallazgos"])

    def test_acortador(self):
        self._comparar_con_ejemplo("test_qr_acortador.json", hallazgo_urgencia_al_final=False)

    def test_arroba(self):
        self._comparar_con_ejemplo("test_qr_arroba.json", hallazgo_urgencia_al_final=True)

    def test_ip(self):
        self._comparar_con_ejemplo("test_qr_ip.json", hallazgo_urgencia_al_final=True)

    def test_legitimo(self):
        self._comparar_con_ejemplo("test_qr_legitimo.json", hallazgo_urgencia_al_final=True)

    def test_suplantacion(self):
        self._comparar_con_ejemplo("test_qr_suplantacion.json", hallazgo_urgencia_al_final=True)


class TestClasificarRiesgo(unittest.TestCase):
    """Fija los umbrales de banda de riesgo: BAJO < 3, MEDIO 3-5, ALTO >= 6."""

    def test_bajo(self):
        self.assertEqual(qr_forense.clasificar_riesgo(0), "BAJO")
        self.assertEqual(qr_forense.clasificar_riesgo(2), "BAJO")

    def test_medio(self):
        self.assertEqual(qr_forense.clasificar_riesgo(3), "MEDIO")
        self.assertEqual(qr_forense.clasificar_riesgo(5), "MEDIO")

    def test_alto(self):
        self.assertEqual(qr_forense.clasificar_riesgo(6), "ALTO")
        self.assertEqual(qr_forense.clasificar_riesgo(100), "ALTO")


class TestRobustezEntradaMalformada(unittest.TestCase):
    """analizar_url no debe lanzar una excepción con entradas que
    urllib.parse.urlsplit rechaza; debe devolver un hallazgo que explique
    que la URL no se pudo analizar, en vez de dejar que el proceso se caiga."""

    def test_url_con_ipv6_sin_cerrar_no_lanza_excepcion(self):
        resultado = qr_forense.analizar_url("http://[::1")
        self.assertEqual(resultado["dominio"], "")
        self.assertEqual(resultado["puntuacion_riesgo"], 0)
        self.assertEqual(len(resultado["hallazgos"]), 1)
        self.assertTrue(resultado["hallazgos"][0].startswith("URL malformada o no analizable"))


class TestNormalizarContenidoQr(unittest.TestCase):
    """El contenido decodificado del QR se recorta antes de analizarlo, para
    que los espacios en blanco de la propia imagen no lo saquen de es_url."""

    def test_elimina_espacios_al_principio_y_al_final(self):
        self.assertEqual(
            qr_forense.normalizar_contenido_qr("  https://evil.top/x  \n"),
            "https://evil.top/x",
        )

    def test_texto_sin_espacios_no_cambia(self):
        self.assertEqual(qr_forense.normalizar_contenido_qr("https://evil.top/x"), "https://evil.top/x")


class TestHostVacio(unittest.TestCase):
    """Un host vacío (p. ej. "http:///login", "https://") no tiene ninguna
    autoridad real a la que navegar, así que se puntúa igual que una IP
    disfrazada (+3) en vez de con 0: es en sí mismo un patrón habitual de
    enlace manipulado o incompleto, no un simple fallo de análisis."""

    def test_host_vacio_se_trata_como_url_malformada(self):
        resultado = qr_forense.analizar_url("http:///login")
        self.assertEqual(resultado["dominio"], "")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertEqual(
            resultado["hallazgos"],
            ["URL malformada o no analizable: no contiene ningún host."],
        )
        self.assertEqual(qr_forense.clasificar_riesgo(resultado["puntuacion_riesgo"]), "MEDIO")

    def test_https_sin_nada_detras_tambien_se_puntua(self):
        resultado = qr_forense.analizar_url("https://")
        self.assertEqual(resultado["dominio"], "")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertEqual(
            resultado["hallazgos"],
            ["URL malformada o no analizable: no contiene ningún host."],
        )


class TestPuntoFinalEnHost(unittest.TestCase):
    """Un único punto final en el host ("bit.ly.", "evil.top.") se analiza
    como si no estuviera, igual que hacen los navegadores con la raíz del
    DNS."""

    def test_acortador_con_punto_final(self):
        resultado = qr_forense.analizar_url("https://bit.ly./x")
        self.assertEqual(resultado["dominio"], "bit.ly")
        self.assertEqual(resultado["puntuacion_riesgo"], 2)
        self.assertEqual(len(resultado["hallazgos"]), 1)
        self.assertIn("acortador", resultado["hallazgos"][0])

    def test_tld_sospechoso_con_punto_final(self):
        resultado = qr_forense.analizar_url("https://evil.top./x")
        self.assertEqual(resultado["dominio"], "evil.top")
        self.assertEqual(resultado["puntuacion_riesgo"], 1)
        self.assertEqual(len(resultado["hallazgos"]), 1)
        self.assertIn(".top", resultado["hallazgos"][0])


class TestHostConEscapesPorcentuales(unittest.TestCase):
    """El host se decodifica antes de las comprobaciones de host, para que
    un escape porcentual no esconda una suplantación de marca o un
    acortador."""

    def test_suplantacion_tras_decodificar_el_host(self):
        resultado = qr_forense.analizar_url("https://%70aypal.evil.com/x")
        self.assertEqual(resultado["dominio"], "paypal.evil.com")
        self.assertEqual(resultado["puntuacion_riesgo"], 5)
        self.assertEqual(len(resultado["hallazgos"]), 2)
        self.assertIn("escape porcentual", resultado["hallazgos"][0])
        self.assertIn("suplantación de marca", resultado["hallazgos"][1])

    def test_acortador_tras_decodificar_el_host(self):
        resultado = qr_forense.analizar_url("https://bit.l%79/x")
        self.assertEqual(resultado["dominio"], "bit.ly")
        self.assertEqual(resultado["puntuacion_riesgo"], 2)
        self.assertEqual(len(resultado["hallazgos"]), 2)
        self.assertIn("escape porcentual", resultado["hallazgos"][0])
        self.assertIn("acortador", resultado["hallazgos"][1])

    def test_host_sin_escapes_no_genera_el_hallazgo(self):
        resultado = qr_forense.analizar_url("https://bit.ly/x")
        self.assertEqual(len(resultado["hallazgos"]), 1)
        self.assertIn("acortador", resultado["hallazgos"][0])


class TestHostConCaracterProhibido(unittest.TestCase):
    """Un host que solo decodifica a un carácter prohibido (p. ej. "%2f" ->
    "/") no es un host real para ningún navegador, aunque urlsplit() lo
    acepte antes de decodificarlo: se valida el host ya decodificado antes
    de seguir analizándolo o de mostrarlo como destino."""

    def test_host_decodifica_a_una_barra_se_trata_como_url_malformada(self):
        resultado = qr_forense.analizar_url("https://%2f/")
        self.assertEqual(resultado["dominio"], "")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertEqual(
            resultado["hallazgos"],
            ["URL malformada o no analizable: el host decodificado contiene un "
             "carácter que ningún navegador acepta en un host."],
        )

    def test_host_normal_no_activa_la_comprobacion(self):
        resultado = qr_forense.analizar_url("https://dgt.es/tramite")
        self.assertEqual(
            resultado["hallazgos"],
            ["No se han detectado patrones sospechosos estructurales en la URL."],
        )


class TestHostContieneCaracterProhibido(unittest.TestCase):
    """host_contiene_caracter_prohibido distingue los delimitadores propios
    de una URL (y los espacios en blanco o de control) de un host válido,
    incluido un literal IPv6 con ':' pero sin corchetes."""

    def test_barra_es_un_caracter_prohibido(self):
        self.assertTrue(qr_forense.host_contiene_caracter_prohibido("/"))

    def test_host_normal_no_tiene_caracteres_prohibidos(self):
        self.assertFalse(qr_forense.host_contiene_caracter_prohibido("dgt.es"))

    def test_los_dos_puntos_no_son_un_caracter_prohibido(self):
        # Un literal IPv6 llega aquí sin corchetes (p. ej. "::1"); ':' no
        # está en CARACTERES_PROHIBIDOS_EN_HOST para no tratarlo como un
        # host inválido.
        self.assertFalse(qr_forense.host_contiene_caracter_prohibido("::1"))


class TestBackslashAntesDelHost(unittest.TestCase):
    """Los navegadores interpretan "\\" como "/" en la autoridad de las
    URLs http(s), así que un "\\" antes del host debe analizarse como si
    fuera "/" y generar un hallazgo propio, para que la URL no quede
    infrapuntuada cuando el truco de "@" deja de aplicarse."""

    def test_backslash_antes_del_arroba_desplaza_el_host_real(self):
        resultado = qr_forense.analizar_url("https://evil.top\\@dgt.es/")
        self.assertEqual(resultado["dominio"], "evil.top")
        self.assertEqual(resultado["puntuacion_riesgo"], 5)
        self.assertEqual(len(resultado["hallazgos"]), 2)
        self.assertIn("\\", resultado["hallazgos"][0])
        self.assertIn(".top", resultado["hallazgos"][1])

    def test_sin_backslash_no_genera_el_hallazgo(self):
        resultado = qr_forense.analizar_url("https://dgt.es/tramite")
        self.assertEqual(resultado["hallazgos"], ["No se han detectado patrones sospechosos estructurales en la URL."])


class TestBackslashConSaltoDeLineaEnMedio(unittest.TestCase):
    """'.' no coincide con un salto de línea salvo que la expresión regular
    use re.DOTALL. Sin ese indicador, una URL con un salto de línea interno
    tras la autoridad no coincidía en absoluto con la expresión que detecta
    el '\\' antes del host, y la normalización se omitía por completo, en
    vez de solo fallar al encontrar el '\\' concreto."""

    def test_arroba_tras_backslash_con_salto_de_linea_llega_al_host_real(self):
        resultado = qr_forense.analizar_url("https://evil.top\\@dgt.es/\nx")
        self.assertEqual(resultado["dominio"], "evil.top")
        self.assertEqual(resultado["puntuacion_riesgo"], 5)
        self.assertEqual(len(resultado["hallazgos"]), 2)
        self.assertIn("\\", resultado["hallazgos"][0])
        self.assertIn(".top", resultado["hallazgos"][1])


class TestBarrasLaxasTrasElEsquema(unittest.TestCase):
    """Para http(s), los navegadores aceptan cualquier mezcla de '/' y '\\'
    tras el esquema como inicio de la autoridad, no solo "//" exacto. Sin
    esta normalización, es_url() rechazaba la URL antes de que analizar_url
    pudiera siquiera llegar al host real."""

    def test_es_url_reconoce_la_mezcla_de_barra_y_backslash(self):
        self.assertTrue(qr_forense.es_url("https:/\\dgt-multas-pago.top/"))

    def test_analizar_url_llega_al_dominio_real(self):
        resultado = qr_forense.analizar_url("https:/\\dgt-multas-pago.top/")
        self.assertEqual(resultado["dominio"], "dgt-multas-pago.top")
        self.assertEqual(resultado["puntuacion_riesgo"], 7)
        self.assertEqual(len(resultado["hallazgos"]), 3)
        self.assertIn(".top", resultado["hallazgos"][0])
        self.assertIn("suplantación de marca", resultado["hallazgos"][1])
        self.assertIn("pago, multa", resultado["hallazgos"][2])

    def test_doble_backslash_tras_el_esquema_tambien_se_reconoce(self):
        resultado = qr_forense.analizar_url("https:\\\\dgt.es/tramite")
        self.assertEqual(resultado["dominio"], "dgt.es")
        self.assertEqual(
            resultado["hallazgos"],
            ["No se han detectado patrones sospechosos estructurales en la URL."],
        )

    def test_combinado_con_backslash_de_truco_sigue_detectando_el_host_real(self):
        resultado = qr_forense.analizar_url("https:/\\evil.top\\@dgt.es/")
        self.assertEqual(resultado["dominio"], "evil.top")
        self.assertIn("\\", resultado["hallazgos"][0])

    def test_sin_backslash_en_las_barras_no_cambia_nada(self):
        self.assertEqual(
            qr_forense.normalizar_barras_tras_el_esquema("https://dgt.es/tramite"),
            "https://dgt.es/tramite",
        )


class TestRutaConEscapesPorcentuales(unittest.TestCase):
    """La ruta y la query se decodifican antes de buscar palabras de
    presión/urgencia, para detectar un término oculto tras un escape
    porcentual."""

    def test_palabra_de_urgencia_oculta_tras_un_escape(self):
        resultado = qr_forense.analizar_url("https://e.test/%70ago")
        self.assertEqual(resultado["puntuacion_riesgo"], 1)
        self.assertEqual(
            resultado["hallazgos"],
            ["Contiene términos asociados a presión/urgencia: pago."],
        )


class TestOrdenEstableDePalabrasDeUrgencia(unittest.TestCase):
    """El hallazgo de presión/urgencia debe listar las palabras siempre en
    el mismo orden (el de palabras_alerta), no en el orden de un set(), que
    depende del hash aleatorio de cada ejecución de Python."""

    def test_orden_es_siempre_el_de_palabras_alerta(self):
        url = "https://dgt-multas-pago.es/tasa?id=88213"
        esperado = "Contiene términos asociados a presión/urgencia: pago, multa, tasa."
        for _ in range(5):
            resultado = qr_forense.analizar_url(url)
            self.assertEqual(resultado["hallazgos"][-1], esperado)


class TestHostUnicodeConvertidoAPunycode(unittest.TestCase):
    """Un host en Unicode se convierte a su forma Punycode (códec "idna" de
    la librería estándar, IDNA 2003) antes de la comprobación de Punycode,
    para detectar homógrafos como una "a" cirílica en "paypal"."""

    def test_homografo_cirilico_llega_a_la_comprobacion_de_punycode(self):
        resultado = qr_forense.analizar_url("https://pаypal.com/login")
        self.assertTrue(resultado["dominio"].startswith("xn--"))
        self.assertTrue(resultado["dominio"].endswith(".com"))
        # El Punycode de esta etiqueta concreta añade tres guiones, así que
        # también dispara la comprobación de "exceso de guiones" (+1).
        self.assertEqual(resultado["puntuacion_riesgo"], 4)
        self.assertEqual(len(resultado["hallazgos"]), 2)
        self.assertIn("Punycode", resultado["hallazgos"][0])
        self.assertIn("guiones", resultado["hallazgos"][1])

    def test_host_ascii_no_se_modifica(self):
        resultado = qr_forense.analizar_url("https://dgt.es/tramite")
        self.assertEqual(resultado["dominio"], "dgt.es")

    def test_error_de_codificacion_no_interrumpe_el_analisis(self):
        # Una etiqueta vacía entre dos puntos ("a..b.com") no es válida para
        # el códec "idna" (UnicodeError); el análisis debe seguir con el
        # host ya decodificado en vez de interrumpirse.
        resultado = qr_forense.analizar_url("https://a..b.com/x")
        self.assertEqual(resultado["dominio"], "a..b.com")


class TestPalabraDeUrgenciaEnHostUnicode(unittest.TestCase):
    """La comprobación 8 debe seguir encontrando una palabra de urgencia en
    el host aunque ese host se convierta a Punycode antes de las
    comprobaciones de host: se pliega una vista del host en Unicode,
    tomada antes de esa conversión, no el host ya convertido a Punycode,
    donde una letra con diacrítico ya no existe como tal."""

    def test_palabra_danesa_en_un_host_que_se_convierte_a_punycode(self):
        resultado = qr_forense.analizar_url("https://www.spærret.com/")
        self.assertTrue(resultado["dominio"].startswith("www.xn--"))
        self.assertTrue(resultado["dominio"].endswith(".com"))
        self.assertIn(
            "Contiene términos asociados a presión/urgencia: spærret.",
            resultado["hallazgos"],
        )


class TestIpDisfrazada(unittest.TestCase):
    """Una IP escrita en decimal, hexadecimal, octal o como literal IPv6
    debe puntuarse igual que la IP en puntos de la comprobación 2 (+3), sin
    sumarse a ella: una misma IP solo puede tener una de las dos formas."""

    def test_decimal(self):
        resultado = qr_forense.analizar_url("http://2130706433/")
        self.assertEqual(resultado["dominio"], "2130706433")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("127.0.0.1", resultado["hallazgos"][0])

    def test_hexadecimal(self):
        resultado = qr_forense.analizar_url("http://0x7f000001/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("127.0.0.1", resultado["hallazgos"][0])

    def test_octal(self):
        resultado = qr_forense.analizar_url("http://0177.0.0.01/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("127.0.0.1", resultado["hallazgos"][0])

    def test_ipv6_literal(self):
        resultado = qr_forense.analizar_url("http://[::1]/")
        self.assertEqual(resultado["dominio"], "::1")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("IPv6", resultado["hallazgos"][0])

    def test_ip_en_puntos_no_se_duplica(self):
        resultado = qr_forense.analizar_url("http://192.168.1.1/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertEqual(len(resultado["hallazgos"]), 1)

    def test_dominio_normal_no_se_marca(self):
        resultado = qr_forense.analizar_url("https://dgt.es/tramite")
        self.assertEqual(
            resultado["hallazgos"],
            ["No se han detectado patrones sospechosos estructurales en la URL."],
        )


class TestIpDisfrazadaAbreviadaOMixta(unittest.TestCase):
    """El analizador de IPv4 de la especificación WHATWG URL también
    reconoce las formas abreviadas o mixtas (menos de cuatro componentes, o
    componentes en distinta base), que un navegador interpreta como la
    misma IP que su forma completa en puntos, y que las comprobaciones de
    un único componente íntegramente decimal, hexadecimal u octal no
    cubrían."""

    def test_decimal_abreviada_de_dos_componentes(self):
        resultado = qr_forense.analizar_url("http://127.1/")
        self.assertEqual(resultado["dominio"], "127.1")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("127.0.0.1", resultado["hallazgos"][0])

    def test_hexadecimal_abreviada_de_dos_componentes(self):
        resultado = qr_forense.analizar_url("http://0x7f.1/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("127.0.0.1", resultado["hallazgos"][0])

    def test_octal_abreviada_de_dos_componentes(self):
        resultado = qr_forense.analizar_url("http://0177.1/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("127.0.0.1", resultado["hallazgos"][0])

    def test_mixta_de_tres_componentes(self):
        resultado = qr_forense.analizar_url("http://0x7f.0.1/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)
        self.assertIn("127.0.0.1", resultado["hallazgos"][0])

    def test_componente_fuera_de_rango_no_es_ip(self):
        # "0x999" (2457 en decimal) no es válido como componente que no sea
        # el último (debe estar entre 0 y 255), así que esto no es una IP
        # para la especificación y no debe puntuarse como tal.
        resultado = qr_forense.analizar_url("https://0x999.1/x")
        self.assertEqual(
            resultado["hallazgos"],
            ["No se han detectado patrones sospechosos estructurales en la URL."],
        )

    def test_mas_de_cuatro_componentes_no_es_ip(self):
        resultado = qr_forense.analizar_url("https://127.0.0.0.1/x")
        self.assertFalse(any("dirección IP" in h or "IP disfrazada" in h for h in resultado["hallazgos"]))

    def test_dominio_normal_no_se_marca(self):
        resultado = qr_forense.analizar_url("https://e.test/x")
        self.assertEqual(
            resultado["hallazgos"],
            ["No se han detectado patrones sospechosos estructurales en la URL."],
        )


class TestEsquemaPeligroso(unittest.TestCase):
    """Un esquema como javascript:, data:, vbscript:, file:, blob: o
    intent: no tiene host que analizar, pero sigue siendo contenido de
    alto riesgo: se puntúa con 6 (ALTO) directamente, en vez de quedar sin
    analizar por no tener '://'."""

    def test_javascript_es_url_y_se_puntua_como_alto(self):
        self.assertTrue(qr_forense.es_url("javascript:alert(1)"))
        resultado = qr_forense.analizar_url("javascript:alert(1)")
        self.assertEqual(resultado["dominio"], "")
        self.assertEqual(resultado["puntuacion_riesgo"], 6)
        self.assertEqual(qr_forense.clasificar_riesgo(resultado["puntuacion_riesgo"]), "ALTO")
        self.assertIn("javascript:", resultado["hallazgos"][0])

    def test_data_tambien_se_puntua_como_alto(self):
        resultado = qr_forense.analizar_url("data:text/html,<script>alert(1)</script>")
        self.assertEqual(resultado["puntuacion_riesgo"], 6)

    def test_esquema_normal_no_se_trata_como_peligroso(self):
        resultado = qr_forense.analizar_url("https://dgt.es/tramite")
        self.assertEqual(
            resultado["hallazgos"],
            ["No se han detectado patrones sospechosos estructurales en la URL."],
        )


class TestEsquemaSinCifrar(unittest.TestCase):
    """'http://' explícito en el contenido original suma +1, pero no si el
    contenido no traía ningún esquema (lo añade el propio script) ni si el
    destino ya es una IP, puntuada aparte."""

    def test_http_explicito_suma_un_punto(self):
        resultado = qr_forense.analizar_url("http://example.com/")
        self.assertEqual(resultado["puntuacion_riesgo"], 1)
        self.assertIn("http://", resultado["hallazgos"][0])

    def test_https_no_suma_nada(self):
        resultado = qr_forense.analizar_url("https://example.com/")
        self.assertEqual(resultado["puntuacion_riesgo"], 0)

    def test_sin_esquema_no_suma_nada(self):
        resultado = qr_forense.analizar_url("www.example.com")
        self.assertEqual(resultado["puntuacion_riesgo"], 0)

    def test_ip_en_puntos_no_suma_el_punto_de_http(self):
        resultado = qr_forense.analizar_url("http://192.168.1.1/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)

    def test_ip_disfrazada_no_suma_el_punto_de_http(self):
        resultado = qr_forense.analizar_url("http://2130706433/")
        self.assertEqual(resultado["puntuacion_riesgo"], 3)


class TestCredencialesEnLaUrl(unittest.TestCase):
    """'usuario:contraseña@' suma +1, independiente y además de los +4 del
    truco del '@' (comprobación 1): son dos hallazgos distintos sobre el
    mismo trozo de URL."""

    def test_usuario_y_contrasena_suman_los_dos_hallazgos(self):
        resultado = qr_forense.analizar_url("https://usuario:1234@evil.com/")
        self.assertEqual(resultado["puntuacion_riesgo"], 5)
        self.assertEqual(len(resultado["hallazgos"]), 2)
        self.assertIn("@", resultado["hallazgos"][0])
        self.assertIn("credenciales", resultado["hallazgos"][1])

    def test_arroba_sin_dos_puntos_no_genera_el_hallazgo_de_credenciales(self):
        resultado = qr_forense.analizar_url("https://dgt.es@pagos-seguros.top/verifica")
        self.assertFalse(any("credenciales" in h for h in resultado["hallazgos"]))

    def test_sin_arroba_no_genera_ningun_hallazgo_de_credenciales(self):
        resultado = qr_forense.analizar_url("https://dgt.es/tramite")
        self.assertFalse(any("credenciales" in h for h in resultado["hallazgos"]))


class TestPlegarDiacriticos(unittest.TestCase):
    """plegar_diacriticos permite comparar palabras de urgencia en varios
    idiomas sin depender de cómo se hayan escrito las tildes, diéresis y
    demás diacríticos en el contenido del QR."""

    def test_vocal_con_tilde_o_dieresis_se_pliega_con_nfkd(self):
        self.assertEqual(qr_forense.plegar_diacriticos("zahlungsrückstand"), "zahlungsruckstand")
        self.assertEqual(qr_forense.plegar_diacriticos("eräpäivä"), "erapaiva")

    def test_letras_sin_descomposicion_canonica_usan_el_mapa(self):
        self.assertEqual(qr_forense.plegar_diacriticos("spærret"), "spaerret")
        self.assertEqual(qr_forense.plegar_diacriticos("bußgeld"), "bussgeld")
        self.assertEqual(qr_forense.plegar_diacriticos("zaległość"), "zaleglosc")

    def test_texto_sin_diacriticos_no_cambia(self):
        self.assertEqual(qr_forense.plegar_diacriticos("bloqueado"), "bloqueado")


CASOS_PALABRAS_DE_URGENCIA_MULTILINGUE = [
    (idioma, palabra, variante)
    for idioma, palabras in qr_forense.PALABRAS_ALERTA_POR_IDIOMA.items()
    for palabra in palabras
    for variante in {palabra, qr_forense.plegar_diacriticos(palabra)}
]


class TestPalabrasDeUrgenciaMultilingue(unittest.TestCase):
    """La comprobación 8 también busca, en la ruta o en el host, cada
    palabra de cada bloque de idioma de PALABRAS_ALERTA_POR_IDIOMA, tanto si
    el QR la lleva con sus diacríticos como si los pierde al escribirla
    (p. ej. en una URL sin tildes). En vez de una clase de prueba por
    idioma, una sola tabla recorre todas las palabras de todos los bloques
    (CASOS_PALABRAS_DE_URGENCIA_MULTILINGUE, construida a partir del propio
    diccionario), para que añadir un idioma o una palabra no requiera
    añadir una clase de prueba nueva."""

    def test_cada_palabra_se_detecta_con_y_sin_diacriticos(self):
        for idioma, palabra, variante in CASOS_PALABRAS_DE_URGENCIA_MULTILINGUE:
            with self.subTest(idioma=idioma, palabra=palabra, variante=variante):
                resultado = qr_forense.analizar_url(f"https://e.test/aviso-{variante}")
                hallazgos_de_urgencia = [
                    h for h in resultado["hallazgos"]
                    if h.startswith("Contiene términos asociados a presión/urgencia:")
                ]
                self.assertEqual(len(hallazgos_de_urgencia), 1)
                self.assertIn(palabra, _palabras_de_urgencia(hallazgos_de_urgencia[0]))


class TestColisionesBenignasDePalabrasCortas(unittest.TestCase):
    """Las palabras de alerta se buscan como subcadena del host o de la
    ruta, no como palabra completa (comprobación 8), así que una palabra de
    cinco letras o menos de PALABRAS_ALERTA_POR_IDIOMA podría coincidir por
    accidente dentro de una palabra corriente sin relación con avisos de
    pago. Esta prueba comprueba, para cada una de esas palabras cortas
    ("trahv" en estonio, "kazna" y "ovrha" en croata, "boete" en
    neerlandés), una palabra corriente en español que la contiene como
    subcadena, y que no debe disparar el hallazgo de presión/urgencia. Si
    alguna de las cuatro coincidiera, habría que quitarla de su lista en vez
    de debilitar esta prueba — pero ninguna lo hace con la palabra corriente
    elegida aquí."""

    def _no_genera_el_hallazgo_de_urgencia(self, ruta):
        resultado = qr_forense.analizar_url(f"https://e.test/{ruta}")
        self.assertFalse(any(
            h.startswith("Contiene términos asociados a presión/urgencia:")
            for h in resultado["hallazgos"]
        ))

    def test_trahv_no_coincide_dentro_de_extrahotelero(self):
        # "extrahotelero" (alojamiento turístico no hotelero) contiene
        # "trah" pero no "trahv": a la "h" le sigue una "o", no una "v".
        self._no_genera_el_hallazgo_de_urgencia("alojamiento-extrahotelero")

    def test_kazna_no_coincide_dentro_de_manzana(self):
        self._no_genera_el_hallazgo_de_urgencia("tarta-de-manzana")

    def test_ovrha_no_coincide_dentro_de_sobrehumano(self):
        self._no_genera_el_hallazgo_de_urgencia("esfuerzo-sobrehumano")

    def test_boete_no_coincide_dentro_de_poeta(self):
        self._no_genera_el_hallazgo_de_urgencia("biografia-del-poeta")


class TestDecodificarQrSinOpencv(unittest.TestCase):
    """decodificar_qr debe fallar con un error claro si falta OpenCV, en
    lugar de impedir importar el módulo cuando no está instalado."""

    def test_error_claro_si_falta_opencv(self):
        with mock.patch.dict(sys.modules, {"cv2": None}):
            with self.assertRaises(RuntimeError) as contexto:
                qr_forense.decodificar_qr(Path("no-existe.png"))
        self.assertIn("opencv-python", str(contexto.exception))


if __name__ == "__main__":
    unittest.main()
