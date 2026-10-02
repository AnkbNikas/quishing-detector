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
    """Un host vacío (p. ej. "http:///login") no tiene dominio que
    comprobar, así que se trata como una URL malformada, igual que una
    que urlsplit() no puede interpretar."""

    def test_host_vacio_se_trata_como_url_malformada(self):
        resultado = qr_forense.analizar_url("http:///login")
        self.assertEqual(resultado["dominio"], "")
        self.assertEqual(resultado["puntuacion_riesgo"], 0)
        self.assertEqual(
            resultado["hallazgos"],
            ["URL malformada o no analizable: no contiene ningún host."],
        )
        self.assertEqual(qr_forense.clasificar_riesgo(resultado["puntuacion_riesgo"]), "BAJO")


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
