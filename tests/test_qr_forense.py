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


class TestAnalizarUrlEjemplos(unittest.TestCase):
    """Fija la puntuación y los hallazgos de analizar_url para los cinco
    casos de ejemplos/."""

    def _comparar_con_ejemplo(self, nombre_json):
        url, esperado = _cargar_ejemplo(nombre_json)
        resultado = qr_forense.analizar_url(url)

        self.assertEqual(resultado["dominio"], esperado["dominio"])
        self.assertEqual(resultado["puntuacion_riesgo"], esperado["puntuacion_riesgo"])
        self.assertEqual(len(resultado["hallazgos"]), len(esperado["hallazgos"]))

    def test_acortador(self):
        self._comparar_con_ejemplo("test_qr_acortador.json")

    def test_arroba(self):
        self._comparar_con_ejemplo("test_qr_arroba.json")

    def test_ip(self):
        self._comparar_con_ejemplo("test_qr_ip.json")

    def test_legitimo(self):
        self._comparar_con_ejemplo("test_qr_legitimo.json")

    def test_suplantacion(self):
        self._comparar_con_ejemplo("test_qr_suplantacion.json")


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
