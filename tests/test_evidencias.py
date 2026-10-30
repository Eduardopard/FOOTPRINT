"""Prueba de aceptación con las evidencias del reto.

Comprueba que FootPrint reconstruye, sin ayuda, lo que el equipo verificó a mano.
Indica la carpeta con la variable EVIDENCIAS (por defecto ./evidencias):

    EVIDENCIAS=/ruta/a/evidencias pytest -v
"""
import os
from pathlib import Path

import pytest

from footprint import analizar_carpeta

CARPETA = Path(os.environ.get("EVIDENCIAS", "evidencias"))
pytestmark = pytest.mark.skipif(not (CARPETA / "firewall.csv").exists(),
                                reason="evidencias no disponibles")


@pytest.fixture(scope="module")
def res():
    return analizar_carpeta(CARPETA)


def test_un_solo_incidente_en_fin_pc07(res):
    assert len(res.incidentes) == 1
    inc = res.incidentes[0]
    assert (inc.host, inc.usuario) == ("FIN-PC07", "dtorres")


def test_cadena_completa(res):
    assert res.incidentes[0].tacticas == ["Acceso inicial", "Ejecución", "Mando y control", "Descubrimiento",
                                          "Movimiento lateral", "Colección", "Exfiltración"]


def test_evidencias_clave_citadas(res):
    refs = {str(e) for a in res.incidentes[0].alertas for e in a.evidencias}
    for esperado in ["proxy.csv:539", "endpoint.csv:954", "firewall.csv:2265", "endpoint.csv:1148",
                     "firewall.csv:2727", "authentication.csv:712", "endpoint.csv:1933", "firewall.csv:3691"]:
        assert esperado in refs, esperado


def test_primera_y_ultima_hora(res):
    inc = res.incidentes[0]
    assert inc.inicio.strftime("%H:%M:%S") == "10:12:41"
    exf = [a for a in inc.alertas if a.tactica == "Exfiltración"][0]
    assert exf.inicio.strftime("%H:%M:%S") == "11:46:13"


def test_ruido_no_entra_al_incidente(res):
    aisladas = {(a.host, a.regla) for a in res.aisladas}
    assert ("FS01", "R08") in aisladas                      # respaldo a destino habitual
    assert all(a.host != "FIN-PC07" for a in res.aisladas)


def test_pcap_alineado_y_confirma_c2(res):
    assert 3590 <= res.pcap["desfase_s"] <= 3615
    p01 = [a for a in res.incidentes[0].alertas if a.regla == "P01"]
    assert p01 and p01[0].indicadores["ip"] == ["203.0.113.77"]
    assert p01[0].inicio.strftime("%H:%M") == "10:17"       # hora ya corregida


def test_hipotesis_separadas_de_hechos(res):
    tipos = {t for t, _ in res.incidentes[0].hipotesis}
    assert tipos == {"Hecho", "Hipótesis", "No determinable"}
    textos = " ".join(x for _, x in res.incidentes[0].hipotesis)
    assert "98.7%" in textos and "docs_2026.zip" in textos


def test_hash_de_cada_fuente(res):
    assert len(res.inventario) == 6 and all(len(m["sha256"]) == 64 for m in res.inventario)
