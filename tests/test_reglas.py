"""Pruebas unitarias con datos sintéticos: cada regla dispara con el patrón
malicioso y NO dispara con un patrón parecido pero legítimo."""
from datetime import datetime, timedelta

import pandas as pd
import pytest

from footprint import analizar, cargar_config
from footprint.cargadores import detectar_tipo, leer_csv
from footprint import reglas

CFG = cargar_config()
T0 = datetime(2026, 1, 1, 9, 0, 0)


def csv(filas, columnas):
    df = pd.DataFrame(filas, columns=columnas)
    return df.to_csv(index=False).encode()


FW_COLS = ["timestamp", "source_ip", "source_host", "destination_ip", "destination_host", "destination_port",
           "protocol", "direction", "action", "bytes_sent", "bytes_received", "duration_seconds"]


def fw(filas):
    return leer_csv("firewall.csv", csv(filas, FW_COLS))[1]


def conexion(t, src, host, dst, port=443, direction="OUTBOUND", action="ALLOW", sent=1500, recv=4000, dur=3, dsth=""):
    return [t.isoformat(), src, host, dst, dsth, port, "TCP", direction, action, sent, recv, dur]


def test_detecta_tipo_por_columnas():
    assert detectar_tipo(FW_COLS) == "firewall"
    assert detectar_tipo(["timestamp", "query", "query_type", "response"]) == "dns"
    assert detectar_tipo(["a", "b"]) is None


def test_beaconing_regular_dispara():
    filas = [conexion(T0 + timedelta(seconds=300 * i + (i % 2) * 4), "10.0.0.5", "PC1", "203.0.113.9") for i in range(6)]
    filas += [conexion(T0 + timedelta(seconds=37 * i ** 2), f"10.0.0.{i % 4 + 1}", f"PC{i % 4 + 1}", "198.51.100.1")
              for i in range(30)]
    alertas = reglas.beaconing(fw(filas), None, CFG)
    assert len(alertas) == 1 and alertas[0].indicadores["ip"] == ["203.0.113.9"]


def test_beaconing_irregular_no_dispara():
    tiempos = [0, 40, 400, 410, 1500, 1520]
    filas = [conexion(T0 + timedelta(seconds=s), "10.0.0.5", "PC1", "203.0.113.9") for s in tiempos]
    assert reglas.beaconing(fw(filas), None, CFG) == []


def test_destino_compartido_no_es_beacon():
    # Conexiones periódicas a un destino que usa toda la red (p. ej. una actualización) no son C2.
    filas = [conexion(T0 + timedelta(seconds=300 * i), f"10.0.0.{h}", f"PC{h}", "198.51.100.7")
             for i in range(6) for h in (1, 2, 3)]
    assert reglas.beaconing(fw(filas), None, CFG) == []


def test_salida_grande_destino_raro_vs_habitual():
    filas = [conexion(T0, "10.0.0.5", "PC1", "203.0.113.9", sent=200_000_000, dur=400)]
    filas += [conexion(T0 + timedelta(minutes=i), "10.0.0.9", "SRV", "198.51.100.44") for i in range(30)]
    filas += [conexion(T0 + timedelta(hours=1), "10.0.0.9", "SRV", "198.51.100.44", sent=500_000_000, dur=600)]
    al = {a.host: a for a in reglas.salida_grande(fw(filas), CFG)}
    assert al["PC1"].severidad == 5 and al["PC1"].tactica == "Exfiltración"
    assert al["SRV"].severidad == 1          # destino habitual: solo informativa


def test_barrido_smb():
    filas = [conexion(T0 + timedelta(seconds=45 * i), "10.20.10.5", "PC1", f"10.20.20.{i}", port=445,
                      direction="INTERNAL", action="DENY" if i % 2 else "ALLOW", sent=500, recv=900)
             for i in range(1, 6)]
    al = reglas.barrido_smb(fw(filas), CFG)
    assert len(al) == 1 and "5 equipos" in al[0].titulo and "3 bloqueadas" in al[0].descripcion


def test_powershell_oculto_vs_administrativo():
    cols = ["timestamp", "host", "username", "event_type", "process_name", "parent_process", "command_line",
            "file_path", "destination_ip", "destination_port", "details"]
    filas = [[T0.isoformat(), "PC1", "ana", "PROCESS_CREATE", "powershell.exe", "explorer.exe",
              r"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\ana\AppData\Local\Temp\x.ps1",
              "", "", "", ""],
             [T0.isoformat(), "IT1", "admin", "PROCESS_CREATE", "powershell.exe", "explorer.exe",
              "powershell.exe Get-Service", "", "", "", ""]]
    ep = leer_csv("endpoint.csv", csv(filas, cols))[1]
    al = reglas.powershell_sospechoso(ep, CFG)
    assert [a.host for a in al] == ["PC1"]


def test_acceso_masivo_umbral():
    cols = ["timestamp", "host", "username", "event_type", "process_name", "parent_process", "command_line",
            "file_path", "destination_ip", "destination_port", "details"]
    def lecturas(n, paso):
        return [[(T0 + timedelta(seconds=paso * i)).isoformat(), "PC1", "ana", "FILE_ACCESS", "", "", "",
                 rf"\\FS\Datos\doc_{i}.xlsx", "", "", "READ"] for i in range(n)]
    assert len(reglas.acceso_masivo(leer_csv("e.csv", csv(lecturas(150, 3), cols))[1], CFG)) == 1
    assert reglas.acceso_masivo(leer_csv("e.csv", csv(lecturas(40, 3), cols))[1], CFG) == []


def test_alerta_aislada_no_abre_incidente():
    filas = [conexion(T0, "10.0.0.5", "PC1", "203.0.113.9", sent=200_000_000, dur=400)]
    res = analizar([("firewall.csv", csv(filas, FW_COLS))])
    assert res.incidentes == [] and len(res.aisladas) == 1


def test_archivo_no_reconocido_genera_advertencia():
    res = analizar([("raro.csv", b"a,b\n1,2\n")])
    assert any("no reconocido" in w for w in res.advertencias)


def test_exportacion_csv_neutraliza_formulas():
    from footprint.reporte import _csv_seguro
    assert _csv_seguro("=HYPERLINK(\"x\")").startswith("'")
    assert _csv_seguro("normal") == "normal"
