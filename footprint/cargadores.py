"""Carga de evidencias.

Cada CSV se reconoce por sus columnas, no por su nombre, así que el sistema acepta
archivos renombrados o exportados por otras herramientas con el mismo esquema.
Se guarda el número de línea original (línea 1 = encabezado) para citar evidencia.
"""
import hashlib
import io

import pandas as pd

FIRMAS = {
    "authentication": {"event_id", "logon_type", "result"},
    "dns": {"query", "query_type", "response"},
    "endpoint": {"event_type", "process_name", "command_line"},
    "firewall": {"direction", "action", "bytes_sent"},
    "proxy": {"url", "domain", "http_status"},
}


def sha256(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def detectar_tipo(columnas) -> str | None:
    cols = {c.strip().lower() for c in columnas}
    for tipo, firma in FIRMAS.items():
        if firma <= cols:
            return tipo
    return None


def leer_csv(nombre: str, datos: bytes):
    """Devuelve (tipo, DataFrame) o (None, None) si el esquema no se reconoce."""
    df = pd.read_csv(io.BytesIO(datos), dtype=str, keep_default_na=False)
    df.columns = [c.strip().lower() for c in df.columns]
    tipo = detectar_tipo(df.columns)
    if tipo is None:
        return None, None
    df["_linea"] = range(2, len(df) + 2)
    df["_fuente"] = nombre
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ("bytes_sent", "bytes_received", "duration_seconds", "destination_port",
                "bytes_received", "http_status", "event_id"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["ts"]).sort_values("ts", kind="stable").reset_index(drop=True)
    return tipo, df


def mapa_ip_host(fuentes: dict) -> dict:
    """IP -> nombre de host, aprendido de los propios logs."""
    mapa = {}
    for df in fuentes.values():
        for ip_col, host_col in (("source_ip", "source_host"), ("destination_ip", "destination_host")):
            if ip_col in df.columns and host_col in df.columns:
                pares = df[[ip_col, host_col]]
                pares = pares[(pares[ip_col] != "") & (pares[host_col] != "")]
                for ip, host in pares.drop_duplicates().itertuples(index=False):
                    mapa.setdefault(ip, host)
    return mapa
