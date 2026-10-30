"""Punto de entrada del motor: archivos -> fuentes -> alertas -> incidentes -> hipótesis."""
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
import yaml

from . import pcap as pcapmod
from .cargadores import leer_csv, mapa_ip_host, sha256
from .correlacion import correlacionar, generar_hipotesis
from .reglas import ejecutar_reglas

CONFIG = Path(__file__).with_name("config.yaml")
MAX_ARCHIVO = 500 * 2 ** 20     # 500 MiB por archivo


def cargar_config(ruta=None):
    with open(ruta or CONFIG, encoding="utf-8") as f:
        return yaml.safe_load(f)


@dataclass
class Resultado:
    fuentes: dict = field(default_factory=dict)        # tipo -> DataFrame
    inventario: list = field(default_factory=list)     # metadatos y hash de cada archivo
    alertas: list = field(default_factory=list)
    incidentes: list = field(default_factory=list)
    aisladas: list = field(default_factory=list)
    pcap: dict = field(default_factory=dict)
    advertencias: list = field(default_factory=list)


def analizar(archivos, cfg=None):
    """archivos: lista de (nombre, bytes). No escribe nada en disco ni usa la red."""
    cfg = cfg or cargar_config()
    r = Resultado()
    pcaps = []
    for nombre, datos in archivos:
        meta = {"archivo": nombre, "bytes": len(datos), "sha256": sha256(datos)}
        if len(datos) > MAX_ARCHIVO:
            r.advertencias.append(f"{nombre}: supera el tamaño máximo y no se procesó.")
            continue
        if nombre.lower().endswith((".pcap", ".pcapng", ".cap")):
            pcaps.append((nombre, datos, meta))
            continue
        try:
            tipo, df = leer_csv(nombre, datos)
        except Exception as e:                      # archivo corrupto o no CSV
            r.advertencias.append(f"{nombre}: no se pudo leer ({e.__class__.__name__}).")
            continue
        if tipo is None:
            r.advertencias.append(f"{nombre}: esquema de columnas no reconocido.")
            continue
        if tipo in r.fuentes:
            df = pd.concat([r.fuentes[tipo], df]).sort_values("ts", kind="stable").reset_index(drop=True)
        r.fuentes[tipo] = df
        meta.update(tipo=tipo, filas=len(df), desde=df.ts.min(), hasta=df.ts.max())
        r.inventario.append(meta)

    r.alertas = ejecutar_reglas(r.fuentes, cfg)
    mapa = mapa_ip_host(r.fuentes)

    for nombre, datos, meta in pcaps:
        try:
            info, dns, fl = pcapmod.leer_pcap(nombre, datos, cfg["pcap"]["max_paquetes"])
        except Exception as e:
            r.advertencias.append(f"{nombre}: no se pudo leer el PCAP ({e.__class__.__name__}).")
            continue
        desfase, coincid = pcapmod.alinear_reloj(fl, r.fuentes.get("firewall"), cfg["pcap"]["tolerancia_alineacion_s"])
        info.update(desfase_s=desfase, coincidencias=coincid, flujos=fl, dns_df=dns)
        r.pcap = info
        meta.update(tipo="pcap", filas=info["paquetes"], desde=info["desde"], hasta=info["hasta"])
        r.inventario.append(meta)
        if info["truncado"]:
            r.advertencias.append(f"{nombre}: se analizaron solo los primeros {cfg['pcap']['max_paquetes']} paquetes.")
        if desfase:
            r.advertencias.append(f"{nombre}: su reloj difiere {desfase:+.0f} s de los logs "
                                  f"({coincid} conexiones coincidentes). Las horas del PCAP se muestran corregidas.")
        r.alertas += pcapmod.detectar(nombre, dns, fl, mapa, desfase, cfg)

    r.incidentes, r.aisladas = correlacionar(r.alertas, cfg)
    for inc in r.incidentes:
        inc.hipotesis = generar_hipotesis(inc, r.fuentes, r.pcap.get("desfase_s", 0), cfg)
    return r


def analizar_carpeta(carpeta, cfg=None):
    rutas = sorted(p for p in Path(carpeta).iterdir()
                   if p.suffix.lower() in (".csv", ".pcap", ".pcapng", ".cap"))
    return analizar([(p.name, p.read_bytes()) for p in rutas], cfg)
