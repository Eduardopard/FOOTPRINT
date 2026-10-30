"""Reglas de detección genéricas sobre los logs CSV.

Cada regla recibe los DataFrames ya cargados y la configuración, y devuelve una
lista de Alertas con las líneas exactas que las sustentan. Ninguna regla conoce
IPs, dominios ni nombres de host concretos: todo se decide por comportamiento,
rareza frente al resto de la red o umbrales de config.yaml.
"""
import ipaddress
import re

import pandas as pd

from .modelo import Alerta, Evidencia


# ---------------------------------------------------------------- utilidades
def _ev(df):
    return [Evidencia(f, str(l)) for f, l in zip(df["_fuente"], df["_linea"])]


def _ev_rango(df):
    """Una sola evidencia para muchas filas: primera…última (N filas)."""
    if len(df) <= 6:
        return _ev(df)
    return [Evidencia(df["_fuente"].iloc[0],
                      f"{df['_linea'].min()}…{df['_linea'].max()} ({len(df)} filas)")]


def _sesiones(df, ventana_min):
    """Agrupa filas ordenadas por ts en sesiones separadas por huecos > ventana."""
    if df.empty:
        return []
    df = df.sort_values("ts")
    corte = df["ts"].diff() > pd.Timedelta(minutes=ventana_min)
    return [g for _, g in df.groupby(corte.cumsum())]


def _ventana_densa(df, ventana_min, minimo):
    """Filas que caen en alguna ventana de `ventana_min` con al menos `minimo` filas."""
    t = df["ts"].sort_values().values
    w = pd.Timedelta(minutes=ventana_min).to_timedelta64()
    densas = set()
    j = 0
    for i in range(len(t)):
        while t[i] - t[j] > w:
            j += 1
        if i - j + 1 >= minimo:
            densas.update(range(j, i + 1))
    return df.sort_values("ts").iloc[sorted(densas)] if densas else df.iloc[0:0]


def _hhmmss(ts):
    return ts.strftime("%H:%M:%S")


# ---------------------------------------------------------------- PROXY
def descarga_rara(px, cfg):
    c = cfg["proxy_descarga_rara"]
    por_dom = px.groupby("domain").agg(visitas=("domain", "size"), usuarios=("username", "nunique"))
    raros = por_dom[(por_dom.visitas <= c["max_visitas_dominio"]) &
                    (por_dom.usuarios <= c["max_usuarios_dominio"])].index
    total_dom = len(por_dom)
    alertas = []
    for dom in raros:
        filas = px[px.domain == dom]
        riesgo = filas[filas.content_type.str.lower().isin(c["tipos_riesgo"])]
        f0 = filas.iloc[0]
        if len(riesgo):
            r = riesgo.iloc[0]
            archivo = r.url.rsplit("/", 1)[-1]
            alertas.append(Alerta(
                regla="R01", titulo=f"Descarga de {archivo} desde dominio poco común",
                tactica="Acceso inicial", tecnica="T1204.002 · T1566.002 (probable)",
                severidad=4, host=f0.source_host, usuario=f0.username,
                inicio=f0.ts, fin=r.ts,
                descripcion=(f"{dom} solo aparece {len(filas)} veces, todas de {f0.username}, frente a "
                             f"{total_dom - len(raros)} dominios habituales. Se descargó {archivo} "
                             f"({r.content_type}, {int(r.bytes_received):,} B) a las {_hhmmss(r.ts)}."),
                evidencias=_ev(filas),
                indicadores={"dominio": [dom], "url": list(riesgo.url), "archivo": [archivo]}))
        else:
            alertas.append(Alerta(
                regla="R01", titulo=f"Visita a dominio poco común ({dom})", tactica="Informativa",
                tecnica="—", severidad=1, host=f0.source_host, usuario=f0.username,
                inicio=f0.ts, fin=filas.ts.iloc[-1],
                descripcion=f"{dom} solo aparece {len(filas)} veces en el proxy.",
                evidencias=_ev(filas), indicadores={"dominio": [dom]}))
    return alertas


# ---------------------------------------------------------------- ENDPOINT
def powershell_sospechoso(ep, cfg):
    c = cfg["powershell_sospechoso"]
    patrones = [re.compile(p, re.I) for p in c["patrones"]]
    ps = ep[ep.process_name.str.lower().isin(["powershell.exe", "pwsh.exe"])]
    alertas = []
    for _, r in ps.iterrows():
        hits = [p.pattern for p in patrones if p.search(r.command_line)]
        if len(hits) < c["min_patrones"]:
            continue
        oculto = bool(re.search(r"hidden", r.command_line, re.I))
        script = re.findall(r"[a-z]:\\[^ ]+\.ps1", r.command_line, re.I)
        alertas.append(Alerta(
            regla="R02", titulo="PowerShell con parámetros de evasión",
            tactica="Ejecución", tecnica="T1059.001" + (" · T1564.003" if oculto else ""),
            severidad=4, host=r.host, usuario=r.username, inicio=r.ts, fin=r.ts,
            descripcion=(f"Proceso padre {r.parent_process}. Coinciden {len(hits)} patrones de abuso "
                         f"(ventana oculta, bypass de política, rutas temporales...). Comando: {r.command_line}"),
            evidencias=_ev(ps.loc[[r.name]]), indicadores={"archivo": script}))
    return alertas


def reconocimiento(ep, cfg):
    c = cfg["reconocimiento"]
    rec = ep[ep.process_name.str.lower().isin(c["procesos"])]
    alertas = []
    for host, g in rec.groupby("host"):
        for s in _sesiones(g, c["ventana_min"]):
            if len(s) < c["min_comandos"]:
                continue
            cmds = ", ".join(s.command_line)
            alertas.append(Alerta(
                regla="R03", titulo=f"Reconocimiento: {len(s)} comandos de descubrimiento",
                tactica="Descubrimiento", tecnica="T1033 · T1018 · T1135",
                severidad=3, host=host, usuario=s.username.iloc[0],
                inicio=s.ts.iloc[0], fin=s.ts.iloc[-1],
                descripcion=f"En {(s.ts.iloc[-1] - s.ts.iloc[0]).seconds // 60 + 1} min: {cmds}.",
                evidencias=_ev(s)))
    return alertas


def acceso_masivo(ep, cfg):
    c = cfg["acceso_masivo_archivos"]
    fa = ep[ep.event_type.str.upper() == "FILE_ACCESS"]
    alertas = []
    for (host, user), g in fa.groupby(["host", "username"]):
        densas = _ventana_densa(g, c["ventana_min"], c["min_archivos"])
        for s in _sesiones(densas, c["ventana_min"]):
            dur = (s.ts.iloc[-1] - s.ts.iloc[0]).total_seconds()
            carpetas = s.file_path.str.extract(r"^(\\\\[^\\]+\\[^\\]+)")[0].dropna().unique()
            subc = s.file_path.str.split("\\").str[-2].value_counts()
            ritmo = dur / max(len(s) - 1, 1)
            alertas.append(Alerta(
                regla="R04", titulo=f"Lectura masiva: {len(s)} archivos en {dur / 60:.0f} min",
                tactica="Colección", tecnica="T1039",
                severidad=4, host=host, usuario=user, inicio=s.ts.iloc[0], fin=s.ts.iloc[-1],
                descripcion=(f"{len(s)} lecturas, una cada {ritmo:.1f} s de media, en "
                             f"{', '.join(carpetas) or 'rutas locales'}. Por carpeta: "
                             + ", ".join(f"{k} {v}" for k, v in subc.items()) + ". "
                             "Un ritmo constante de segundos sugiere un script, no a una persona."),
                evidencias=_ev_rango(s), indicadores={"recurso": list(carpetas)}))
    return alertas


def compresion(ep, cfg):
    c = cfg["compresion"]
    exts = tuple(c["extensiones"])
    proc = ep[ep.process_name.str.lower().isin(c["procesos"]) |
              ep.command_line.str.contains("compress-archive", case=False)]
    arch = ep[(ep.event_type.str.upper() == "FILE_CREATE") &
              ep.file_path.str.lower().str.endswith(exts) &
              ep.file_path.str.contains(r"\\(?:temp|appdata|public|programdata)\\", case=False)]
    todo = pd.concat([proc, arch]).sort_values("ts")
    alertas = []
    for host, g in todo.groupby("host"):
        for s in _sesiones(g, 30):
            tam = s.details.str.extract(r"size=(\d+)")[0].dropna()
            tam = int(tam.iloc[0]) if len(tam) else None
            rutas = [p for p in s.file_path if p] or re.findall(r"[a-z]:\\\S+\.(?:zip|7z|rar|cab|tar|gz)",
                                                               " ".join(s.command_line), re.I)
            desc = "; ".join(x for x in s.command_line if x)
            alertas.append(Alerta(
                regla="R05", titulo="Compresión de datos en ruta temporal",
                tactica="Colección", tecnica="T1560.001 · T1074.001",
                severidad=3, host=host, usuario=s.username.iloc[0],
                inicio=s.ts.iloc[0], fin=s.ts.iloc[-1],
                descripcion=(f"{desc}. " if desc else "") +
                            (f"Archivo creado: {rutas[0]} ({tam:,} B)." if tam and rutas else ""),
                evidencias=_ev(s), indicadores={"archivo": rutas[:3], "tamano": [tam] if tam else []}))
    return alertas


# ---------------------------------------------------------------- FIREWALL + DNS
def beaconing(fw, dns, cfg):
    c = cfg["beaconing"]
    sal = fw[fw.direction.str.upper() == "OUTBOUND"]
    hosts_por_destino = sal.groupby("destination_ip").source_host.nunique()
    peq = sal[sal.bytes_sent <= c["max_bytes_por_conexion"]]
    alertas = []
    for (host, ip), g in peq.groupby(["source_host", "destination_ip"]):
        if len(g) < c["min_conexiones"] or hosts_por_destino.get(ip, 0) > c["max_hosts_destino"]:
            continue
        inter = g.ts.diff().dt.total_seconds().dropna()
        cv = inter.std() / inter.mean() if inter.mean() else 1
        if cv > c["max_coef_variacion"]:
            continue
        resol = dns[dns.response == ip] if dns is not None else pd.DataFrame()
        dominios = sorted(resol["query"].unique()) if len(resol) else []
        quien = resol.source_host.nunique() if len(resol) else 0
        alertas.append(Alerta(
            regla="R06", titulo=f"Beaconing cada {inter.mean() / 60:.1f} min hacia {ip}",
            tactica="Mando y control", tecnica="T1071.001 · T1573",
            severidad=4, host=host, inicio=g.ts.iloc[0], fin=g.ts.iloc[-1],
            descripcion=(f"{len(g)} conexiones cortas con intervalo medio de {inter.mean():.0f} s "
                         f"(variación {cv:.1%}). Ningún otro host contacta este destino."
                         + (f" Resuelto desde {', '.join(dominios)}, consultado por {quien} host(s)."
                            if dominios else "")),
            evidencias=_ev(g) + (_ev(resol) if len(resol) else []),
            indicadores={"ip": [ip], "dominio": dominios}))
    return alertas


def barrido_smb(fw, cfg):
    c = cfg["barrido_smb"]
    i = fw[(fw.direction.str.upper() == "INTERNAL") & fw.destination_port.isin(c["puertos"]) &
           (fw.bytes_sent <= c["max_bytes"]) & (fw.bytes_received <= c["max_bytes"])]
    alertas = []
    for host, g in i.groupby("source_host"):
        for s in _sesiones(g, c["ventana_min"]):
            if s.destination_ip.nunique() < c["min_destinos"]:
                continue
            den = s[s.action.str.upper() == "DENY"]
            nombres = [h or ip for h, ip in zip(s.destination_host, s.destination_ip)]
            alertas.append(Alerta(
                regla="R07", titulo=f"Barrido SMB a {s.destination_ip.nunique()} equipos",
                tactica="Movimiento lateral", tecnica="T1046 · T1021.002 (intento)",
                severidad=4, host=host, inicio=s.ts.iloc[0], fin=s.ts.iloc[-1],
                descripcion=(f"Conexiones de pocos bytes a {', '.join(nombres)} "
                             f"en {(s.ts.iloc[-1] - s.ts.iloc[0]).seconds // 60 + 1} min; "
                             f"{len(den)} bloqueadas por el firewall."),
                evidencias=_ev(s),
                indicadores={"destino": nombres,
                             "bloqueado": [h or ip for h, ip in zip(den.destination_host, den.destination_ip)]}))
    return alertas


def salida_grande(fw, cfg):
    c = cfg["salida_grande"]
    sal = fw[fw.direction.str.upper() == "OUTBOUND"]
    conex = sal.destination_ip.value_counts()
    grandes = sal[sal.bytes_sent >= c["min_bytes"]]
    alertas = []
    for _, r in grandes.iterrows():
        n = int(conex.get(r.destination_ip, 0))
        raro = n < c["max_conexiones_destino_raro"]
        mb = r.bytes_sent / 2 ** 20
        alertas.append(Alerta(
            regla="R08",
            titulo=(f"Exfiltración: {mb:.0f} MiB a destino poco común" if raro
                    else f"Transferencia grande ({mb:.0f} MiB) a destino habitual"),
            tactica="Exfiltración" if raro else "Informativa",
            tecnica="T1041" if raro else "—",
            severidad=5 if raro else 1, host=r.source_host, inicio=r.ts,
            fin=r.ts + pd.Timedelta(seconds=float(r.duration_seconds or 0)),
            descripcion=(f"{int(r.bytes_sent):,} B enviados a {r.destination_ip}:{int(r.destination_port)} "
                         f"en {int(r.duration_seconds)} s. Ese destino tiene {n} conexiones en todo el registro."
                         + ("" if raro else " Es un destino que la red usa a diario: revisar si es un proceso "
                                            "programado (respaldo, sincronización).")),
            evidencias=_ev(sal.loc[[r.name]]),
            indicadores={"ip": [r.destination_ip], "bytes": [int(r.bytes_sent)]} if raro else {"bytes": [int(r.bytes_sent)]}))
    return alertas


# ---------------------------------------------------------------- AUTENTICACIÓN
def fallos_autenticacion(au, cfg):
    c = cfg["fallos_autenticacion"]
    red_est = ipaddress.ip_network(cfg["red"]["estaciones"])
    alertas = []
    fallos = au[au.result.str.upper() == "FAILURE"]
    for user, g in fallos.groupby("username"):
        for s in _sesiones(g, c["ventana_min"]):
            if len(s) >= c["min_fallos"] and s.destination_host.nunique() >= c["min_destinos"]:
                alertas.append(Alerta(
                    regla="R09", titulo=f"{len(s)} accesos fallidos a {s.destination_host.nunique()} equipos",
                    tactica="Movimiento lateral", tecnica="T1021.002 (intento)",
                    severidad=2, host=s.source_host.iloc[0], usuario=user,
                    inicio=s.ts.iloc[0], fin=s.ts.iloc[-1],
                    descripcion=f"Destinos: {', '.join(s.destination_host)}. Motivos: "
                                f"{', '.join(s.failure_reason.value_counts().index)}.",
                    evidencias=_ev(s)))

    def es_estacion(ip):
        try:
            return ipaddress.ip_address(ip) in red_est
        except ValueError:
            return False

    a_est = au[au.destination_ip.map(es_estacion)]
    for _, r in a_est.iterrows():
        alertas.append(Alerta(
            regla="R10", titulo=f"Autenticación de red hacia la estación {r.destination_host}",
            tactica="Movimiento lateral", tecnica="T1021.002",
            severidad=3, host=r.source_host, usuario=r.username, inicio=r.ts, fin=r.ts,
            descripcion=(f"Resultado {r.result} ({r.failure_reason or 'sin motivo'}). Entre estaciones de "
                         f"usuario no debería haber autenticaciones de red; hay {len(a_est)} en todo el registro."),
            evidencias=_ev(au.loc[[r.name]])))
    return alertas


def uso_de_cuentas(au):
    """Para cada usuario: desde cuántos hosts distintos se autentica (para hipótesis)."""
    return au.groupby("username").source_host.unique().to_dict()


def ejecutar_reglas(f, cfg):
    """f = dict tipo -> DataFrame. Ejecuta cada regla para la que existan datos."""
    alertas = []
    if "proxy" in f:
        alertas += descarga_rara(f["proxy"], cfg)
    if "endpoint" in f:
        ep = f["endpoint"]
        alertas += powershell_sospechoso(ep, cfg) + reconocimiento(ep, cfg)
        alertas += acceso_masivo(ep, cfg) + compresion(ep, cfg)
    if "firewall" in f:
        fw = f["firewall"]
        alertas += beaconing(fw, f.get("dns"), cfg) + barrido_smb(fw, cfg) + salida_grande(fw, cfg)
    if "authentication" in f:
        alertas += fallos_autenticacion(f["authentication"], cfg)
    return alertas
