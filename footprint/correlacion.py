"""Correlación: agrupa alertas por equipo y ventana de tiempo, y abre un incidente
solo cuando un mismo equipo acumula varias tácticas distintas de la cadena de
ataque. Una alerta aislada (un fallo de contraseña, un respaldo grande) no basta.
Después genera las hipótesis que enlazan unas fases con otras."""
from collections import Counter

import pandas as pd

from .modelo import TACTICAS, Incidente


def orden_tactica(t):
    return TACTICAS.index(t) if t in TACTICAS else len(TACTICAS)


def correlacionar(alertas, cfg):
    c = cfg["correlacion"]
    ventana = pd.Timedelta(hours=c["ventana_horas"])
    incidentes, aisladas = [], []
    por_host = {}
    for a in alertas:
        por_host.setdefault(a.host, []).append(a)
    for host, lista in por_host.items():
        lista.sort(key=lambda a: a.inicio)
        grupos, actual = [], [lista[0]]
        for a in lista[1:]:
            if a.inicio - max(x.fin for x in actual) <= ventana:
                actual.append(a)
            else:
                grupos.append(actual)
                actual = [a]
        grupos.append(actual)
        for g in grupos:
            relevantes = [a for a in g if a.severidad >= 2 and a.tactica in TACTICAS]
            tacticas = sorted({a.tactica for a in relevantes}, key=orden_tactica)
            if len(tacticas) >= c["min_tacticas_incidente"]:
                usuarios = Counter(a.usuario for a in g if a.usuario)
                incidentes.append(Incidente(
                    host=host, usuario=usuarios.most_common(1)[0][0] if usuarios else "",
                    inicio=min(a.inicio for a in g), fin=max(a.fin for a in g),
                    puntaje=sum(a.severidad for a in relevantes) + 5 * len(tacticas),
                    tacticas=tacticas, alertas=sorted(g, key=lambda a: a.inicio)))
            else:
                aisladas += g
    incidentes.sort(key=lambda i: -i.puntaje)
    return incidentes, sorted(aisladas, key=lambda a: a.inicio)


def generar_hipotesis(inc, fuentes, desfase_pcap, cfg):
    """Devuelve una lista de (tipo, texto). tipo: Hecho | Hipótesis | No determinable."""
    h = cfg["hipotesis"]
    out = []
    por = {}
    for a in inc.alertas:
        por.setdefault(a.regla, []).append(a)

    def primero(*reglas):
        for r in reglas:
            if r in por:
                return por[r][0]
        return None

    ini = primero("R01")
    eje = primero("R02")
    if ini and eje and pd.Timedelta(0) <= eje.inicio - ini.fin <= pd.Timedelta(minutes=h["descarga_a_ejecucion_min"]):
        d = (eje.inicio - ini.fin).total_seconds()
        out.append(("Hipótesis", f"El archivo descargado ({', '.join(ini.indicadores.get('archivo', []))}) "
                                  f"probablemente contenía el script ejecutado {int(d // 60)} min {int(d % 60)} s después. "
                                  "No hay evento de extracción que lo confirme."))
    if ini and "R01" in por and not any(k in fuentes for k in ("correo", "email")):
        out.append(("No determinable", "Cómo llegó el enlace al usuario: no se aportaron registros de correo."))

    c2 = [a for a in inc.alertas if a.regla in ("R06", "P01")]
    exf = [a for a in inc.alertas if a.regla == "R08" and a.severidad >= 5]
    ips_c2 = {ip for a in c2 for ip in a.indicadores.get("ip", [])}
    for e in exf:
        if set(e.indicadores.get("ip", [])) & ips_c2:
            out.append(("Hecho", f"La exfiltración de las {e.inicio:%H:%M:%S} va al mismo destino que las balizas "
                                 f"({', '.join(set(e.indicadores['ip']) & ips_c2)})."))
    comp = primero("R05")
    if comp and exf and comp.indicadores.get("tamano"):
        tam = comp.indicadores["tamano"][0]
        for e in exf:
            env = e.indicadores["bytes"][0]
            dt = (e.inicio - comp.fin).total_seconds()
            if 0 <= dt <= h["compresion_a_salida_min"] * 60 and h["ratio_tamano"][0] <= env / tam <= h["ratio_tamano"][1]:
                out.append(("Hipótesis", f"Lo enviado es muy probablemente {comp.indicadores['archivo'][0]}: "
                                         f"sale {int(dt)} s después de crearlo y equivale al {env / tam:.1%} de su "
                                         "tamaño. El contenido va cifrado, así que no se puede confirmar."))
    lect = primero("R04")
    if lect and comp and pd.Timedelta(0) <= comp.inicio - lect.fin <= pd.Timedelta(minutes=30):
        out.append(("Hipótesis", "Los archivos de la lectura masiva son los que se comprimieron; "
                                 "no hay eventos de copia que lo muestren."))
    if c2 and primero("R03"):
        ult = max(a.fin for a in c2 if a.regla == "R06") if por.get("R06") else None
        rec = primero("R03")
        if ult and pd.Timedelta(0) <= rec.inicio - ult <= pd.Timedelta(minutes=15):
            out.append(("Hipótesis", "Las balizas se detienen poco antes del reconocimiento manual: "
                                     "probable control interactivo del atacante."))
    if "authentication" in fuentes and inc.usuario:
        au = fuentes["authentication"]
        hosts = set(au[au.username == inc.usuario].source_host)
        if hosts <= {inc.host}:
            out.append(("Hecho", f"{inc.usuario} solo se autentica desde {inc.host}: no hay evidencia de que "
                                 "su contraseña se usara en otro equipo."))
    if "R07" in por or "R10" in por:
        exitos = []
        if "authentication" in fuentes:
            r10 = [a for a in inc.alertas if a.regla == "R10"]
            exitos = [a for a in r10 if "SUCCESS" in a.descripcion]
        out.append(("Hecho" if not exitos else "Hipótesis",
                    "No hay evidencia de movimiento lateral exitoso: los intentos hacia otros equipos fueron "
                    "bloqueados o denegados." if not exitos else
                    "Hay autenticaciones exitosas hacia otras estaciones: revisar esos equipos."))
    if "firewall" in fuentes and (ips_c2 or exf):
        fw = fuentes["firewall"]
        iocs = ips_c2 | {ip for e in exf for ip in e.indicadores.get("ip", [])}
        despues = fw[fw.destination_ip.isin(iocs) & (fw.ts > inc.fin)]
        fin_log = fw.ts.max()
        if despues.empty:
            out.append(("Hecho", f"No hay más tráfico hacia los indicadores después de las {inc.fin:%H:%M:%S} "
                                 f"y hasta el fin de los registros ({fin_log:%H:%M:%S})."))
        out.append(("No determinable", "Si quedó persistencia en el equipo o hubo actividad después del fin de los registros."))
    if desfase_pcap:
        out.append(("Hipótesis", f"El reloj del PCAP difiere {desfase_pcap:+.0f} s del de los logs; se alineó "
                                 "comparando sus conexiones con las del firewall."))
    return out
