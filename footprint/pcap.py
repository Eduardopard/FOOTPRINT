"""Análisis del PCAP: DNS, flujos TCP, sesiones periódicas y alineación de reloj."""
import io
from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean, pstdev

import pandas as pd

from .modelo import Alerta, Evidencia


def leer_pcap(nombre: str, datos: bytes, max_paquetes: int):
    """Extrae respuestas DNS y un resumen por flujo TCP. Lectura en streaming."""
    from scapy.all import DNS, DNSRR, IP, TCP, PcapReader  # import diferido: scapy tarda en cargar

    dns, flujos = [], {}
    n = 0
    with PcapReader(io.BytesIO(datos)) as rd:
        for n, p in enumerate(rd, 1):
            if n > max_paquetes:
                break
            if IP not in p:
                continue
            t = datetime.fromtimestamp(float(p.time), tz=timezone.utc).replace(tzinfo=None)
            if DNS in p and p[DNS].qr == 1 and p[DNS].qd:
                qd = p[DNS].qd
                qd = qd[0] if isinstance(qd, list) else qd
                q = qd.qname.decode(errors="replace").rstrip(".")
                an = p[DNS].an or []
                an = an if isinstance(an, list) else [an[i] for i in range(p[DNS].ancount)]
                ans = [str(rr.rdata) for rr in an if isinstance(rr, DNSRR) and rr.type == 1]
                dns.append({"ts": t, "frame": n, "cliente": p[IP].dst, "query": q, "respuestas": ans})
            elif TCP in p:
                a, b = (p[IP].src, p[TCP].sport), (p[IP].dst, p[TCP].dport)
                clave = tuple(sorted([a, b]))
                f = flujos.get(clave)
                flags = int(p[TCP].flags)
                if f is None:
                    if not (flags & 0x02) or (flags & 0x10):     # el flujo empieza con un SYN sin ACK
                        continue
                    f = flujos[clave] = {"inicio": t, "src": a[0], "sport": a[1], "dst": b[0], "dport": b[1],
                                         "isn": int(p[TCP].seq), "frame_ini": n, "frame_fin": n, "fin": t,
                                         "bytes_cli": 0, "bytes_srv": 0, "datos_t": []}
                f["frame_fin"], f["fin"] = n, t
                carga = len(p[TCP].payload)
                if carga:
                    if p[IP].src == f["src"]:
                        f["bytes_cli"] += carga
                        f["datos_t"].append(t)
                    else:
                        f["bytes_srv"] += carga
    fl = pd.DataFrame(flujos.values())
    if len(fl):
        fl["registros"] = fl.datos_t.map(len)
        fl["cadencia_s"] = fl.datos_t.map(
            lambda ts: round(mean((ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)), 3)
            if len(ts) > 1 else None)
        fl["duracion_s"] = (fl.fin - fl.inicio).dt.total_seconds().round(2)
        fl = fl.drop(columns="datos_t").sort_values("inicio").reset_index(drop=True)
    info = {"nombre": nombre, "paquetes": n, "dns": len(dns), "flujos_tcp": len(fl),
            "desde": min([d["ts"] for d in dns] + list(fl.inicio if len(fl) else [])) if (dns or len(fl)) else None,
            "hasta": max([d["ts"] for d in dns] + list(fl.fin if len(fl) else [])) if (dns or len(fl)) else None,
            "truncado": n > max_paquetes}
    return info, pd.DataFrame(dns), fl


def alinear_reloj(fl, fw, tolerancia_s):
    """Estima el desfase entre el reloj del PCAP y el del firewall.

    Compara cada flujo del PCAP con las conexiones del firewall con el mismo par
    origen-destino, y busca el desfase que hace coincidir más pares (±tolerancia).
    Devuelve (desfase_segundos, coincidencias) o (0, 0) si no hay base suficiente.
    """
    if fw is None or fl is None or fl.empty:
        return 0.0, 0
    sal = fw[["source_ip", "destination_ip", "ts"]]
    pares = fl.merge(sal, left_on=["src", "dst"], right_on=["source_ip", "destination_ip"])
    if pares.empty:
        return 0.0, 0
    deltas = (pares.ts - pares.inicio).dt.total_seconds()
    mejor, n_mejor = 0.0, 0
    for c in deltas:
        cerca = deltas[(deltas - c).abs() <= tolerancia_s]
        # cada flujo del PCAP cuenta una sola vez
        n = pares.loc[cerca.index].drop_duplicates(["src", "sport", "dst"]).shape[0]
        if n > n_mejor:
            mejor, n_mejor = float(cerca.median()), n
    return (round(mejor), n_mejor) if n_mejor >= 2 else (0.0, n_mejor)


def detectar(nombre, dns, fl, mapa_ip, desfase_s, cfg):
    """Sesiones periódicas hacia destinos que resuelve un dominio poco común."""
    if fl.empty:
        return []
    clientes = dns.groupby("query").cliente.nunique() if len(dns) else pd.Series(dtype=int)
    raros = set(clientes[clientes <= 1].index) if (clientes > 1).any() else set()
    ip_dom = defaultdict(set)
    for _, d in dns.iterrows():
        if d["query"] in raros:
            for ip in d.respuestas:
                ip_dom[ip].add(d["query"])
    alertas = []
    for (src, dst), g in fl.groupby(["src", "dst"]):
        if len(g) < 3:
            continue
        inter = g.inicio.diff().dt.total_seconds().dropna()
        cv = pstdev(inter) / mean(inter) if mean(inter) else 1
        if cv > cfg["beaconing"]["max_coef_variacion"] and dst not in ip_dom:
            continue
        puertos = list(g.sport)
        secuencial = all(b - a == 1 for a, b in zip(puertos, puertos[1:]))
        resto = fl[fl.dst != dst]
        rasgos = [f"{len(g)} sesiones cada {mean(inter) / 60:.1f} min (variación {cv:.1%})"]
        if secuencial:
            rasgos.append(f"puertos de origen consecutivos {puertos[0]}–{puertos[-1]}")
        if g.cadencia_s.notna().all() and g.cadencia_s.nunique() == 1:
            rasgos.append(f"{int(g.registros.iloc[0])} registros a {g.cadencia_s.iloc[0]} s exactos")
        if len(resto):
            rasgos.append(f"el resto de flujos dura como máximo {resto.duracion_s.max()} s; estas, {g.duracion_s.max()} s")
        if g.bytes_srv.sum() == 0:
            rasgos.append("el servidor no envía datos en la captura")
        doms = sorted(ip_dom.get(dst, []))
        frames_dns = dns[dns["query"].isin(doms)].frame.tolist() if doms else []
        corr = pd.Timedelta(seconds=desfase_s)
        alertas.append(Alerta(
            regla="P01", titulo=f"Sesiones periódicas hacia {dst} (PCAP)",
            tactica="Mando y control", tecnica="T1071.001 · T1573",
            severidad=4, host=mapa_ip.get(src, src),
            inicio=g.inicio.iloc[0] + corr, fin=g.fin.iloc[-1] + corr,
            descripcion=("; ".join(rasgos) + "."
                         + (f" Destino resuelto desde {', '.join(doms)}, consultado por un solo equipo." if doms else "")
                         + (f" Horas corregidas {desfase_s:+.0f} s por desfase de reloj." if desfase_s else "")),
            evidencias=[Evidencia(nombre, f"{a}-{b}") for a, b in zip(g.frame_ini, g.frame_fin)]
                       + ([Evidencia(nombre, ",".join(map(str, frames_dns)))] if frames_dns else []),
            indicadores={"ip": [dst], "dominio": doms}))
    return alertas
