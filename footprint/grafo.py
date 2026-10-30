"""Grafo del incidente: el equipo comprometido al centro y, alrededor, todo lo que
tocó durante el ataque, en el orden de la cadena. Dibujado con Plotly (sin CDN)."""
import math

import plotly.graph_objects as go

COLORES = {"usuario": "#1F6FEB", "equipo": "#E5484D", "externo": "#F59E42",
           "interno": "#8A8F98", "archivo": "#8B5CF6", "actividad": "#14B8A6"}
NOMBRES = {"usuario": "Usuario", "equipo": "Equipo comprometido", "externo": "Infraestructura externa",
           "interno": "Equipo interno", "archivo": "Archivo", "actividad": "Actividad"}


def construir(inc):
    """Devuelve (nodos, aristas). nodo = (id, etiqueta, tipo); arista = (origen, destino, etiqueta, alerta)."""
    nodos, aristas = {}, []
    host = inc.host

    def nodo(i, etiqueta, tipo):
        nodos.setdefault(i, (i, etiqueta, tipo))
        return i

    nodo(host, host, "equipo")
    if inc.usuario:
        aristas.append((nodo("u:" + inc.usuario, inc.usuario, "usuario"), host, "", None))
    for a in inc.alertas:
        h = a.inicio.strftime("%H:%M")
        ind = a.indicadores
        if a.regla == "R01":
            d = nodo("d:" + ind["dominio"][0], ind["dominio"][0], "externo")
            aristas.append((host, d, f"{h} descarga {ind.get('archivo', [''])[0]}", a))
        elif a.regla == "R02":
            s = ind.get("archivo") or ["PowerShell"]
            aristas.append((host, nodo("f:" + s[0], s[0].rsplit("\\", 1)[-1], "archivo"), f"{h} ejecuta oculto", a))
        elif a.regla in ("R06", "P01"):
            ip = ind["ip"][0]
            etiqueta = ip + ("\n" + ind["dominio"][0] if ind.get("dominio") else "")
            nodo("ip:" + ip, etiqueta, "externo")
            if not any(x[1] == "ip:" + ip and "baliza" in x[2] for x in aristas):
                aristas.append((host, "ip:" + ip, f"{h} balizas", a))
        elif a.regla == "R03":
            aristas.append((host, nodo("act:recon", "whoami · nltest · net", "actividad"), f"{h} reconocimiento", a))
        elif a.regla == "R07":
            for dest in ind.get("destino", []):
                bloq = dest in ind.get("bloqueado", [])
                aristas.append((host, nodo("h:" + dest, dest, "interno"), "445 " + ("bloqueado" if bloq else "permitido"), a))
        elif a.regla == "R10":
            dest = a.titulo.rsplit(" ", 1)[-1]
            aristas.append((host, nodo("h:" + dest, dest, "interno"), f"{h} acceso denegado", a))
        elif a.regla == "R04":
            rec = (ind.get("recurso") or ["recurso compartido"])[0]
            aristas.append((host, nodo("r:" + rec, rec, "interno"), f"{h} lee {a.titulo.split()[2]} archivos", a))
        elif a.regla == "R05" and ind.get("archivo"):
            z = ind["archivo"][0]
            aristas.append((host, nodo("f:" + z, z.rsplit("\\", 1)[-1], "archivo"), f"{h} comprime", a))
        elif a.regla == "R08" and a.severidad >= 5:
            ip = ind["ip"][0]
            nodo("ip:" + ip, ip, "externo")
            zips = [n for n in nodos if n.startswith("f:") and n.lower().endswith((".zip", ".7z", ".rar"))]
            aristas.append((zips[0] if zips else host, "ip:" + ip, f"{h} EXFILTRA {a.titulo.split()[1]} MiB", a))
    return list(nodos.values()), aristas


def figura(inc, alto=620):
    nodos, aristas = construir(inc)
    # Derecha: lo que tocó el atacante, de arriba abajo en orden cronológico.
    # Izquierda: el usuario y los equipos internos a los que intentó llegar.
    # La IP externa se ordena por su ÚLTIMA aparición (la exfiltración), para que
    # quede junto al archivo comprimido y la flecha de salida sea corta.
    def momento(nid):
        ts = [a.inicio for o, d, _, a in aristas if d == nid and a is not None]
        if not ts:
            return 0
        return (max(ts) if nid.startswith("ip:") else min(ts)).timestamp()

    tipos = {n[0]: n[2] for n in nodos}
    derecha = sorted([i for i, t in tipos.items() if t in ("externo", "archivo", "actividad") or i.startswith("r:")],
                     key=momento)
    izquierda = [i for i, t in tipos.items() if t == "usuario"] + \
                sorted(i for i in tipos if i not in derecha and i != inc.host and tipos[i] != "usuario")
    pos = {inc.host: (0.0, 0.0)}

    def arco(ids, desde, hasta):
        for k, i in enumerate(ids):
            ang = math.radians(desde + (hasta - desde) * (k / max(len(ids) - 1, 1)) if len(ids) > 1 else (desde + hasta) / 2)
            pos[i] = (1.15 * math.cos(ang), math.sin(ang))

    arco(derecha, 72, -72)
    arco(izquierda, 112, 248)
    fig = go.Figure()
    unidas = {}
    for o, d, etiqueta, a in aristas:            # varias acciones sobre el mismo par -> una flecha
        unidas.setdefault((o, d), []).append(etiqueta)
    for (o, d), etiquetas in unidas.items():
        etiqueta = "<br>".join(etiquetas)
        (x0, y0), (x1, y1) = pos[o], pos[d]
        rojo = "EXFILTRA" in etiqueta or "bloqueado" in etiqueta or "denegado" in etiqueta
        fig.add_annotation(x=x1, y=y1, ax=x0, ay=y0, xref="x", yref="y", axref="x", ayref="y",
                           showarrow=True, arrowhead=3, arrowsize=1.2, arrowwidth=2.5 if "EXFILTRA" in etiqueta else 1.2,
                           arrowcolor="#E5484D" if rojo else "#B8BEC7", standoff=22, startstandoff=22, text="")
        t = 0.5 if o != inc.host else 0.55
        lx, ly = x0 + (x1 - x0) * t, y0 + (y1 - y0) * t
        if o != inc.host:                         # arista entre dos nodos del borde: etiqueta hacia fuera
            lx += 0.42 if lx > 0 else -0.42
        if not etiqueta:
            continue
        fig.add_annotation(x=lx, y=ly, text=etiqueta, showarrow=False,
                           font=dict(size=11, color="#C0392B" if rojo else "#34495E"),
                           bgcolor="rgba(255,255,255,0.85)")
    for tipo, color in COLORES.items():
        sel = [n for n in nodos if n[2] == tipo]
        if not sel:
            continue
        fig.add_trace(go.Scatter(
            x=[pos[n[0]][0] for n in sel], y=[pos[n[0]][1] for n in sel], mode="markers+text",
            marker=dict(size=34 if tipo == "equipo" else 24, color=color, line=dict(width=2, color="white")),
            text=[n[1].replace("\n", "<br>") for n in sel],
            textposition=["bottom center" if n[0] == inc.host else
                          ("middle right" if pos[n[0]][0] > 0 else "middle left") for n in sel],
            textfont=dict(size=12), name=NOMBRES[tipo], hoverinfo="text"))
    fig.update_layout(height=alto, showlegend=True, plot_bgcolor="white", margin=dict(l=10, r=10, t=10, b=10),
                      xaxis=dict(visible=False, range=[-1.75, 1.75]), yaxis=dict(visible=False, range=[-1.3, 1.25]),
                      legend=dict(orientation="h", y=-0.02))
    return fig
