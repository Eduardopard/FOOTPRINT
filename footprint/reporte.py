"""Generación del reporte (Markdown y JSON) y de tablas para la interfaz."""
import json

import pandas as pd

from .modelo import TACTICAS


def _csv_seguro(v):
    """Evita inyección de fórmulas al abrir exportaciones en Excel."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def tabla_alertas(alertas):
    return pd.DataFrame([{
        "Hora": a.inicio, "Fin": a.fin, "Equipo": a.host, "Usuario": a.usuario, "Táctica": a.tactica,
        "Técnica": a.tecnica, "Severidad": a.severidad, "Detección": a.titulo, "Detalle": a.descripcion,
        "Evidencia": a.refs(50), "Regla": a.regla,
    } for a in alertas])


def indicadores(inc):
    out = {}
    for a in inc.alertas:
        for k, vs in a.indicadores.items():
            if k in ("tamano", "bytes"):
                continue
            for v in vs:
                if v and v not in out.setdefault(k, []):
                    out[k].append(v)
    return out


def markdown(res):
    L = ["# Reporte de incidente — FootPrint", ""]
    if not res.incidentes:
        L += ["No se detectó ninguna cadena de ataque con los umbrales actuales.", ""]
    for n, inc in enumerate(res.incidentes, 1):
        dur = (inc.fin - inc.inicio)
        L += [f"## Incidente {n}: {inc.host} ({inc.usuario})", "",
              f"- Ventana: {inc.inicio:%Y-%m-%d %H:%M:%S} → {inc.fin:%H:%M:%S} ({int(dur.total_seconds() // 60)} min)",
              f"- Puntaje de riesgo: {inc.puntaje}",
              f"- Tácticas ({len(inc.tacticas)}): {', '.join(inc.tacticas)}", "",
              "### Línea de tiempo", "",
              "| Hora | Táctica | Evento | Evidencia |", "| --- | --- | --- | --- |"]
        for a in inc.alertas:
            L.append(f"| {a.inicio:%H:%M:%S} | {a.tactica} | {a.titulo} | {a.refs(8)} |")
        L += ["", "### Detalle", ""]
        for a in inc.alertas:
            L += [f"**{a.inicio:%H:%M:%S} · {a.titulo}** ({a.tecnica}, severidad {a.severidad})", "",
                  a.descripcion, "", f"Evidencia: {a.refs(50)}", ""]
        for tipo in ("Hecho", "Hipótesis", "No determinable"):
            items = [t for k, t in inc.hipotesis if k == tipo]
            if items:
                L += [f"### {tipo if tipo != 'Hecho' else 'Hechos de correlación'}", ""] + [f"- {t}" for t in items] + [""]
        ioc = indicadores(inc)
        if ioc:
            L += ["### Indicadores de compromiso", ""] + [f"- **{k}**: {', '.join(map(str, v))}" for k, v in ioc.items()] + [""]
    if res.aisladas:
        L += ["## Alertas aisladas (no forman cadena)", "", "| Hora | Equipo | Detección | Evidencia |", "| --- | --- | --- | --- |"]
        L += [f"| {a.inicio:%H:%M:%S} | {a.host} | {a.titulo} | {a.refs(4)} |" for a in res.aisladas] + [""]
    L += ["## Fuentes analizadas", "", "| Archivo | Tipo | Registros | SHA-256 |", "| --- | --- | --- | --- |"]
    L += [f"| {m['archivo']} | {m.get('tipo', '?')} | {m.get('filas', '?')} | `{m['sha256']}` |" for m in res.inventario]
    if res.advertencias:
        L += ["", "## Advertencias", ""] + [f"- {w}" for w in res.advertencias]
    return "\n".join(L) + "\n"


def json_export(res):
    def alerta(a):
        return {"regla": a.regla, "titulo": a.titulo, "tactica": a.tactica, "tecnica": a.tecnica,
                "severidad": a.severidad, "host": a.host, "usuario": a.usuario,
                "inicio": a.inicio.isoformat(), "fin": a.fin.isoformat(), "descripcion": a.descripcion,
                "evidencias": [str(e) for e in a.evidencias], "indicadores": a.indicadores}
    return json.dumps({
        "incidentes": [{"host": i.host, "usuario": i.usuario, "inicio": i.inicio.isoformat(),
                        "fin": i.fin.isoformat(), "puntaje": i.puntaje, "tacticas": i.tacticas,
                        "alertas": [alerta(a) for a in i.alertas],
                        "hipotesis": [{"tipo": t, "texto": x} for t, x in i.hipotesis]} for i in res.incidentes],
        "aisladas": [alerta(a) for a in res.aisladas],
        "fuentes": [{k: (str(v) if k in ("desde", "hasta") else v) for k, v in m.items()} for m in res.inventario],
        "advertencias": res.advertencias,
    }, ensure_ascii=False, indent=2, default=str)


def csv_alertas(alertas):
    df = tabla_alertas(alertas)
    return df.map(_csv_seguro).to_csv(index=False).encode("utf-8-sig") if len(df) else b""


def orden_tactica(t):
    return TACTICAS.index(t) if t in TACTICAS else len(TACTICAS)
