"""FootPrint — interfaz web. Ejecutar con:  streamlit run app.py"""
import html
import re

import pandas as pd
import plotly.express as px
import streamlit as st

from footprint import analizar, cargar_config
from footprint import grafo, reporte
from footprint.modelo import TACTICAS

st.set_page_config(page_title="FootPrint · Análisis de incidentes", layout="wide")

SEV_NOMBRE = {1: "Informativa", 2: "Baja", 3: "Media", 4: "Alta", 5: "Crítica"}
COLOR_SEV = {1: "#B8BEC7", 2: "#F5C451", 3: "#F59E42", 4: "#EF5B5B", 5: "#B42318"}
FUENTES = [
    ("Autenticación", "Inicios de sesión correctos y fallidos."),
    ("DNS", "Dominios que consultó cada equipo."),
    ("Endpoint", "Procesos, comandos y archivos en cada equipo."),
    ("Firewall", "Conexiones de red permitidas y bloqueadas."),
    ("Proxy", "Páginas y descargas web."),
    ("Captura de red (PCAP)", "Tráfico real para confirmar las conexiones."),
]

st.markdown("""<style>
:root { --acento:#1F6FEB; --texto:#1A1C1F; --suave:#6B7280; --borde:#E6E8EC; --fondo:#F4F5F7;
        --fuente:"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif; }
.stApp, .stApp p, .stApp li, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp button,
.stApp input, [data-testid="stMetricValue"], [data-testid="stMetricLabel"] { font-family: var(--fuente); }
[data-testid="stDecoration"] { display:none; }
header[data-testid="stHeader"] { background:transparent; }
.block-container, [data-testid="stMainBlockContainer"] { padding-top:2.2rem; max-width:1280px; }
[data-testid="stSidebar"] { background:#FFFFFF; border-right:1px solid var(--borde); }

/* Pestañas en forma de píldora */
.stTabs [role="tablist"] { display:flex; flex-wrap:wrap; gap:4px; background:#E9EBEF; padding:5px; border-radius:24px;
                           width:100%; box-sizing:border-box; overflow:visible;
                           border:none !important; box-shadow:none !important; }
.stTabs [role="tablist"]::before, .stTabs [role="tablist"]::after { display:none !important; }
.stTabs [data-testid="stTab"] { flex:1 1 auto; display:flex; align-items:center; justify-content:center;
                                height:38px; padding:0 12px; border-radius:999px; background:transparent;
                                white-space:nowrap; border:none !important; box-shadow:none; }
.stTabs [data-testid="stTab"]::before, .stTabs [data-testid="stTab"]::after,
.stTabs .react-aria-SelectionIndicator { display:none !important; }
.stTabs [data-testid="stTab"] p { font-size:0.92rem; font-weight:500; color:#4B5260; }
.stTabs [data-testid="stTab"][aria-selected="true"] { background:#FFFFFF; box-shadow:0 1px 3px rgba(16,24,40,.10); }
.stTabs [data-testid="stTab"][aria-selected="true"] p { color:var(--texto); font-weight:600; }
.stTabs [data-testid="stTabPanel"] { padding-top:1.4rem; }
@media (max-width: 1440px) {
  .stTabs [data-testid="stTab"] { padding:0 8px; }
  .stTabs [data-testid="stTab"] p { font-size:0.84rem; }
}

/* Métricas como tarjetas */
[data-testid="stMetric"] { background:#FFFFFF; border:1px solid var(--borde); border-radius:22px; padding:18px 16px;
                            text-align:center; }
[data-testid="stMetric"] > div, [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] > div,
[data-testid="stMetricValue"], [data-testid="stMetricValue"] > div { justify-content:center; text-align:center; }
[data-testid="stMetricLabel"] { display:flex !important; align-items:center; justify-content:center; gap:4px; }
[data-testid="stMetricLabel"] > * { flex:0 0 auto; width:auto; }
[data-testid="stMetricLabel"] p { color:var(--suave); font-size:0.86rem; }
[data-testid="stMetricValue"] { font-size:1.9rem; font-weight:600; color:var(--texto); }

.stButton button, .stDownloadButton button { border-radius:999px; font-weight:600; }

/* Componentes propios */
.hu-hero, .hu-intro, .hu-inc, .hu-centro { text-align:center; }
.hu-hero h1 { font-size:2.4rem; font-weight:700; letter-spacing:-0.02em; margin:0 0 .3rem 0; padding:0; color:var(--texto);
              text-align:center; }
.hu-hero p { color:var(--suave); font-size:1.05rem; margin:0 auto 1.6rem auto; max-width:760px; }
.hu-marca { font-size:1.6rem; font-weight:700; letter-spacing:-0.02em; color:var(--texto); margin:0; }
.hu-marca span { color:var(--acento); }
.hu-sub { color:var(--suave); font-size:0.9rem; margin:.1rem 0 1rem 0; }
.hu-intro h3 { font-size:1.35rem; font-weight:650; margin:0 0 .2rem 0; padding:0; color:var(--texto); }
.hu-intro h3 { text-align:center; }
.hu-intro p { color:var(--suave); margin:0 auto 1.1rem auto; font-size:0.95rem; max-width:860px; }
.hu-card { background:#FFFFFF; border:1px solid var(--borde); border-radius:24px; padding:22px 24px; margin-bottom:14px; }
.hu-grid { display:grid; grid-template-columns:repeat(var(--cols), minmax(0, 1fr)); gap:16px; margin-bottom:1.6rem; }
.hu-grid > .hu-card { margin:0; text-align:center; }
@media (max-width: 1100px) { .hu-grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } }
.hu-card h4 { font-size:1.02rem; font-weight:650; margin:0 0 .5rem 0; padding:0; color:var(--texto); }
.hu-card p { color:var(--suave); margin:0; font-size:0.93rem; }
.hu-num { display:inline-flex; align-items:center; justify-content:center; width:30px; height:30px; border-radius:50%;
          background:#EAF1FE; color:var(--acento); font-weight:700; font-size:0.9rem; margin-bottom:.7rem; }
.hu-etq { color:var(--suave); font-size:0.8rem; font-weight:600; text-transform:uppercase; letter-spacing:.06em; }
.hu-inc h2 { font-size:1.7rem; font-weight:700; margin:.15rem 0 .2rem 0; padding:0; color:var(--texto); text-align:center; }
.hu-inc p { color:var(--suave); margin:0; }
.hu-cadena { display:grid; grid-template-columns:repeat(8, minmax(0, 1fr)); gap:8px; margin:.8rem 0 .2rem 0; }
@media (max-width: 1100px) { .hu-cadena { grid-template-columns:repeat(4, minmax(0, 1fr)); } }
.hu-fase { border-radius:16px; padding:12px 8px; background:#F4F5F7; color:#9AA0A6; font-size:0.82rem; min-height:92px;
           text-align:center; }
.hu-fase small { display:block; font-size:0.72rem; font-weight:600; opacity:.75; }
.hu-fase b { display:block; font-weight:600; font-size:0.78rem; margin:.1rem 0 .3rem 0; line-height:1.25; }
.hu-fase.on { background:#FDECEC; color:#B42318; }
.hu-leyenda { color:var(--suave); font-size:0.82rem; margin:0; }
.hu-evento { display:flex; gap:18px; padding:14px 0; border-top:1px solid #F0F1F3; }
.hu-evento:first-child { border-top:none; padding-top:4px; }
.hu-hora { font-variant-numeric:tabular-nums; color:var(--suave); font-size:0.9rem; min-width:70px; padding-top:1px; }
.hu-titulo { font-weight:600; color:var(--texto); }
.hu-meta { margin:.35rem 0 .25rem 0; display:flex; gap:6px; flex-wrap:wrap; }
.hu-ref { color:#9AA0A6; font-size:0.8rem; word-break:break-all; }
.hu-chip { display:inline-block; padding:2px 10px; border-radius:999px; font-size:0.76rem; font-weight:600;
           background:#EEF0F3; color:#4B5260; }
.hu-s1 { background:#F1F2F4; color:#6B7280; } .hu-s2 { background:#FEF6E0; color:#8A6100; }
.hu-s3 { background:#FEF0E3; color:#A4510B; } .hu-s4 { background:#FDECEC; color:#C0362C; }
.hu-s5 { background:#B42318; color:#FFFFFF; }
.hu-lista { margin:0; padding:0; list-style:none; }
.hu-lista li { padding:9px 0; border-top:1px solid #F0F1F3; color:var(--texto); font-size:0.93rem; }
.hu-lista li:first-child { border-top:none; }
.hu-lista small { color:#9AA0A6; }
.hu-punto { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px; vertical-align:middle; }
.hu-nota { background:#F4F5F7; border-radius:16px; padding:12px 14px; color:var(--suave); font-size:0.84rem; margin-top:.4rem; }
</style>""", unsafe_allow_html=True)


def esc(s):
    """El texto de la evidencia se escapa antes de mostrarse como HTML."""
    return html.escape(str(s)).replace("$", "&#36;").replace("\\", "&#92;")


def bloque(contenido):
    st.markdown(contenido, unsafe_allow_html=True)


def intro(titulo, texto):
    bloque(f"<div class='hu-intro'><h3>{titulo}</h3><p>{texto}</p></div>")


def chip_sev(sev):
    return f"<span class='hu-chip hu-s{sev}'>Severidad {SEV_NOMBRE.get(sev, sev).lower()}</span>"


def alertas_df(alertas):
    df = reporte.tabla_alertas(alertas)
    if len(df):
        df["Hora"] = df["Hora"].dt.strftime("%H:%M:%S")
        df["Fin"] = df["Fin"].dt.strftime("%H:%M:%S")
        df["Severidad"] = df["Severidad"].map(lambda s: f"{s} · {SEV_NOMBRE.get(s, '')}")
    return df


# --------------------------------------------------------------------- barra lateral
with st.sidebar:
    bloque("<div class='hu-marca'>FootPrint<span>.</span></div>"
           "<div class='hu-sub'>Reconstrucción automática de incidentes</div>")
    subidos = st.file_uploader("Archivos de evidencia", type=["csv", "pcap", "pcapng", "cap"],
                               accept_multiple_files=True,
                               help="Puedes seleccionar varios a la vez. Los CSV se reconocen por sus columnas, "
                                    "no por su nombre.")
    analizar_btn = st.button("Analizar evidencias", type="primary", disabled=not subidos, width="stretch")
    if not subidos:
        st.caption("Sube al menos un archivo para activar el análisis.")
    bloque("<div class='hu-nota'><b>Privacidad.</b> Todo se procesa en memoria en este equipo. "
           "Nada se guarda en disco ni se envía a servicios externos. Cada archivo se identifica "
           "con su hash SHA-256.</div>")

if analizar_btn:
    with st.spinner("Analizando y correlacionando evidencias..."):
        st.session_state.res = analizar([(f.name, f.getvalue()) for f in subidos], cargar_config())

res = st.session_state.get("res")

# --------------------------------------------------------------------- pantalla de inicio
if res is None:
    bloque("<div class='hu-hero'><h1>Análisis de incidentes</h1>"
           "<p>Sube los registros de tu red y FootPrint reconstruye lo que pasó: qué equipo se vio afectado, "
           "en qué orden actuó el atacante y en qué fila de cada archivo está la prueba.</p></div>")
    pasos = [("Sube los archivos", "Usa el panel de la izquierda para cargar los CSV y la captura de red. "
                                   "Luego pulsa <b>Analizar evidencias</b>."),
             ("FootPrint detecta","11 reglas buscan comportamientos sospechosos: descargas raras, comandos "
                                "ocultos, envío de datos al exterior, etc."),
             ("FootPrint correlaciona","Solo abre un incidente si un mismo equipo muestra 3 o más fases de "
                                     "ataque en menos de 2 horas. Así evita falsas alarmas."),
             ("Revisas el resultado", "Cronología, mapa del ataque, conclusiones separadas de las "
                                      "suposiciones y un reporte descargable.")]
    bloque("<div class='hu-grid' style='--cols:4'>" +
           "".join(f"<div class='hu-card'><span class='hu-num'>{n}</span><h4>{t}</h4><p>{d}</p></div>"
                   for n, (t, d) in enumerate(pasos, 1)) + "</div>")
    intro("Archivos que acepta", "No importa cómo se llamen: FootPrint reconoce cada CSV por sus columnas.")
    bloque("<div class='hu-grid' style='--cols:3'>" +
           "".join(f"<div class='hu-card'><h4>{t}</h4><p>{d}</p></div>" for t, d in FUENTES) + "</div>")
    st.stop()

# --------------------------------------------------------------------- resultados
n_archivos = len(res.inventario)
n_registros = sum(x.get("filas", 0) or 0 for x in res.inventario)
if res.incidentes:
    estado = (f"Se encontró {len(res.incidentes)} incidente" if len(res.incidentes) == 1
              else f"Se encontraron {len(res.incidentes)} incidentes")
else:
    estado = "No se encontró ninguna cadena de ataque"
bloque(f"<div class='hu-hero'><h1>{estado}</h1>"
       f"<p>{n_archivos} archivo{'s' if n_archivos != 1 else ''} analizado{'s' if n_archivos != 1 else ''} · "
       f"{n_registros:,} registros revisados · {len(res.alertas)} comportamientos sospechosos detectados</p></div>")

for w in res.advertencias:
    st.warning(w)

tabs = st.tabs(["Resumen", "Cronología", "Mapa del ataque", "Conclusiones", "Detecciones",
                "Tráfico de red", "Archivos", "Reporte"])


# --------------------------------------------------------------------- resumen
with tabs[0]:
    m = st.columns(4)
    m[0].metric("Incidentes", len(res.incidentes),
                help="Equipos con 3 o más fases de ataque en una ventana de 2 horas.")
    m[1].metric("Detecciones", len(res.alertas), help="Comportamientos sospechosos encontrados por las reglas.")
    m[2].metric("Alertas aisladas", len(res.aisladas),
                help="Detecciones que no forman cadena: se muestran, pero no abren incidente.")
    m[3].metric("Registros revisados", f"{n_registros:,}")
    st.write("")
    if not res.incidentes:
        st.success("No se encontró ninguna cadena de ataque con los umbrales actuales. "
                   "Las detecciones sueltas, si las hay, están en la pestaña Detecciones.")
    for n, inc in enumerate(res.incidentes, 1):
        dur = int((inc.fin - inc.inicio).total_seconds() // 60)
        usuario = f"Usuario {esc(inc.usuario)} · " if inc.usuario else ""
        bloque(f"<div class='hu-inc'><span class='hu-etq'>Incidente {n}</span><h2>Equipo {esc(inc.host)}</h2>"
               f"<p>{usuario}de {inc.inicio:%H:%M:%S} a {inc.fin:%H:%M:%S} ({dur} min)</p></div>")
        st.write("")
        exf = [a for a in inc.alertas if a.tactica == "Exfiltración"]
        alta = [a for a in inc.alertas if a.severidad >= 4]
        c = st.columns(4)
        c[0].metric("Primera actividad", inc.inicio.strftime("%H:%M:%S"))
        c[1].metric("Duración", f"{dur} min")
        c[2].metric("Puntaje de riesgo", inc.puntaje, help="Suma ponderada de la severidad de sus detecciones.")
        if exf and alta:
            ventaja = int((exf[0].inicio - alta[0].inicio).total_seconds() // 60)
            c[3].metric("Margen para reaccionar", f"{ventaja} min",
                        help="Minutos entre la primera detección grave y la salida de datos: "
                             "tiempo que hubo para contener el ataque.")
        else:
            c[3].metric("Fases de ataque", f"{len(inc.tacticas)} de {len(TACTICAS)}")

        fases = []
        for i, t in enumerate(TACTICAS, 1):
            hits = [a for a in inc.alertas if a.tactica == t]
            if hits:
                fases.append(f"<div class='hu-fase on'><small>Fase {i}</small><b>{t}</b>{hits[0].inicio:%H:%M}</div>")
            else:
                fases.append(f"<div class='hu-fase'><small>Fase {i}</small><b>{t}</b>No observada</div>")
        bloque("<div class='hu-card hu-centro'><h4>Cadena de ataque</h4>"
               "<p class='hu-leyenda'>Fases del modelo MITRE ATT&amp;CK. En rojo, las que se observaron en este "
               "equipo, con la hora en que empezaron.</p>"
               f"<div class='hu-cadena'>{''.join(fases)}</div></div>")

        eventos = "".join(
            f"<div class='hu-evento'><div class='hu-hora'>{a.inicio:%H:%M:%S}</div><div>"
            f"<div class='hu-titulo'>{esc(a.titulo)}</div>"
            f"<div class='hu-meta'><span class='hu-chip'>{esc(a.tactica)}</span>{chip_sev(a.severidad)}</div>"
            f"<div class='hu-ref'>Evidencia: {esc(a.refs(4))}</div></div></div>"
            for a in inc.alertas)
        bloque("<div class='hu-card'><h4>Qué pasó, paso a paso</h4>"
               "<p class='hu-leyenda' style='margin-bottom:.6rem'>Cada paso cita el archivo y la línea "
               "donde está la prueba.</p>" + eventos + "</div>")
    if res.aisladas:
        with st.expander(f"Alertas aisladas ({len(res.aisladas)}): revisadas, pero no forman una cadena de ataque"):
            st.dataframe(alertas_df(res.aisladas)[["Hora", "Equipo", "Usuario", "Detección", "Detalle", "Evidencia"]],
                         hide_index=True, width="stretch")


# --------------------------------------------------------------------- cronología
with tabs[1]:
    intro("Cronología", "Cada barra es una detección, ordenada por fase del ataque y coloreada por severidad. "
                        "Pasa el cursor por encima para ver el equipo y la evidencia.")
    if not res.alertas:
        st.info("No hay detecciones que mostrar.")
    else:
        df = reporte.tabla_alertas(res.alertas)
        df["Fin visible"] = df.apply(lambda r: max(r["Fin"], r["Hora"] + pd.Timedelta(seconds=60)), axis=1)
        df["Nivel"] = df["Severidad"].map(SEV_NOMBRE)
        orden = [t for t in TACTICAS + ["Informativa"] if t in set(df["Táctica"])]
        fig = px.timeline(df, x_start="Hora", x_end="Fin visible", y="Táctica", color="Nivel",
                          hover_name="Detección", hover_data={"Equipo": True, "Evidencia": True, "Nivel": False,
                                                             "Fin visible": False, "Táctica": False},
                          color_discrete_map={SEV_NOMBRE[k]: v for k, v in COLOR_SEV.items()},
                          category_orders={"Táctica": orden, "Nivel": [SEV_NOMBRE[k] for k in (5, 4, 3, 2, 1)]},
                          text="Equipo")
        fig.update_traces(textposition="outside", marker_line_width=0, cliponaxis=False)
        fig.update_layout(height=460, legend_title="Severidad", xaxis_title="", yaxis_title="",
                          paper_bgcolor="#FFFFFF", plot_bgcolor="#FFFFFF", font=dict(color="#1A1C1F"),
                          margin=dict(l=16, r=60, t=16, b=16))
        fig.update_xaxes(gridcolor="#F0F1F3", tickformat="%H:%M")
        fig.update_yaxes(gridcolor="#F0F1F3")
        st.plotly_chart(fig, width="stretch")
        st.dataframe(alertas_df(res.alertas)[["Hora", "Equipo", "Usuario", "Táctica", "Severidad", "Detección",
                                              "Evidencia"]],
                     hide_index=True, width="stretch")


# --------------------------------------------------------------------- mapa del ataque
with tabs[2]:
    intro("Mapa del ataque", "El equipo afectado está en el centro. A la derecha, lo que tocó el atacante de "
                             "arriba abajo en orden cronológico; a la izquierda, el usuario y los equipos internos "
                             "a los que intentó llegar. Las flechas van de quien actúa hacia su objetivo, y las "
                             "rojas marcan acciones bloqueadas o la salida de datos.")
    if not res.incidentes:
        st.info("El mapa se dibuja cuando hay al menos un incidente.")
    for n, inc in enumerate(res.incidentes, 1):
        bloque(f"<div class='hu-centro'><span class='hu-etq'>Incidente {n} · equipo {esc(inc.host)}</span></div>")
        fig = grafo.figura(inc)
        fig.update_layout(paper_bgcolor="#FFFFFF")
        st.plotly_chart(fig, width="stretch")


# --------------------------------------------------------------------- conclusiones
with tabs[3]:
    intro("Conclusiones", "FootPrint separa lo que está probado de lo que solo es probable. Revisa las hipótesis "
                          "antes de darlas por buenas.")
    if not res.incidentes:
        st.info("No hay incidentes sobre los que sacar conclusiones.")
    grupos = [("Hecho", "Hechos de correlación", "#12B76A", "Se deducen de cruzar varias evidencias."),
              ("Hipótesis", "Hipótesis fundamentadas", "#F5A524", "Son probables, pero ninguna fila lo confirma."),
              ("No determinable", "No se puede determinar", "#EF5B5B", "Faltan registros para responderlo.")]
    for n, inc in enumerate(res.incidentes, 1):
        bloque(f"<div class='hu-centro'><span class='hu-etq'>Incidente {n} · equipo {esc(inc.host)}</span></div>")
        st.write("")
        hechos = "".join(f"<li><b>{a.inicio:%H:%M:%S}</b> &nbsp;{esc(a.titulo)}<br><small>{esc(a.refs(3))}</small></li>"
                         for a in inc.alertas)
        izq, der = st.columns(2)
        with izq:
            bloque("<div class='hu-card'><h4><span class='hu-punto' style='background:#12B76A'></span>"
                   "Hechos observados</h4><p class='hu-leyenda' style='margin-bottom:.5rem'>Cada uno aparece "
                   f"en una fila concreta de la evidencia.</p><ul class='hu-lista'>{hechos}</ul></div>")
        with der:
            for tipo, titulo, color, ayuda in grupos:
                items = [t for k, t in inc.hipotesis if k == tipo]
                if items:
                    lis = "".join(f"<li>{esc(t)}</li>" for t in items)
                    bloque(f"<div class='hu-card'><h4><span class='hu-punto' style='background:{color}'></span>"
                           f"{titulo}</h4><p class='hu-leyenda' style='margin-bottom:.5rem'>{ayuda}</p>"
                           f"<ul class='hu-lista'>{lis}</ul></div>")


# --------------------------------------------------------------------- detecciones + explorador
with tabs[4]:
    intro("Detecciones", "Todo lo que encontraron las reglas, forme parte de un incidente o no. Filtra por "
                         "severidad y descarga la tabla si la necesitas.")
    sev = st.select_slider("Mostrar desde la severidad", options=[1, 2, 3, 4, 5], value=1,
                           format_func=lambda s: SEV_NOMBRE[s])
    todas = [a for a in res.alertas if a.severidad >= sev]
    st.dataframe(alertas_df(todas).drop(columns=["Fin"], errors="ignore"), hide_index=True, width="stretch")
    st.columns([1, 1, 1])[1].download_button("Descargar detecciones (CSV)", reporte.csv_alertas(todas),
                                             "detecciones.csv", "text/csv", disabled=not todas, width="stretch")
    st.write("")
    intro("Ver la evidencia original", "Elige una detección para ver las filas exactas de los archivos que la "
                                       "respaldan.")
    if todas:
        elegido = st.selectbox("Detección", range(len(todas)), label_visibility="collapsed",
                               format_func=lambda i: f"{todas[i].inicio:%H:%M:%S} · {todas[i].host} · {todas[i].titulo}")
        a = todas[elegido]
        bloque(f"<div class='hu-card'><h4>{esc(a.titulo)}</h4>"
               f"<div class='hu-meta'><span class='hu-chip'>{esc(a.tactica)}</span>"
               f"<span class='hu-chip'>{esc(a.tecnica)}</span>{chip_sev(a.severidad)}</div>"
               f"<p>{esc(a.descripcion)}</p></div>")
        for ev in a.evidencias:
            fuente = next((df for df in res.fuentes.values() if df["_fuente"].iloc[0] == ev.fuente), None)
            if fuente is not None:
                nums = [int(x) for x in re.findall(r"\d+", ev.ref.split("(")[0])]
                filas = (fuente[fuente._linea.between(nums[0], nums[-1])] if "…" in ev.ref
                         else fuente[fuente._linea.isin(nums)])
                vista = filas.drop(columns=["_fuente", "ts"]).rename(columns={"_linea": "línea"}).set_index("línea")
                st.caption(f"{ev.fuente} · {len(vista)} fila(s)")
                st.dataframe(vista.head(500), width="stretch")
            elif res.pcap and ev.fuente == res.pcap.get("nombre"):
                fl = res.pcap["flujos"]
                nums = [int(x) for x in re.findall(r"\d+", ev.ref)]
                st.caption(f"{ev.fuente} · paquetes {ev.ref}")
                st.dataframe(fl[fl.frame_ini.isin(nums)], hide_index=True, width="stretch")
    else:
        st.info("No hay detecciones con esa severidad.")


# --------------------------------------------------------------------- tráfico de red (pcap)
COLS_FLUJO = {"sospechoso": "Sospechoso", "inicio": "Inicio", "fin": "Fin", "src": "Origen", "sport": "Puerto origen",
              "dst": "Destino", "dport": "Puerto destino", "bytes_cli": "Bytes enviados",
              "bytes_srv": "Bytes recibidos", "registros": "Envíos de datos", "cadencia_s": "Intervalo medio (s)",
              "duracion_s": "Duración (s)", "frame_ini": "Paquete inicial", "frame_fin": "Paquete final"}

with tabs[5]:
    intro("Tráfico de red", "Resumen de la captura PCAP: las conexiones TCP y los dominios consultados. "
                            "Las conexiones sospechosas aparecen primero.")
    if not res.pcap:
        st.info("No se cargó ninguna captura de red (PCAP).")
    else:
        p = res.pcap
        c = st.columns(4)
        c[0].metric("Paquetes", f"{p['paquetes']:,}")
        c[1].metric("Conexiones TCP", p["flujos_tcp"])
        c[2].metric("Respuestas DNS", p["dns"])
        c[3].metric("Desfase de reloj", f"{p['desfase_s']:+.0f} s",
                    help=f"Diferencia entre el reloj de la captura y el de los registros, estimada con "
                         f"{p['coincidencias']} conexiones que coinciden con el firewall. Las horas se corrigen.")
        if p.get("desde") is not None:
            st.caption(f"Periodo de la captura (reloj original): {p['desde']:%H:%M:%S} a {p['hasta']:%H:%M:%S}")
        sosp = {ip for a in res.alertas if a.regla == "P01" for ip in a.indicadores.get("ip", [])}
        fl = p["flujos"].copy()
        if len(fl):
            fl["sospechoso"] = fl.dst.isin(sosp)
            fl = fl.sort_values(["sospechoso", "inicio"], ascending=[False, True])
            fl = fl[[k for k in COLS_FLUJO if k in fl.columns]].rename(columns=COLS_FLUJO)
            bloque("<div class='hu-intro'><h3 style='font-size:1.05rem'>Conexiones TCP</h3></div>")
            st.dataframe(fl, hide_index=True, width="stretch",
                         column_config={"Sospechoso": st.column_config.CheckboxColumn()})
        if len(p["dns_df"]):
            bloque("<div class='hu-intro'><h3 style='font-size:1.05rem'>Dominios consultados</h3>"
                   "<p>Los dominios que consulta un solo equipo aparecen primero: son los más raros.</p></div>")
            d = p["dns_df"]
            res_dns = d.groupby("query").agg(consultas=("frame", "size"), equipos=("cliente", "nunique"),
                                             respuestas=("respuestas", lambda s: ", ".join(sorted({x for l in s for x in l}))))
            res_dns = res_dns.sort_values("equipos").reset_index()
            res_dns.columns = ["Dominio", "Consultas", "Equipos que lo consultan", "IP resueltas"]
            st.dataframe(res_dns, hide_index=True, width="stretch")


# --------------------------------------------------------------------- archivos
COLS_INV = {"archivo": "Archivo", "tipo": "Tipo", "filas": "Registros", "bytes": "Tamaño (bytes)",
            "desde": "Desde", "hasta": "Hasta", "sha256": "SHA-256"}

with tabs[6]:
    intro("Archivos analizados", "Cadena de custodia: el SHA-256 es un código único de cada archivo. Si alguien "
                                 "lo modifica, el código cambia, así que sirve para demostrar que la evidencia "
                                 "analizada es la original.")
    inv = pd.DataFrame(res.inventario)
    if len(inv):
        inv = inv[[k for k in COLS_INV if k in inv.columns]].rename(columns=COLS_INV)
        st.dataframe(inv, hide_index=True, width="stretch")
    else:
        st.info("No se pudo leer ningún archivo.")


# --------------------------------------------------------------------- reporte
with tabs[7]:
    intro("Reporte", "El mismo contenido listo para compartir. Markdown para leerlo o pegarlo en un documento; "
                     "JSON para otras herramientas.")
    md = reporte.markdown(res)
    c = st.columns([1, 2, 2, 1])
    c[1].download_button("Descargar reporte (Markdown)", md.encode("utf-8"), "reporte_incidente.md", "text/markdown",
                         width="stretch")
    c[2].download_button("Descargar resultados (JSON)", reporte.json_export(res).encode("utf-8"),
                         "resultados.json", "application/json", width="stretch")
    st.write("")
    with st.container(border=True):
        st.markdown(md)
