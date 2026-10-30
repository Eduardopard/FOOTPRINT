# FootPrint — reconstrucción automática de incidentes

Aplicación web local que recibe registros CSV (autenticación, DNS, endpoint, firewall,
proxy) y capturas PCAP, detecta comportamientos sospechosos, los correlaciona por equipo
y tiempo, y reconstruye la cadena de ataque citando la fila exacta de cada evidencia.

Con las evidencias de *Operación Huella Digital* reconstruye sola el incidente de
FIN-PC07: 7 tácticas de MITRE ATT&CK, de la descarga a la exfiltración, separando hechos,
hipótesis y lo que no se puede determinar, en menos de 2 segundos.

## Cómo ejecutarlo

Requiere Python 3.10 o superior.

```bash
pip install -r requirements.txt
streamlit run app.py
```

Se abre en `http://localhost:8501`. Sube los archivos desde la barra lateral y pulsa **Analizar**.

Desde la terminal (respaldo de la demo):

```bash
python cli.py ruta/a/evidencias --reporte reporte.md --json resultados.json
```

Pruebas (19: 11 unitarias con datos sintéticos y 8 de aceptación con las evidencias):

```bash
EVIDENCIAS=ruta/a/evidencias pytest -v          # Linux / macOS
set EVIDENCIAS=ruta\a\evidencias && pytest -v    # Windows (cmd)
```

## Cómo funciona

```
CSV + PCAP ──► 1. Carga ──► 2. Detección ──► 3. Correlación ──► 4. Explicación
               por columnas   11 reglas        por equipo y        línea de tiempo, grafo,
               + SHA-256      genéricas        ventana de 2 h      hechos vs hipótesis, reporte
```

1. **Carga** (`footprint/cargadores.py`). Cada CSV se reconoce por sus columnas, no por su
   nombre. Se conserva el número de línea original para citar la evidencia
   (`firewall.csv:3691`) y se calcula el SHA-256 de cada archivo (cadena de custodia).
2. **Detección** (`footprint/reglas.py`, `footprint/pcap.py`). Reglas por comportamiento y por
   rareza frente al resto de la red. **Ninguna regla contiene IPs, dominios ni hosts del
   caso**: los umbrales están en `footprint/config.yaml`.
3. **Correlación** (`footprint/correlacion.py`). Las alertas se agrupan por equipo; solo se
   abre un incidente si un equipo acumula **3 o más tácticas distintas** en 2 horas. Una
   alerta suelta (un fallo de contraseña, un respaldo grande) queda como *aislada*: así se
   reducen los falsos positivos.
4. **Explicación**. Se generan las hipótesis que enlazan fases (descarga → ejecución,
   compresión → exfiltración por tamaño y tiempo) y se marcan como tales. El reporte se
   descarga en Markdown o JSON.

### Reglas

| Id | Detección | Táctica | Lógica |
| --- | --- | --- | --- |
| R01 | Descarga desde dominio poco común | Acceso inicial | dominio visitado ≤ 3 veces por 1 usuario + tipo de archivo de riesgo |
| R02 | PowerShell con parámetros de evasión | Ejecución | ≥ 2 patrones: ventana oculta, bypass, codificado, rutas temporales |
| R03 | Comandos de reconocimiento | Descubrimiento | ≥ 2 de whoami, nltest, net... en 15 min |
| R04 | Lectura masiva de archivos | Colección | ≥ 100 lecturas del mismo usuario en 15 min |
| R05 | Compresión en ruta temporal | Colección | tar/7z/rar o archivo comprimido creado en %TEMP% |
| R06 | Beaconing | Mando y control | ≥ 4 conexiones pequeñas, variación de intervalos < 15 %, destino de un solo host |
| R07 | Barrido SMB | Movimiento lateral | ≥ 4 destinos 445/139/135 con pocos bytes en 10 min |
| R08 | Salida grande | Exfiltración | ≥ 50 MB a destino con < 20 conexiones históricas (si es habitual: informativa) |
| R09 | Fallos de acceso a varios equipos | Movimiento lateral | ≥ 3 fallos a ≥ 3 destinos en 10 min |
| R10 | Autenticación hacia una estación | Movimiento lateral | autenticación de red cuyo destino es la red de usuarios |
| P01 | Sesiones periódicas en el PCAP | Mando y control | flujos periódicos o hacia IP resuelta desde un dominio que consulta un solo equipo |

**Alineación de reloj del PCAP.** FootPrint compara los flujos del PCAP con las conexiones del
firewall y estima el desfase que hace coincidir más pares. En el reto detecta +3605 s
(3 coincidencias) y corrige las horas antes de correlacionar.

### Añadir o ajustar una regla

- Cambiar un umbral: editar `footprint/config.yaml`.
- Nueva regla: una función en `footprint/reglas.py` que reciba un DataFrame y devuelva
  `Alerta`s, añadida en `ejecutar_reglas`, más su prueba en `tests/test_reglas.py`.
- Nueva fuente: añadir su firma de columnas en `FIRMAS` (`footprint/cargadores.py`).

## Seguridad de la solución

- **Sin red.** Todo se procesa en memoria en el equipo del analista. Streamlit escucha solo
  en `127.0.0.1` y con la telemetría desactivada (`.streamlit/config.toml`).
- **Evidencia intacta.** Los archivos no se modifican ni se guardan; su SHA-256 aparece en
  la pestaña *Fuentes* y en el reporte.
- **Entradas hostiles.** Límite de 500 MiB por archivo y de paquetes por PCAP; archivos
  corruptos o con esquema desconocido generan una advertencia, no un fallo; el texto que
  viene de la evidencia se escapa antes de mostrarse como HTML; las exportaciones CSV
  neutralizan fórmulas (inyección CSV).
- **Trazabilidad.** Cada conclusión cita su fila o sus frames, y la interfaz permite ver la
  fila original de cualquier detección.

## Estructura

```
app.py                 interfaz web (Streamlit)
cli.py                 versión de terminal
footprint/
  config.yaml          umbrales de todas las reglas
  cargadores.py        reconocimiento de fuentes, líneas, hashes
  reglas.py            reglas sobre CSV
  pcap.py              DNS, flujos TCP, alineación de reloj, regla P01
  correlacion.py       incidentes e hipótesis
  grafo.py             grafo del incidente
  reporte.py           Markdown, JSON y CSV
  modelo.py            Alerta, Evidencia, Incidente
tests/                 pruebas unitarias y de aceptación
```

## Límites conocidos

- Los umbrales están calibrados para este volumen de registros; en una red grande conviene
  ajustarlos o calcularlos por percentiles.
- El PCAP se lee entero en memoria; para capturas de varios GB habría que procesarlas en
  bloques o resumirlas antes con Zeek.
- Las hipótesis se construyen con reglas fijas (tiempo y tamaño); no sustituyen la
  revisión del analista.
