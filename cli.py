"""FootPrint desde la terminal (útil como respaldo de la demo o para automatizar).

    python cli.py <carpeta_con_evidencias> [--reporte reporte.md] [--json resultados.json]
"""
import argparse
import sys
from pathlib import Path

from footprint import analizar_carpeta
from footprint.reporte import json_export, markdown


def main():
    ap = argparse.ArgumentParser(description="Reconstruye incidentes a partir de logs CSV y PCAP.")
    ap.add_argument("carpeta")
    ap.add_argument("--reporte", help="ruta del reporte Markdown a generar")
    ap.add_argument("--json", help="ruta del JSON a generar")
    args = ap.parse_args()
    if not Path(args.carpeta).is_dir():
        sys.exit(f"No existe la carpeta {args.carpeta}")

    res = analizar_carpeta(args.carpeta)
    for w in res.advertencias:
        print("ADVERTENCIA:", w)
    print(f"\n{len(res.alertas)} detecciones · {len(res.incidentes)} incidente(s) · {len(res.aisladas)} aisladas\n")
    for n, inc in enumerate(res.incidentes, 1):
        print(f"INCIDENTE {n}: {inc.host} ({inc.usuario})  {inc.inicio:%H:%M:%S} → {inc.fin:%H:%M:%S}  "
              f"puntaje {inc.puntaje}")
        print("  Tácticas:", " → ".join(inc.tacticas))
        for a in inc.alertas:
            print(f"  {a.inicio:%H:%M:%S}  {a.tactica:<19} {a.titulo}")
            print(f"            {a.refs(4)}")
        for tipo, texto in inc.hipotesis:
            print(f"  [{tipo}] {texto}")
        print()
    if res.aisladas:
        print("Alertas aisladas:")
        for a in res.aisladas:
            print(f"  {a.inicio:%H:%M:%S}  {a.host:<10} {a.titulo}")
    if args.reporte:
        Path(args.reporte).write_text(markdown(res), encoding="utf-8")
        print(f"\nReporte: {args.reporte}")
    if args.json:
        Path(args.json).write_text(json_export(res), encoding="utf-8")
        print(f"JSON: {args.json}")


if __name__ == "__main__":
    main()
