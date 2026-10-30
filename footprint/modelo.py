"""Modelo común: toda detección produce una Alerta con su evidencia trazable."""
from dataclasses import dataclass, field
from datetime import datetime

# Orden de la cadena de ataque (MITRE ATT&CK), usado para ordenar y para el grafo.
TACTICAS = [
    "Acceso inicial",
    "Ejecución",
    "Evasión",
    "Mando y control",
    "Descubrimiento",
    "Movimiento lateral",
    "Colección",
    "Exfiltración",
]


@dataclass
class Evidencia:
    fuente: str          # firewall.csv, dns.csv, ..., suspicious-traffic.pcap
    ref: str             # "534" (línea) o "470-511" (frames del PCAP)

    def __str__(self):
        prefijo = "frames" if self.fuente.endswith(".pcap") else ""
        return f"{self.fuente}:{prefijo}{self.ref}" if not prefijo else f"{self.fuente} {prefijo} {self.ref}"


@dataclass
class Alerta:
    regla: str
    titulo: str
    tactica: str
    tecnica: str
    severidad: int                  # 1 = informativa ... 5 = crítica
    host: str
    inicio: datetime
    fin: datetime
    descripcion: str
    usuario: str = ""
    evidencias: list = field(default_factory=list)
    indicadores: dict = field(default_factory=dict)   # {"ip": [...], "dominio": [...], ...}
    tipo: str = "Hecho"             # Hecho | Hipótesis

    def refs(self, maximo=6):
        partes = [str(e) for e in self.evidencias[:maximo]]
        if len(self.evidencias) > maximo:
            partes.append(f"(+{len(self.evidencias) - maximo})")
        return "; ".join(partes)


@dataclass
class Incidente:
    host: str
    usuario: str
    inicio: datetime
    fin: datetime
    puntaje: int
    tacticas: list
    alertas: list
    hipotesis: list = field(default_factory=list)
