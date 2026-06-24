"""
core/modelos.py — Modelos de Datos de Sésamo Auditor

Define los tipos estrictos y estructuras de datos del framework:
- Severidad, Confianza, CategoriaOWASP (Enums)
- Hallazgo (Dataclass para cada vulnerabilidad individual)
- ResultadoEscaneo (Dataclass contenedora del escaneo completo)

Estos modelos son la base de todo el framework. Todos los plugins,
el engine, y los reportes dependen de estos tipos.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class Severidad(Enum):
    """
    Nivel de severidad de un hallazgo de seguridad.
    El valor numérico permite ordenamiento por criticidad.
    """
    INFO = (0, "ℹ️", "Informativo")
    BAJA = (1, "🔵", "Baja")
    MEDIA = (2, "🟡", "Media")
    ALTA = (3, "🟠", "Alta")
    CRITICA = (4, "🔴", "Crítica")

    def __init__(self, nivel: int, icono: str, etiqueta: str):
        self.nivel = nivel
        self.icono = icono
        self.etiqueta = etiqueta

    def __lt__(self, other):
        if not isinstance(other, Severidad):
            return NotImplemented
        return self.nivel < other.nivel

    def __le__(self, other):
        if not isinstance(other, Severidad):
            return NotImplemented
        return self.nivel <= other.nivel

    def __gt__(self, other):
        if not isinstance(other, Severidad):
            return NotImplemented
        return self.nivel > other.nivel

    def __ge__(self, other):
        if not isinstance(other, Severidad):
            return NotImplemented
        return self.nivel >= other.nivel


class Confianza(Enum):
    """
    Nivel de confianza en un hallazgo.
    - FALSE_POSITIVE: Falso positivo — se excluye de todo.
    - TENTATIVA: Indicios, podría ser falso positivo.
    - FIRME: Evidencia sólida pero no confirmada al 100%.
    - CONFIRMADA: Verificado con validación de segundo paso.
    """
    FALSE_POSITIVE = (0, "Falso Positivo")
    TENTATIVA = (1, "Tentativa")
    FIRME = (2, "Firme")
    CONFIRMADA = (3, "Confirmada")

    def __init__(self, nivel: int, etiqueta: str):
        self.nivel = nivel
        self.etiqueta = etiqueta


class CategoriaOWASP(Enum):
    """
    Mapeo directo a las categorías de OWASP Top 10 2021.
    Cada valor contiene el código y la descripción oficial.
    """
    A01_BROKEN_ACCESS_CONTROL = ("A01:2021", "Broken Access Control")
    A02_CRYPTOGRAPHIC_FAILURES = ("A02:2021", "Cryptographic Failures")
    A03_INJECTION = ("A03:2021", "Injection")
    A04_INSECURE_DESIGN = ("A04:2021", "Insecure Design")
    A05_SECURITY_MISCONFIGURATION = ("A05:2021", "Security Misconfiguration")
    A06_VULNERABLE_COMPONENTS = ("A06:2021", "Vulnerable and Outdated Components")
    A07_AUTH_FAILURES = ("A07:2021", "Identification and Authentication Failures")
    A08_DATA_INTEGRITY = ("A08:2021", "Software and Data Integrity Failures")
    A09_LOGGING_FAILURES = ("A09:2021", "Security Logging and Monitoring Failures")
    A10_SSRF = ("A10:2021", "Server-Side Request Forgery (SSRF)")

    def __init__(self, codigo: str, descripcion: str):
        self.codigo = codigo
        self.descripcion = descripcion

    def __str__(self) -> str:
        return f"{self.codigo} — {self.descripcion}"


@dataclass
class Hallazgo:
    """
    Representa una vulnerabilidad individual detectada por un plugin.

    Cada hallazgo contiene toda la información necesaria para:
    - Identificar la vulnerabilidad (nombre, CWE, categoría OWASP)
    - Localizar el problema (URL, parámetro, método HTTP)
    - Verificar la evidencia (payload usado, respuesta del servidor)
    - Remediar el problema (sugerencia de corrección)

    Attributes:
        plugin_nombre: Nombre del plugin que detectó el hallazgo.
        categoria_owasp: Categoría OWASP Top 10 correspondiente.
        severidad: Nivel de severidad (INFO a CRITICA).
        confianza: Nivel de confianza en el hallazgo.
        url_afectada: URL completa donde se detectó la vulnerabilidad.
        parametro: Nombre del parámetro vulnerable (query, body, header).
        metodo_http: Método HTTP usado (GET, POST, PUT, etc.).
        payload_usado: Payload exacto que provocó la vulnerabilidad.
        evidencia: Extracto de la respuesta que confirma la vulnerabilidad.
        cwe_id: Identificador CWE (Common Weakness Enumeration).
        remediacion: Sugerencia de corrección para el desarrollador.
        timestamp: Momento ISO 8601 en que se detectó el hallazgo.
    """
    plugin_nombre: str
    categoria_owasp: CategoriaOWASP
    severidad: Severidad
    confianza: Confianza
    url_afectada: str
    parametro: str = ""
    metodo_http: str = "GET"
    payload_usado: str = ""
    evidencia: str = ""
    cwe_id: str = ""
    remediacion: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    global_idx: int = 0

    def to_dict(self) -> dict:
        """Serializa el hallazgo a diccionario para exportación JSON/reportes."""
        return {
            "plugin_nombre": self.plugin_nombre,
            "categoria_owasp": {
                "codigo": self.categoria_owasp.codigo,
                "descripcion": self.categoria_owasp.descripcion,
            },
            "severidad": {
                "nivel": self.severidad.nivel,
                "etiqueta": self.severidad.etiqueta,
            },
            "confianza": {
                "nivel": self.confianza.nivel,
                "etiqueta": self.confianza.etiqueta,
            },
            "url_afectada": self.url_afectada,
            "parametro": self.parametro,
            "metodo_http": self.metodo_http,
            "payload_usado": self.payload_usado,
            "evidencia": self.evidencia,
            "cwe_id": self.cwe_id,
            "remediacion": self.remediacion,
            "timestamp": self.timestamp,
        }

    @property
    def clave_deduplicacion(self) -> tuple:
        """
        Clave única para eliminar hallazgos duplicados.
        Sigue la estrategia de deduplicación estricta de ZAP combinando:
        risk (severidad) + confidence + plugin_nombre + url_afectada + parametro + evidencia
        """
        return (
            self.severidad.nivel,
            self.confianza.nivel,
            self.plugin_nombre,
            self.url_afectada,
            self.parametro.lower(),
            self.evidencia.lower()
        )


@dataclass
class ResultadoEscaneo:
    """
    Contenedor completo de un escaneo de seguridad.

    Agrupa todos los hallazgos validados junto con la metadata del escaneo
    (target, duración, plugins ejecutados, URLs escaneadas).

    Attributes:
        target_url: URL objetivo del escaneo.
        fecha_inicio: Timestamp ISO 8601 del inicio del escaneo.
        fecha_fin: Timestamp ISO 8601 del fin del escaneo (se llena al finalizar).
        hallazgos: Lista de hallazgos validados encontrados.
        urls_escaneadas: Cantidad total de URLs analizadas.
        plugins_ejecutados: Lista de nombres de plugins que se ejecutaron.
    """
    target_url: str
    fecha_inicio: str = field(default_factory=lambda: datetime.now().isoformat())
    fecha_fin: Optional[str] = None
    hallazgos: list[Hallazgo] = field(default_factory=list)
    urls_escaneadas: int = 0
    plugins_ejecutados: list[str] = field(default_factory=list)

    @property
    def hallazgos_filtrados(self) -> list[Hallazgo]:
        """Retorna solo los hallazgos que no son clasificados como Falso Positivo."""
        return [h for h in self.hallazgos if h.confianza != Confianza.FALSE_POSITIVE]

    @property
    def duracion(self) -> str:
        """Calcula la duración del escaneo en formato legible HH:MM:SS."""
        if not self.fecha_fin:
            return "En progreso..."
        inicio = datetime.fromisoformat(self.fecha_inicio)
        fin = datetime.fromisoformat(self.fecha_fin)
        delta = fin - inicio
        horas, resto = divmod(int(delta.total_seconds()), 3600)
        minutos, segundos = divmod(resto, 60)
        return f"{horas:02d}:{minutos:02d}:{segundos:02d}"

    def por_severidad(self, severidad: Severidad) -> list[Hallazgo]:
        """Filtra hallazgos (excluyendo falsos positivos) por nivel de severidad."""
        return [h for h in self.hallazgos_filtrados if h.severidad == severidad]

    def por_categoria(self, categoria: CategoriaOWASP) -> list[Hallazgo]:
        """Filtra hallazgos (excluyendo falsos positivos) por categoría OWASP."""
        return [h for h in self.hallazgos_filtrados if h.categoria_owasp == categoria]

    def resumen(self) -> dict:
        """
        Genera un resumen ejecutivo del escaneo con conteos por severidad.
        Excluye automáticamente de estadísticas y conteos a los falsos positivos.

        Returns:
            Dict con conteos por severidad, total y score de riesgo.
        """
        conteos = {}
        for sev in Severidad:
            conteos[sev.etiqueta] = len(self.por_severidad(sev))

        return {
            "target": self.target_url,
            "duracion": self.duracion,
            "urls_escaneadas": self.urls_escaneadas,
            "plugins_ejecutados": len(self.plugins_ejecutados),
            "total_hallazgos": len(self.hallazgos_filtrados),
            "por_severidad": conteos,
            "score_riesgo": self.score_riesgo(),
        }

    def score_riesgo(self) -> int:
        """
        Calcula un score de riesgo global de 0 a 100.
        Excluye automáticamente a los falsos positivos.
        """
        pesos = {
            Severidad.CRITICA: 25,
            Severidad.ALTA: 10,
            Severidad.MEDIA: 5,
            Severidad.BAJA: 2,
            Severidad.INFO: 0,
        }
        score = sum(
            pesos[h.severidad] for h in self.hallazgos_filtrados
        )
        return min(score, 100)

    def deduplicar(self) -> None:
        """
        Elimina hallazgos duplicados basándose en la clave de deduplicación estricta.
        Conserva el hallazgo de mayor severidad cuando hay duplicados.
        """
        vistos: dict[tuple, Hallazgo] = {}
        for hallazgo in self.hallazgos:
            clave = hallazgo.clave_deduplicacion
            if clave not in vistos or hallazgo.severidad > vistos[clave].severidad:
                vistos[clave] = hallazgo
        self.hallazgos = list(vistos.values())

    def finalizar(self) -> None:
        """Marca el escaneo como finalizado con el timestamp actual."""
        self.fecha_fin = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Serializa el resultado completo a diccionario, excluyendo falsos positivos."""
        return {
            "target_url": self.target_url,
            "fecha_inicio": self.fecha_inicio,
            "fecha_fin": self.fecha_fin,
            "duracion": self.duracion,
            "urls_escaneadas": self.urls_escaneadas,
            "plugins_ejecutados": self.plugins_ejecutados,
            "total_hallazgos": len(self.hallazgos_filtrados),
            "score_riesgo": self.score_riesgo(),
            "resumen": self.resumen(),
            "hallazgos": [h.to_dict() for h in self.hallazgos_filtrados],
        }
