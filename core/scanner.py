"""
core/scanner.py — Orquestador de escaneo en capas de Sésamo Auditor

Implementa la arquitectura en capas:
- Scanner: orquestador principal
- HostProcess: ejecución y flujo de control aislado por target/host
"""

import re
from urllib.parse import urlparse
from core.logger import get_logger
from core.modelos import ResultadoEscaneo, Confianza, Severidad

logger = get_logger("scanner")

class HostProcess:
    """
    Gestiona el proceso de escaneo para un Host específico (target).
    Implementa las políticas de exclusión de parámetros, tech detection,
    sensibilidad de alertas y límites.
    """

    def __init__(self, target_url: str, config: dict, http_client):
        self.target_url = target_url
        self.config = config
        self.http_client = http_client
        self.target_domain = urlparse(target_url).netloc

        # Parámetros excluidos por defecto
        self.params_excluidos = {
            "asp.net_sessionid", "aspsessionid", "phpsessid", "jsessionid", 
            "sessid", "siteserver", "__viewstate", "__eventvalidation", 
            "__eventtarget", "__eventargument", "javax.faces.viewstate", 
            "cfid", "cftoken", "csrf", "csrf_token", "xsrf_token"
        }
        # Agregar exclusiones de config si existen
        config_exclusiones = config.get("plugins", {}).get("excluir_parametros", [])
        for param in config_exclusiones:
            self.params_excluidos.add(param.lower())

        # Tecnologías detectadas en el target
        self.tecnologias_detectadas = self._detectar_tecnologias()
        logger.info(f"HostProcess inicializado para {self.target_url} | Tecnologías detectadas: {self.tecnologias_detectadas}")

    def _detectar_tecnologias(self) -> set[str]:
        """Detecta tecnologías basadas en headers y respuestas iniciales (Tech Detection)."""
        tecnologias = set()
        try:
            resp = self.http_client.get(self.target_url)
            if resp:
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                
                # Servidor web
                server = headers.get("server", "")
                if "apache" in server:
                    tecnologias.add("apache")
                if "nginx" in server:
                    tecnologias.add("nginx")
                if "iis" in server or "microsoft" in server:
                    tecnologias.add("iis")
                    tecnologias.add("windows")
                
                # Cabecera X-Powered-By
                powered = headers.get("x-powered-by", "")
                if "php" in powered:
                    tecnologias.add("php")
                if "asp" in powered:
                    tecnologias.add("asp")
                    tecnologias.add("windows")
                if "express" in powered or "node" in powered:
                    tecnologias.add("nodejs")

                # Cookies de sesión comunes
                cookies = [c.name.lower() for c in self.http_client.session.cookies]
                if any("phpsessid" in c for c in cookies):
                    tecnologias.add("php")
                if any("jsessionid" in c for c in cookies):
                    tecnologias.add("java")
                if any("aspsessionid" in c or "asp.net_sessionid" in c for c in cookies):
                    tecnologias.add("asp")
                    tecnologias.add("windows")

                # Cuerpo de la respuesta (análisis simple)
                body = resp.text.lower()
                if "wp-content" in body or "wp-includes" in body:
                    tecnologias.add("wordpress")
                    tecnologias.add("php")

        except Exception as e:
            logger.warning(f"Error detectando tecnologías: {e}")
        return tecnologias

    def parametro_excluido(self, nombre_param: str) -> bool:
        """Determina si un parámetro debe ser excluido del escaneo activo."""
        nombre_lower = nombre_param.lower()
        # Verificar matches exactos o prefijos
        for excl in self.params_excluidos:
            if excl in nombre_lower:
                return True
        return False

    def plugin_aplica_a_tecnologia(self, plugin) -> bool:
        """Determina si las tecnologías del target son compatibles con el plugin."""
        if not plugin.tech_targets:
            return True # Aplica a todo si no define targets
        
        # Verificar si al menos una tecnología objetivo coincide con las detectadas
        for tech in plugin.tech_targets:
            if tech.lower() in self.tecnologias_detectadas:
                return True
        return False

    def esta_en_scope(self, url: str) -> bool:
        """Verifica si la URL pertenece al host en scope y no está excluida."""
        parsed = urlparse(url)
        if parsed.netloc != self.target_domain:
            return False

        exclusiones = self.config.get("target", {}).get("exclusiones", [])
        for excl in exclusiones:
            if excl in parsed.path:
                return False
        return True


class Scanner:
    """Orquestador general en capas."""

    def __init__(self, config: dict, http_client):
        self.config = config
        self.http_client = http_client

    def crear_host_process(self, target_url: str) -> HostProcess:
        return HostProcess(target_url, self.config, self.http_client)
