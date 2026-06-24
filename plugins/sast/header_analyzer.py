"""
plugins/sast/header_analyzer.py — Plugin de Análisis de Headers de Seguridad

Verifica que las respuestas HTTP incluyan los headers de seguridad
recomendados y que las cookies tengan los flags de seguridad apropiados.

Categoría OWASP: A05:2021 — Security Misconfiguration
CWE: CWE-693 (Protection Mechanism Failure)
"""

from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import (
    CategoriaOWASP,
    Confianza,
    Hallazgo,
    Severidad,
)

logger = get_logger("header_analyzer")


class HeaderAnalyzerPlugin(BasePlugin):
    """
    Plugin de análisis de headers de seguridad HTTP y cookies.

    Verifica la presencia de headers de seguridad críticos y analiza
    los flags de cookies para detectar configuraciones inseguras.
    """

    @property
    def nombre(self) -> str:
        return "Security Headers Analyzer"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A05_SECURITY_MISCONFIGURATION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def _cargar_headers_esperados(self) -> list[dict]:
        """
        Carga los headers de seguridad esperados desde el archivo externo.

        Returns:
            Lista de dicts con keys: header, severidad, descripcion, remediacion.
        """
        headers = []
        try:
            lineas = self.cargar_payloads("security_headers.txt")
            for linea in lineas:
                partes = linea.split(":::")
                if len(partes) == 4:
                    headers.append({
                        "header": partes[0].strip(),
                        "severidad": partes[1].strip(),
                        "descripcion": partes[2].strip(),
                        "remediacion": partes[3].strip(),
                    })
        except FileNotFoundError:
            logger.warning("Archivo security_headers.txt no encontrado.")
        return headers

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        """Ejecuta el análisis de headers y cookies de seguridad."""
        hallazgos = []

        headers_esperados = self._cargar_headers_esperados()
        logger.info(f"Headers de seguridad a verificar: {len(headers_esperados)}")

        # Hacer request a la URL principal
        response = http_client.get(target_url)
        if response is None:
            logger.error(f"No se pudo conectar a {target_url}")
            return hallazgos

        response_headers = response.headers

        # ─── Verificar headers de seguridad faltantes ───
        logger.info("Verificando headers de seguridad...")

        for header_info in headers_esperados:
            header_name = header_info["header"]
            if header_name not in response_headers:
                severidad = self._mapear_severidad(header_info["severidad"])

                hallazgo = Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=severidad,
                    confianza=Confianza.CONFIRMADA,
                    url_afectada=target_url,
                    parametro=header_name,
                    metodo_http="GET",
                    payload_usado="",
                    evidencia=f"Header de seguridad '{header_name}' ausente. "
                              f"{header_info['descripcion']}",
                    cwe_id="CWE-693",
                    remediacion=header_info["remediacion"],
                )
                hallazgos.append(hallazgo)

                icono = severidad.icono
                logger.info(
                    f"  {icono} Header faltante: {header_name} "
                    f"({severidad.etiqueta})"
                )

        # ─── Verificar CORS permisivo ───
        cors_header = response_headers.get("Access-Control-Allow-Origin", "")
        if cors_header == "*":
            hallazgo = Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.MEDIA,
                confianza=Confianza.CONFIRMADA,
                url_afectada=target_url,
                parametro="Access-Control-Allow-Origin",
                metodo_http="GET",
                payload_usado="",
                evidencia=(
                    "CORS configurado con wildcard (*) — permite requests "
                    "desde cualquier origen, potencialmente exponiendo datos "
                    "a sitios maliciosos."
                ),
                cwe_id="CWE-942",
                remediacion=(
                    "Restringir Access-Control-Allow-Origin a dominios "
                    "específicos y de confianza."
                ),
            )
            hallazgos.append(hallazgo)
            logger.warning("  🟡 CORS permisivo detectado: Access-Control-Allow-Origin: *")

        # ─── Verificar cookies inseguras ───
        cookies_raw = response.headers.get("Set-Cookie", "")
        if cookies_raw:
            hallazgos_cookies = self._analizar_cookies(
                target_url, cookies_raw
            )
            hallazgos.extend(hallazgos_cookies)

        return hallazgos

    def _analizar_cookies(self, url: str, cookies_raw: str) -> list[Hallazgo]:
        """Analiza los flags de seguridad de las cookies."""
        hallazgos = []
        cookies_lower = cookies_raw.lower()

        # Verificar flag HttpOnly
        if "httponly" not in cookies_lower:
            hallazgos.append(Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.MEDIA,
                confianza=Confianza.CONFIRMADA,
                url_afectada=url,
                parametro="Cookie:HttpOnly",
                metodo_http="GET",
                payload_usado="",
                evidencia="Cookie sin flag HttpOnly — accesible via JavaScript (document.cookie)",
                cwe_id="CWE-1004",
                remediacion="Añadir flag HttpOnly a todas las cookies de sesión.",
            ))
            logger.info("  🟡 Cookie sin HttpOnly")

        # Verificar flag Secure
        if "secure" not in cookies_lower:
            hallazgos.append(Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.MEDIA,
                confianza=Confianza.CONFIRMADA,
                url_afectada=url,
                parametro="Cookie:Secure",
                metodo_http="GET",
                payload_usado="",
                evidencia="Cookie sin flag Secure — se transmite en conexiones HTTP no cifradas",
                cwe_id="CWE-614",
                remediacion="Añadir flag Secure a todas las cookies de sesión.",
            ))
            logger.info("  🟡 Cookie sin Secure")

        # Verificar flag SameSite
        if "samesite" not in cookies_lower:
            hallazgos.append(Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.BAJA,
                confianza=Confianza.CONFIRMADA,
                url_afectada=url,
                parametro="Cookie:SameSite",
                metodo_http="GET",
                payload_usado="",
                evidencia="Cookie sin flag SameSite — vulnerable a ataques CSRF",
                cwe_id="CWE-1275",
                remediacion="Añadir flag SameSite=Strict o SameSite=Lax a las cookies.",
            ))
            logger.info("  🔵 Cookie sin SameSite")

        return hallazgos

    def _mapear_severidad(self, severidad_str: str) -> Severidad:
        """Mapea string de severidad a Enum."""
        mapa = {
            "INFO": Severidad.INFO,
            "BAJA": Severidad.BAJA,
            "MEDIA": Severidad.MEDIA,
            "ALTA": Severidad.ALTA,
            "CRITICA": Severidad.CRITICA,
        }
        return mapa.get(severidad_str.upper(), Severidad.MEDIA)
