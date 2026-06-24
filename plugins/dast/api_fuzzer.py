"""
plugins/dast/api_fuzzer.py — Plugin de Fuzzing de Endpoints API

Descubre endpoints ocultos, archivos de configuración expuestos y
paneles de administración no protegidos mediante fuzzing de rutas
desde un diccionario externo.

Categoría OWASP: A05:2021 — Security Misconfiguration
CWE: CWE-200 (Exposure of Sensitive Information)
"""

from urllib.parse import urljoin

from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import (
    CategoriaOWASP,
    Confianza,
    Hallazgo,
    Severidad,
)

logger = get_logger("api_fuzzer")

# Firmas que indican información sensible en respuestas
_FIRMAS_SENSIBLES = [
    "password", "secret", "token", "api_key", "apikey",
    "private_key", "access_token", "database", "connection_string",
    "credentials", "Authorization",
]

# Firmas que indican stack traces / errores de debug
_FIRMAS_DEBUG = [
    "Traceback (most recent call last)",
    "at Object.<anonymous>",
    "stack trace",
    "Exception in",
    "Error:",
    "DEBUG = True",
    "SQLSTATE",
]


class APIFuzzerPlugin(BasePlugin):
    """
    Plugin de fuzzing de endpoints para descubrimiento de recursos ocultos.

    Envía requests a rutas comunes cargadas desde wordlists/fuzz_paths.txt
    y clasifica las respuestas por código HTTP y contenido.
    """

    @property
    def nombre(self) -> str:
        return "API Endpoint Fuzzer"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A05_SECURITY_MISCONFIGURATION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        """Ejecuta el fuzzing de endpoints contra el target."""
        hallazgos = []

        try:
            rutas = self.cargar_payloads("fuzz_paths.txt")
        except FileNotFoundError:
            logger.error("Archivo fuzz_paths.txt no encontrado.")
            return hallazgos

        logger.info(f"Rutas de fuzzing cargadas: {len(rutas)}")

        # Detectar si es SPA (single page application) — toda ruta devuelve index.html
        # Si 3 rutas aleatorias devuelven exactamente el mismo contenido, es SPA
        es_spa = False
        spa_baseline_text = ""
        for test_path in ["/xx_sesamo_test_1", "/xx_sesamo_test_2", "/xx_sesamo_test_3"]:
            test_url = urljoin(target_url, test_path)
            resp = http_client.get(test_url)
            if resp:
                if not spa_baseline_text:
                    spa_baseline_text = resp.text
                elif resp.text == spa_baseline_text:
                    es_spa = True
                else:
                    es_spa = False
                    break
        if es_spa:
            spa_baseline_len = len(spa_baseline_text)
            logger.info("SPA detectada — ignorando rutas que devuelvan el index.html")
        else:
            spa_baseline_len = 0

        # Obtener baseline para detectar redirecciones "catch-all" (falsos 200)
        baseline_len = 0
        baseline_text = ""
        baseline_resp = http_client.get(target_url)
        if baseline_resp:
            baseline_len = len(baseline_resp.content)
            baseline_text = baseline_resp.text

        # También obtener un baseline de página inexistente para ver si hay comportamiento custom
        inexistente_url = urljoin(target_url, "/recurso_inexistente_sesamo_999")
        inexistente_resp = http_client.get(inexistente_url)
        inexistente_len = 0
        if inexistente_resp:
            inexistente_len = len(inexistente_resp.content)

        # Excluir rutas ya descubiertas por el crawler
        urls_conocidas = set(metadata.get("urls_descubiertas", []))

        for ruta in rutas:
            url_test = urljoin(target_url, ruta)

            # Saltar si ya fue descubierta por el crawler
            if url_test in urls_conocidas:
                continue

            response = http_client.get(url_test)
            if response is None:
                continue

            # Si el tamaño coincide exactamente con el home o con el manejador de 404 ficticio, ignorar
            longitud_actual = len(response.content)
            if longitud_actual == baseline_len or longitud_actual == inexistente_len:
                continue

            # Si es SPA y el contenido coincide con el index.html, ignorar
            if es_spa and longitud_actual == spa_baseline_len and response.text == spa_baseline_text:
                continue

            # Comparación por similitud básica de tamaño (umbral del 98%)
            if baseline_len > 0 and abs(longitud_actual - baseline_len) / baseline_len < 0.02:
                continue

            # ─── Analizar respuesta ───
            if response.status_code == 200:
                hallazgo = self._analizar_recurso_encontrado(
                    url_test, ruta, response
                )
                if hallazgo:
                    hallazgos.append(hallazgo)

            elif response.status_code == 403:
                # Recurso existe pero está protegido
                hallazgo = Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.INFO,
                    confianza=Confianza.FIRME,
                    url_afectada=url_test,
                    parametro="",
                    metodo_http="GET",
                    payload_usado=ruta,
                    evidencia=f"Recurso existe pero acceso denegado (HTTP 403)",
                    cwe_id="CWE-200",
                    remediacion=(
                        "Verificar que la protección es intencional. "
                        "Considerar retornar 404 en vez de 403 para no "
                        "confirmar la existencia del recurso."
                    ),
                )
                hallazgos.append(hallazgo)
                logger.info(f"  🔵 Recurso protegido: {ruta} (403)")

            elif response.status_code >= 500:
                # Error del servidor — potencialmente interesante
                hallazgo = self._analizar_error_servidor(
                    url_test, ruta, response
                )
                if hallazgo:
                    hallazgos.append(hallazgo)

        return hallazgos

    def _analizar_recurso_encontrado(
        self, url: str, ruta: str, response
    ) -> Hallazgo | None:
        """
        Analiza un recurso accesible (HTTP 200) para determinar su sensibilidad.

        Returns:
            Hallazgo si es sensible, None si es benigno.
        """
        texto = response.text
        content_type = response.headers.get("Content-Type", "")

        # Determinar severidad según el tipo de recurso
        severidad = Severidad.BAJA
        evidencia_extra = ""

        # Verificar si contiene información sensible
        texto_lower = texto.lower()
        firmas_encontradas = [
            firma for firma in _FIRMAS_SENSIBLES
            if firma.lower() in texto_lower
        ]
        if firmas_encontradas:
            severidad = Severidad.ALTA
            evidencia_extra = f" Firmas sensibles: {', '.join(firmas_encontradas[:3])}"

        # Verificar si contiene stack traces / debug info
        firmas_debug = [
            firma for firma in _FIRMAS_DEBUG
            if firma.lower() in texto_lower
        ]
        if firmas_debug:
            severidad = max(severidad, Severidad.MEDIA)
            evidencia_extra += f" Debug info detectado."

        # Archivos especialmente sensibles
        rutas_criticas = [
            ".env", ".git/config", "docker-compose", "database",
            "backup", "dump.sql", "phpinfo",
        ]
        if any(rc in ruta.lower() for rc in rutas_criticas):
            severidad = max(severidad, Severidad.ALTA)

        # Solo reportar si es relevante (no páginas HTML genéricas de 404 mapeadas a 200)
        if len(texto) < 10:
            return None

        icono = "🟠" if severidad >= Severidad.ALTA else "🟡" if severidad >= Severidad.MEDIA else "🔵"
        logger.info(f"  {icono} Recurso descubierto: {ruta} ({len(texto)} bytes)")

        return Hallazgo(
            plugin_nombre=self.nombre,
            categoria_owasp=self.categoria_owasp,
            severidad=severidad,
            confianza=Confianza.FIRME,
            url_afectada=url,
            parametro="",
            metodo_http="GET",
            payload_usado=ruta,
            evidencia=(
                f"Recurso accesible: HTTP 200, {len(texto)} bytes, "
                f"Content-Type: {content_type}.{evidencia_extra}"
            ),
            cwe_id="CWE-200",
            remediacion=(
                "Verificar si este recurso debe ser público. "
                "Si no, restringir acceso o eliminarlo del servidor. "
                "Implementar autenticación para recursos sensibles."
            ),
        )

    def _analizar_error_servidor(
        self, url: str, ruta: str, response
    ) -> Hallazgo | None:
        """Analiza errores del servidor (5xx) para detectar info leaks."""
        texto = response.text

        # Buscar stack traces o información de debug
        texto_lower = texto.lower()
        tiene_debug = any(
            firma.lower() in texto_lower for firma in _FIRMAS_DEBUG
        )

        if tiene_debug:
            logger.warning(f"  🟡 Error con debug info: {ruta} ({response.status_code})")

            return Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.MEDIA,
                confianza=Confianza.FIRME,
                url_afectada=url,
                parametro="",
                metodo_http="GET",
                payload_usado=ruta,
                evidencia=(
                    f"Error del servidor HTTP {response.status_code} con "
                    f"información de debug/stack trace expuesta."
                ),
                cwe_id="CWE-209",
                remediacion=(
                    "Desactivar modo debug en producción. "
                    "Configurar páginas de error personalizadas sin stack traces. "
                    "No exponer información interna del servidor."
                ),
            )

        return None
