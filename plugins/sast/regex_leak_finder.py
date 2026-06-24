"""
plugins/sast/regex_leak_finder.py — Plugin de Detección de Secretos

Busca secretos expuestos (API keys, JWT, passwords, tokens) en archivos
JavaScript descargados y respuestas HTTP usando patrones regex.

Categoría OWASP: A02:2021 — Cryptographic Failures
CWE: CWE-798 (Hard-coded Credentials)
"""

import re
from urllib.parse import urljoin

from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import (
    CategoriaOWASP,
    Confianza,
    Hallazgo,
    Severidad,
)

logger = get_logger("regex_leak_finder")

# Valores que indican falsos positivos (ejemplos, placeholders, tests)
_FALSOS_POSITIVOS = [
    "example", "test", "placeholder", "xxx", "your_",
    "INSERT_", "REPLACE_", "TODO", "changeme", "password123",
    "sample", "demo", "dummy", "fake", "mock",
    "0000000", "1111111", "abcdef", "123456",
    "password", "passwd", "pwd", "contraseña", "contrasena",
]

_PATRONES_FALSOS_HTML = [
    'name="password"', "name='password'",
    'name="passwd"', "name='passwd'",
    'name="pwd"', "name='pwd'",
    'type="password"', "type='password'",
    'placeholder="password', "placeholder='password",
    'name="contraseña', "name='contraseña",
    'id="password"', "id='password'",
    '<input', '<form', '</form>',
    'name="search', 'name="email', 'name="user', 'name="login',
]


class RegexLeakFinderPlugin(BasePlugin):
    """
    Plugin de detección de secretos y credenciales expuestos.

    Carga patrones regex desde wordlists/secrets_patterns.txt y los aplica
    sobre el contenido de archivos JS y respuestas HTML del target.
    """

    @property
    def nombre(self) -> str:
        return "Secrets & Credentials Leak Finder"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A02_CRYPTOGRAPHIC_FAILURES

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def _cargar_patrones(self) -> list[tuple[str, str]]:
        """
        Carga patrones regex desde el archivo externo.

        Returns:
            Lista de tuplas (nombre_patron, regex_compilado).
        """
        patrones = []
        try:
            lineas = self.cargar_payloads("secrets_patterns.txt")
            for linea in lineas:
                if ":::" in linea:
                    partes = linea.split(":::", 1)
                    nombre = partes[0].strip()
                    regex = partes[1].strip()
                    patrones.append((nombre, regex))
        except FileNotFoundError:
            logger.warning("Archivo secrets_patterns.txt no encontrado.")
        return patrones

    def _es_falso_positivo(self, valor: str) -> bool:
        valor_lower = valor.lower()
        return any(fp in valor_lower for fp in _FALSOS_POSITIVOS)

    def _es_contexto_html(self, valor: str) -> bool:
        return any(p in valor.lower() for p in _PATRONES_FALSOS_HTML)

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        """Ejecuta la búsqueda de secretos en archivos JS y respuestas HTTP."""
        hallazgos = []
        patrones = self._cargar_patrones()

        if not patrones:
            logger.error("No se pudieron cargar patrones de secretos.")
            return hallazgos

        logger.info(f"Patrones cargados: {len(patrones)}")

        # ─── Analizar archivos JavaScript ───
        archivos_js = metadata.get("archivos_js", [])
        logger.info(f"Analizando {len(archivos_js)} archivos JavaScript...")

        for js_url in archivos_js:
            response = http_client.get(js_url)
            if response is None or response.status_code != 200:
                continue

            hallazgos_js = self._analizar_contenido(
                js_url, response.text, patrones
            )
            hallazgos.extend(hallazgos_js)

        # ─── Analizar URLs descubiertas (respuestas HTML) ───
        urls = metadata.get("urls_descubiertas", [])
        logger.info(f"Analizando {len(urls)} páginas HTML...")

        for url in urls[:50]:  # Limitar para no ser excesivo
            response = http_client.get(url)
            if response is None or response.status_code != 200:
                continue

            hallazgos_html = self._analizar_contenido(
                url, response.text, patrones
            )
            hallazgos.extend(hallazgos_html)

        return hallazgos

    def _analizar_contenido(
        self, url: str, contenido: str, patrones: list[tuple[str, str]]
    ) -> list[Hallazgo]:
        """
        Aplica todos los patrones regex sobre un contenido textual.

        Args:
            url: URL fuente del contenido.
            contenido: Texto a analizar.
            patrones: Lista de tuplas (nombre, regex).

        Returns:
            Lista de Hallazgos encontrados.
        """
        hallazgos = []

        for nombre_patron, regex in patrones:
            try:
                matches = re.findall(regex, contenido)
            except re.error:
                continue

            for match in matches:
                valor = match if isinstance(match, str) else match[0] if match else ""

                if self._es_falso_positivo(valor):
                    continue

                # Filtrar contexto HTML (nombres de campos, etiquetas, etc.)
                if self._es_contexto_html(valor):
                    continue

                # Truncar evidencia para no exponer secretos completos en reportes
                valor_truncado = valor[:40] + "..." if len(valor) > 40 else valor

                severidad = self._determinar_severidad(nombre_patron)

                hallazgo = Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=severidad,
                    confianza=Confianza.FIRME,
                    url_afectada=url,
                    parametro=nombre_patron,
                    metodo_http="GET",
                    payload_usado="",
                    evidencia=f"Secreto detectado ({nombre_patron}): '{valor_truncado}'",
                    cwe_id="CWE-798",
                    remediacion=(
                        "Eliminar secretos del código fuente. "
                        "Usar variables de entorno o un gestor de secretos. "
                        "Rotar inmediatamente cualquier credencial expuesta."
                    ),
                )
                hallazgos.append(hallazgo)

                logger.warning(
                    f"  🟠 Secreto encontrado: {nombre_patron} en {url}"
                )

        return hallazgos

    def _determinar_severidad(self, nombre_patron: str) -> Severidad:
        """Determina severidad según el tipo de secreto encontrado."""
        patrones_criticos = [
            "private_key", "aws_secret", "password_field",
            "db_connection_string", "connection_string",
        ]
        patrones_altos = [
            "jwt_token", "bearer_token", "api_key", "api_secret",
            "aws_access_key", "github_token", "stripe_key",
            "slack_token", "firebase_key", "sendgrid_key",
        ]

        nombre_lower = nombre_patron.lower()

        if any(p in nombre_lower for p in patrones_criticos):
            return Severidad.CRITICA
        elif any(p in nombre_lower for p in patrones_altos):
            return Severidad.ALTA
        else:
            return Severidad.MEDIA
