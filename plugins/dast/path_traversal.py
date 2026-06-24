"""
plugins/dast/path_traversal.py — Plugin de Directory Traversal / LFI

Detecta vulnerabilidades de traversal de directorios intentando acceder
a archivos fuera del directorio web raíz mediante payloads con ../ y
variantes de encoding.

Categoría OWASP: A01:2021 — Broken Access Control
CWE: CWE-22 (Path Traversal)
"""

from urllib.parse import urljoin, urlparse, parse_qs

from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import (
    CategoriaOWASP,
    Confianza,
    Hallazgo,
    Severidad,
)

logger = get_logger("path_traversal")

# Firmas que confirman acceso a archivos del sistema
_FIRMAS_ARCHIVOS_SISTEMA = [
    # Linux /etc/passwd
    "root:x:0:0:",
    "root:*:0:0:",
    "daemon:x:",
    "bin:x:",
    "nobody:x:",
    # Windows win.ini
    "[extensions]",
    "[fonts]",
    "[Mail]",
    "[boot loader]",
    "timeout=",
    # /proc/version
    "Linux version",
    # /etc/hosts
    "localhost",
]


class PathTraversalPlugin(BasePlugin):
    """
    Plugin de detección de directory traversal y LFI.

    Prueba payloads de traversal contra parámetros que potencialmente
    reciben nombres de archivo (download, file, path, etc.) y endpoints
    conocidos de descarga.
    """

    @property
    def nombre(self) -> str:
        return "Path Traversal Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        """Ejecuta el escaneo de directory traversal."""
        hallazgos = []

        try:
            payloads = self.cargar_payloads("traversal_payloads.txt")
        except FileNotFoundError:
            logger.error("Archivo traversal_payloads.txt no encontrado.")
            return hallazgos

        logger.info(f"Payloads cargados: {len(payloads)}")

        # ─── Probar parámetros de URLs que sugieren manejo de archivos ───
        urls = metadata.get("urls_descubiertas", [])
        params_archivo = {"file", "path", "doc", "document", "download",
                          "filename", "filepath", "page", "template",
                          "include", "dir", "folder", "src", "source"}

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            for param_name in params:
                if param_name.lower() in params_archivo:
                    hallazgos_param = self._probar_parametro(
                        url_base, param_name, params, payloads, http_client
                    )
                    hallazgos.extend(hallazgos_param)

        # ─── Probar endpoints comunes de descarga ───
        endpoints_descarga = [
            "/ftp/", "/download/", "/file/", "/files/",
            "/uploads/", "/static/", "/assets/",
        ]

        for endpoint in endpoints_descarga:
            url_endpoint = urljoin(target_url, endpoint)
            # Probar traversal directamente en la ruta
            for payload in payloads[:20]:  # Solo los más comunes
                url_test = urljoin(url_endpoint, payload)
                response = http_client.get(url_test)

                if response is None:
                    continue

                if self._contiene_firma_sistema(response.text):
                    hallazgo = Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=url_test,
                        parametro="path",
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=(
                            f"Contenido de archivo del sistema detectado en respuesta "
                            f"(HTTP {response.status_code})"
                        ),
                        cwe_id="CWE-22",
                        remediacion=(
                            "Validar y sanitizar todas las rutas de archivo. "
                            "Usar una whitelist de archivos permitidos. "
                            "Nunca concatenar input del usuario en rutas de archivo. "
                            "Usar chroot o sandboxing para el sistema de archivos."
                        ),
                    )
                    hallazgos.append(hallazgo)

                    logger.warning(
                        f"  🔴 Path Traversal detectado: {url_test}"
                    )
                    break

        # ─── Probar formularios con campos de archivo ───
        formularios = metadata.get("formularios", [])
        for formulario in formularios:
            inputs = formulario.get("inputs", [])
            for inp in inputs:
                if inp.get("name", "").lower() in params_archivo:
                    action = formulario.get("action", target_url)
                    if not action.startswith("http"):
                        action = urljoin(target_url, action)

                    hallazgos_form = self._probar_parametro(
                        action, inp["name"], {}, payloads, http_client
                    )
                    hallazgos.extend(hallazgos_form)

        return hallazgos

    def _probar_parametro(
        self, url_base: str, param_name: str, params_originales: dict,
        payloads: list[str], http_client
    ) -> list[Hallazgo]:
        """Prueba payloads de traversal contra un parámetro específico."""
        hallazgos = []

        for payload in payloads:
            params = {k: v[0] if isinstance(v, list) else v
                      for k, v in params_originales.items()}
            params[param_name] = payload

            response = http_client.get(url_base, params=params)
            if response is None:
                continue

            if self._contiene_firma_sistema(response.text):
                hallazgo = Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.CRITICA,
                    confianza=Confianza.CONFIRMADA,
                    url_afectada=url_base,
                    parametro=param_name,
                    metodo_http="GET",
                    payload_usado=payload,
                    evidencia=(
                        f"Archivo del sistema accedido via parámetro '{param_name}' "
                        f"(HTTP {response.status_code})"
                    ),
                    cwe_id="CWE-22",
                    remediacion=(
                        "Validar y sanitizar rutas de archivo. "
                        "Usar whitelist de archivos permitidos."
                    ),
                )
                hallazgos.append(hallazgo)

                logger.warning(
                    f"  🔴 Path Traversal: {url_base} [param: {param_name}]"
                )
                break

        return hallazgos

    def _contiene_firma_sistema(self, texto: str) -> bool:
        """Verifica si el texto contiene firmas de archivos del sistema."""
        return any(firma in texto for firma in _FIRMAS_ARCHIVOS_SISTEMA)
