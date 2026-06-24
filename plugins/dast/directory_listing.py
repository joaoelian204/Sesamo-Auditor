"""
plugins/dast/directory_listing.py — Plugin de Directory Listing

Detecta directorios con listing habilitado que exponen archivos
del servidor (.bak, .kdbx, .yml, .pyc, etc.).

Categoría OWASP: A05:2021 — Security Misconfiguration
CWE: CWE-548 (Information Exposure Through Directory Listing)
"""

import re
from urllib.parse import urljoin
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("directory_listing")

_PATRON_DIR_LISTING = re.compile(
    r'(<title>listing directory|Index of |Parent Directory|Directory listing for)',
    re.IGNORECASE,
)

_DIRECTORIOS_COMUNES = [
    "/ftp/", "/backup/", "/backups/", "/uploads/", "/upload/",
    "/files/", "/download/", "/downloads/", "/assets/", "/static/",
    "/public/", "/media/", "/images/", "/img/", "/css/", "/js/",
    "/logs/", "/log/", "/data/", "/config/", "/conf/",
    "/private/", "/admin/", "/temp/", "/tmp/", "/cache/",
    "/.git/", "/.svn/", "/.env/", "/vendor/", "/node_modules/",
    "/storage/", "/export/", "/import/", "/docs/", "/documentation/",
    "/.well-known/", "/robots.txt", "/sitemap.xml",
    "/api/", "/rest/", "/graphql", "/swagger", "/api-docs",
]

_ARCHIVOS_SENSIBLES_PATRON = re.compile(
    r'\.(bak|old|orig|swp|save|tmp|kdbx|pyc|key|pem|crt|csv|sql|dump|log)$',
    re.IGNORECASE,
)


class DirectoryListingPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "Directory Listing Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A05_SECURITY_MISCONFIGURATION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []

        for directorio in _DIRECTORIOS_COMUNES:
            url_test = urljoin(target_url, directorio)
            response = http_client.get(url_test)
            if response is None:
                continue

            if response.status_code != 200:
                continue

            if _PATRON_DIR_LISTING.search(response.text):
                archivos = self._extraer_archivos(response.text)
                criticos = [a for a in archivos if _ARCHIVOS_SENSIBLES_PATRON.search(a)]
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.ALTA if criticos else Severidad.MEDIA,
                    confianza=Confianza.CONFIRMADA,
                    url_afectada=url_test,
                    parametro="",
                    metodo_http="GET",
                    payload_usado="",
                    evidencia=(
                        f"Directory listing habilitado en {directorio} — {len(archivos)} archivo(s) expuesto(s)"
                        f"{', incluye: ' + ', '.join(criticos[:5]) if criticos else ''}"
                    ),
                    cwe_id="CWE-548",
                    remediacion=(
                        "Deshabilitar directory listing en el servidor web. "
                        "Configurar Apache/NGINX para retornar 403 Forbidden en directorios sin índice. "
                        "Eliminar o proteger archivos sensibles expuestos."
                    ),
                ))
                logger.warning(f"  {'🔴' if criticos else '🟠'} Directory listing: {url_test} ({len(archivos)} archivos{' — críticos: ' + ', '.join(criticos[:3]) if criticos else ''})")

        return hallazgos

    def _extraer_archivos(self, html: str) -> list[str]:
        archivos = re.findall(r'href="([^"]+)"', html)
        return [a for a in archivos if a not in (".", "..", "/") and not a.startswith("?")]
