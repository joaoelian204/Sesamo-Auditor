"""
core/crawler.py — Crawler de Superficie de Ataque de Sésamo Auditor

Descubridor de la superficie de ataque de una aplicación web:
- Crawling BFS recursivo con profundidad configurable
- Extracción de formularios HTML (<form>, <input>)
- Descubrimiento de endpoints API desde archivos JavaScript
- Análisis de robots.txt
- Respeta el scope del dominio base

Uso:
    from core.crawler import Crawler
    from core.http_client import HttpClient

    client = HttpClient()
    crawler = Crawler(client, config={"max_depth": 10, "max_urls": 500})
    metadata = crawler.rastrear("https://target.com")

    print(metadata.urls_descubiertas)
    print(metadata.formularios)
    print(metadata.endpoints_api)
"""

import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.http_client import HttpClient
from core.logger import get_logger

logger = get_logger("crawler")

# Configuración por defecto del crawler
_CONFIG_DEFECTO = {
    "max_depth": 10,
    "max_urls": 500,
    "respetar_scope": True,
    "max_workers": 10,
}

# Extensiones de archivos que NO se rastrean (binarios, multimedia, etc.)
_EXTENSIONES_IGNORADAS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar",
    ".woff", ".woff2", ".ttf", ".eot",
    ".map",
}

# Patrones regex para descubrir endpoints API en archivos JavaScript
_PATRONES_API = [
    r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']',
    r'["\'](/rest/[a-zA-Z0-9_/\-]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-]+)["\']',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
    r'href:\s*["\'](/[a-zA-Z0-9_/\-]+)["\']',
    # Sub-path patterns (search, find, query, filter, lookup)
    r'["\'](/(?:api|rest)/[a-zA-Z0-9_/\-]+/(?:search|find|query|filter|lookup))["\']',
    # URLs with query parameters embedded in JS
    r'["\'](/(?:api|rest)/[a-zA-Z0-9_/\-]+\?[^"\']+)["\']',
    # Angular HttpClient patterns (this.http.get<T>('/api/...'))
    r'(?:this\.http|http)\.\w+\s*[<(]\s*[`"\']([^`"\']+)[`"\']',
    # Template literal paths
    r'`(/(?:api|rest)/[a-zA-Z0-9_/${\}/\-]+)`',
]


@dataclass
class FormularioDescubierto:
    """Representa un formulario HTML descubierto durante el crawling."""
    url_pagina: str
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serializa el formulario a diccionario."""
        return {
            "url_pagina": self.url_pagina,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
        }


@dataclass
class MetadataCrawl:
    """
    Resultado completo del crawling — superficie de ataque descubierta.

    Contiene todas las URLs, formularios, endpoints API y archivos
    encontrados durante el rastreo. Esta estructura se pasa al engine
    y de ahí a cada plugin como metadata.
    """
    urls_descubiertas: set[str] = field(default_factory=set)
    formularios: list[FormularioDescubierto] = field(default_factory=list)
    endpoints_api: set[str] = field(default_factory=set)
    archivos_js: list[str] = field(default_factory=list)
    archivos_estaticos: list[str] = field(default_factory=list)
    robots_txt: Optional[str] = None

    def to_dict(self) -> dict:
        """Serializa la metadata a diccionario para los plugins."""
        return {
            "urls_descubiertas": list(self.urls_descubiertas),
            "formularios": [f.to_dict() for f in self.formularios],
            "endpoints_api": list(self.endpoints_api),
            "archivos_js": self.archivos_js,
            "archivos_estaticos": self.archivos_estaticos,
            "robots_txt": self.robots_txt,
        }

    def resumen(self) -> str:
        """Genera un resumen legible del crawling."""
        return (
            f"Superficie descubierta:\n"
            f"  URLs:        {len(self.urls_descubiertas)}\n"
            f"  Formularios: {len(self.formularios)}\n"
            f"  APIs:        {len(self.endpoints_api)}\n"
            f"  Archivos JS: {len(self.archivos_js)}\n"
            f"  Estáticos:   {len(self.archivos_estaticos)}\n"
            f"  robots.txt:  {'Sí' if self.robots_txt else 'No'}"
        )


class Crawler:
    """
    Crawler BFS que descubre la superficie de ataque de una aplicación web.

    Recorre la aplicación en anchura (BFS) hasta la profundidad máxima
    configurada, extrayendo links, formularios, endpoints API y archivos
    JavaScript relevantes para los plugins de auditoría.

    Attributes:
        http_client: Cliente HTTP compartido para hacer requests.
        max_depth: Profundidad máxima de crawling.
        max_urls: Cantidad máxima de URLs a descubrir.
        respetar_scope: Si True, solo sigue URLs del mismo dominio.
    """

    def __init__(self, http_client: HttpClient, config: dict | None = None):
        """
        Inicializa el crawler con el cliente HTTP y configuración.

        Args:
            http_client: Instancia compartida de HttpClient.
            config: Configuración del crawler. Claves opcionales:
                - max_depth (int): Profundidad máxima (default: 10)
                - max_urls (int): URLs máximas a descubrir (default: 500)
                - respetar_scope (bool): Solo seguir URLs del mismo dominio (default: True)
        """
        cfg = {**_CONFIG_DEFECTO, **(config or {})}
        self.http_client = http_client
        self.max_depth: int = cfg["max_depth"]
        self.max_urls: int = cfg["max_urls"]
        self.respetar_scope: bool = cfg["respetar_scope"]
        self.max_workers: int = cfg["max_workers"]

    def rastrear(self, target_url: str, exclusiones: list[str] | None = None) -> MetadataCrawl:
        """
        Ejecuta el crawling completo sobre la URL objetivo.

        Realiza un recorrido BFS desde la URL base, descubriendo
        URLs, formularios, endpoints API y archivos JavaScript.

        Args:
            target_url: URL base del objetivo a rastrear.
            exclusiones: Lista de patrones de URL a excluir del crawling
                        (ej: ["/logout", "/static/"]).

        Returns:
            MetadataCrawl con toda la superficie de ataque descubierta.
        """
        exclusiones = exclusiones or []
        metadata = MetadataCrawl()
        dominio_base = urlparse(target_url).netloc

        logger.info(f"Iniciando crawling de {target_url}")
        logger.info(f"Configuración: max_depth={self.max_depth}, max_urls={self.max_urls}")

        # Cola BFS: (url, profundidad_actual)
        cola: deque[tuple[str, int]] = deque()
        cola.append((target_url, 0))
        visitadas: set[str] = set()

        # Intentar obtener robots.txt
        metadata.robots_txt = self._obtener_robots_txt(target_url)

        # ─── Fase 1: Descargar páginas en paralelo ───
        logger.info("Descargando páginas (paralelo)...")
        max_workers = self.max_workers

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures_pool = {}  # url -> Future

            while cola and len(metadata.urls_descubiertas) < self.max_urls:
                # Llenar el pool con lotes de URLs
                while cola and len(futures_pool) < max_workers * 2:
                    url_actual, profundidad = cola.popleft()
                    url_normalizada = self._normalizar_url(url_actual)

                    if url_normalizada in visitadas:
                        continue
                    if self._esta_excluida(url_normalizada, exclusiones):
                        continue
                    if profundidad > self.max_depth:
                        continue
                    if self._es_archivo_binario(url_normalizada):
                        metadata.archivos_estaticos.append(url_normalizada)
                        continue

                    visitadas.add(url_normalizada)
                    future = pool.submit(
                        self.http_client.get, url_normalizada
                    )
                    futures_pool[future] = (url_normalizada, profundidad)

                # Recolectar resultados a medida que terminan
                if not futures_pool:
                    break

                for future in as_completed(futures_pool, timeout=30):
                    url_normalizada, profundidad = futures_pool.pop(future)
                    try:
                        response = future.result()
                    except Exception:
                        continue
                    if response is None:
                        continue

                    content_type = response.headers.get("Content-Type", "")
                    if response.status_code != 200:
                        continue

                    metadata.urls_descubiertas.add(url_normalizada)
                    logger.debug(
                        f"[Profundidad {profundidad}] {url_normalizada} "
                        f"({response.status_code})"
                    )

                    if "text/html" in content_type or "application/xhtml" in content_type:
                        soup = BeautifulSoup(response.text, "html.parser")

                        links = self._extraer_links(soup, url_normalizada, dominio_base)
                        for link in links:
                            if link not in visitadas:
                                cola.append((link, profundidad + 1))

                        formularios = self._extraer_formularios(soup, url_normalizada)
                        metadata.formularios.extend(formularios)

                        scripts = self._extraer_scripts(soup, url_normalizada)
                        for script_url in scripts:
                            if script_url not in metadata.archivos_js:
                                metadata.archivos_js.append(script_url)

                    elif "javascript" in content_type or url_normalizada.endswith(".js"):
                        endpoints = self._analizar_javascript(response.text, target_url)
                        metadata.endpoints_api.update(endpoints)

        # Cerrar cualquier future pendiente
        for future in futures_pool:
            future.cancel()

        # Analizar todos los archivos JS descubiertos (en paralelo)
        js_por_analizar = [js for js in metadata.archivos_js if js not in visitadas]
        if js_por_analizar:
            js_workers = min(len(js_por_analizar), 10)
            with ThreadPoolExecutor(max_workers=js_workers) as executor:
                futuros = {
                    executor.submit(self._analizar_js_url, js_url, target_url): js_url
                    for js_url in js_por_analizar
                }
                for futuro in as_completed(futuros):
                    try:
                        endpoints = futuro.result()
                        metadata.endpoints_api.update(endpoints)
                    except Exception as e:
                        logger.debug(f"Error analizando JS: {e}")

        logger.info(f"Crawling completado.")
        logger.info(metadata.resumen())

        return metadata

    def _normalizar_url(self, url: str) -> str:
        """Normaliza una URL eliminando fragmentos y trailing slashes duplicados."""
        parsed = urlparse(url)
        # Eliminar fragmento (#)
        url_limpia = parsed._replace(fragment="").geturl()
        return url_limpia

    def _esta_excluida(self, url: str, exclusiones: list[str]) -> bool:
        """Verifica si una URL contiene algún patrón de exclusión."""
        path = urlparse(url).path
        return any(excl in path for excl in exclusiones)

    def _es_archivo_binario(self, url: str) -> bool:
        """Verifica si la URL apunta a un archivo binario (imagen, font, etc.)."""
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in _EXTENSIONES_IGNORADAS)

    def _extraer_links(
        self, soup: BeautifulSoup, url_actual: str, dominio_base: str
    ) -> list[str]:
        """
        Extrae y normaliza todos los links válidos de una página HTML.

        Args:
            soup: Objeto BeautifulSoup de la página parseada.
            url_actual: URL de la página actual (para resolver rutas relativas).
            dominio_base: Dominio del target (para verificar scope).

        Returns:
            Lista de URLs absolutas válidas dentro del scope.
        """
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()

            # Ignorar links vacíos, javascript:, mailto:, tel:
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue

            # Resolver URL relativa a absoluta
            url_absoluta = urljoin(url_actual, href)

            # Verificar scope si está habilitado
            if self.respetar_scope:
                dominio_link = urlparse(url_absoluta).netloc
                if dominio_link != dominio_base:
                    continue

            links.append(url_absoluta)

        return links

    def _extraer_formularios(
        self, soup: BeautifulSoup, url_pagina: str
    ) -> list[FormularioDescubierto]:
        """
        Extrae todos los formularios HTML de una página.

        Para cada <form> encontrado, extrae:
        - action (URL de destino del form)
        - method (GET/POST)
        - inputs (nombre y tipo de cada <input>, <textarea>, <select>)

        Args:
            soup: Objeto BeautifulSoup de la página parseada.
            url_pagina: URL de la página donde se encontró el formulario.

        Returns:
            Lista de FormularioDescubierto.
        """
        formularios = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                action = urljoin(url_pagina, action)
            else:
                action = url_pagina

            method = form.get("method", "GET").upper()

            # Extraer todos los campos del formulario
            inputs = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                nombre = input_tag.get("name", "")
                tipo = input_tag.get("type", "text")
                if nombre:
                    inputs.append({
                        "name": nombre,
                        "type": tipo,
                        "value": input_tag.get("value", ""),
                    })

            formulario = FormularioDescubierto(
                url_pagina=url_pagina,
                action=action,
                method=method,
                inputs=inputs,
            )
            formularios.append(formulario)

            logger.debug(
                f"Formulario encontrado: {method} {action} "
                f"({len(inputs)} campos)"
            )

        return formularios

    def _extraer_scripts(self, soup: BeautifulSoup, url_pagina: str) -> list[str]:
        """
        Extrae URLs de archivos JavaScript referenciados en la página.

        Args:
            soup: Objeto BeautifulSoup de la página parseada.
            url_pagina: URL de la página actual.

        Returns:
            Lista de URLs absolutas de archivos .js encontrados.
        """
        scripts = []
        for script_tag in soup.find_all("script", src=True):
            src = script_tag["src"].strip()
            url_absoluta = urljoin(url_pagina, src)
            scripts.append(url_absoluta)

        return scripts

    def _analizar_javascript(self, contenido_js: str, base_url: str) -> set[str]:
        """
        Analiza el contenido de un archivo JavaScript buscando endpoints API.

        Usa patrones regex para detectar rutas de API como:
        - /api/users, /rest/products, /v1/auth
        - fetch("/api/data"), axios.get("/rest/items")
        - /rest/products/search?q=term (con query params)

        Args:
            contenido_js: Contenido textual del archivo JavaScript.
            base_url: URL base del target para resolver rutas relativas.

        Returns:
            Set de URLs de endpoints API descubiertos.
        """
        endpoints = set()

        for patron in _PATRONES_API:
            matches = re.findall(patron, contenido_js)
            for match in matches:
                # Limpiar template literal variables (${...})
                match_limpio = re.sub(r'\$\{[^}]+\}', '', match)
                if not match_limpio or match_limpio == '/':
                    continue

                # Resolver rutas relativas
                if match_limpio.startswith("/"):
                    endpoint = urljoin(base_url, match_limpio)
                elif match_limpio.startswith("http"):
                    endpoint = match_limpio
                else:
                    continue

                endpoints.add(endpoint)

        if endpoints:
            logger.debug(f"  {len(endpoints)} endpoints API descubiertos en JS")

        return endpoints

    def _analizar_js_url(self, js_url: str, target_url: str) -> set[str]:
        """Descarga y analiza un archivo JS en busca de endpoints API."""
        js_response = self.http_client.get(js_url)
        if js_response and js_response.status_code == 200:
            return self._analizar_javascript(js_response.text, target_url)
        return set()

    def _obtener_robots_txt(self, target_url: str) -> Optional[str]:
        """
        Intenta obtener el contenido de robots.txt del target.

        No obedece las reglas de robots.txt (es una auditoría de seguridad),
        pero lo reporta como información relevante.

        Args:
            target_url: URL base del target.

        Returns:
            Contenido de robots.txt si existe, None si no.
        """
        robots_url = urljoin(target_url, "/robots.txt")
        response = self.http_client.get(robots_url)

        if response and response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "text/plain" in content_type or "text/html" not in content_type:
                logger.info(f"robots.txt encontrado ({len(response.text)} bytes)")
                return response.text

        logger.debug("robots.txt no encontrado")
        return None
