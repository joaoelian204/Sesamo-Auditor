"""
integraciones/playwright_crawler.py — Crawler headless con Playwright

Extiende el crawling estático con un navegador headless que ejecuta
JavaScript, clica botones, llena formularios y captura peticiones de red.

Requiere: pip install playwright && playwright install chromium
"""

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse
from core.logger import get_logger

logger = get_logger("playwright_crawler")

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_DISPONIBLE = True
except ImportError:
    PLAYWRIGHT_DISPONIBLE = False
    logger.warning("Playwright no instalado. Usa: pip install playwright && playwright install chromium")


@dataclass
class MetadataCrawlDinamico:
    urls_descubiertas: set[str] = field(default_factory=set)
    endpoints_api: set[str] = field(default_factory=set)
    formularios: list[dict] = field(default_factory=list)
    archivos_js: list[str] = field(default_factory=list)
    peticiones_red: list[dict] = field(default_factory=list)
    localStorage: dict = field(default_factory=dict)
    cookies: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "urls_descubiertas": list(self.urls_descubiertas),
            "endpoints_api": list(self.endpoints_api),
            "formularios": self.formularios,
            "archivos_js": self.archivos_js,
            "peticiones_red": self.peticiones_red,
        }

    def resumen(self) -> str:
        return (
            f"Superficie dinámica descubierta:\n"
            f"  URLs:        {len(self.urls_descubiertas)}\n"
            f"  APIs:        {len(self.endpoints_api)}\n"
            f"  Formularios: {len(self.formularios)}\n"
            f"  JS:          {len(self.archivos_js)}\n"
            f"  Peticiones:  {len(self.peticiones_red)}"
        )


class PlaywrightCrawler:
    """
    Crawler headless que ejecuta JavaScript y captura peticiones de red.

    Complementa al Crawler estático (BS4) descubriendo:
    - URLs de SPAs renderizadas dinámicamente
    - Endpoints API de fetch/XHR
    - Formularios dinámicos
    - LocalStorage y cookies
    """

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.max_urls: int = cfg.get("max_urls", 100)
        self.max_depth: int = cfg.get("max_depth", 3)
        self.timeout_ms: int = cfg.get("timeout_ms", 30000)
        self.headless: bool = cfg.get("headless", True)
        self.user_agent: str = cfg.get("user_agent", "SesamoAuditor/1.0 (Playwright)")
        self.viewport: dict = cfg.get("viewport", {"width": 1280, "height": 720})

    def rastrear(self, target_url: str, exclusiones: list[str] | None = None) -> MetadataCrawlDinamico:
        if not PLAYWRIGHT_DISPONIBLE:
            logger.error("Playwright no disponible. Instálalo con: pip install playwright && playwright install chromium")
            return MetadataCrawlDinamico()

        exclusiones = exclusiones or []
        metadata = MetadataCrawlDinamico()
        dominio_base = urlparse(target_url).netloc

        logger.info(f"Iniciando crawling headless de {target_url}")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                user_agent=self.user_agent,
                viewport=self.viewport,
                ignore_https_errors=True,
            )

            page = context.new_page()

            peticiones_api: set[str] = set()

            def on_request(request):
                url = request.url
                if dominio_base in url:
                    resource_type = request.resource_type
                    if resource_type in ("xhr", "fetch"):
                        metadata.peticiones_red.append({
                            "url": url,
                            "method": request.method,
                            "type": resource_type,
                        })
                        if "/api/" in url or "/rest/" in url or "/v1/" in url or "/graphql" in url:
                            metadata.endpoints_api.add(url.split("?")[0])
                        metadata.urls_descubiertas.add(url.split("?")[0])
                    elif resource_type == "script" and url.endswith(".js"):
                        metadata.archivos_js.append(url)

            page.on("request", on_request)

            cola = [(target_url, 0)]
            visitadas = set()

            while cola and len(metadata.urls_descubiertas) < self.max_urls:
                url_actual, profundidad = cola.pop(0)

                if url_actual in visitadas:
                    continue
                if any(excl in url_actual for excl in exclusiones):
                    continue
                if profundidad > self.max_depth:
                    continue
                if urlparse(url_actual).netloc != dominio_base:
                    continue

                visitadas.add(url_actual)

                try:
                    page.goto(url_actual, wait_until="networkidle", timeout=self.timeout_ms)
                except PWTimeout:
                    logger.debug(f"Timeout cargando {url_actual}, continuando igual...")
                except Exception as e:
                    logger.debug(f"Error cargando {url_actual}: {e}")
                    continue

                metadata.urls_descubiertas.add(url_actual)

                # Extraer links del DOM renderizado
                links = page.eval_on_selector_all(
                    "a[href]", "els => els.map(el => el.href)"
                )
                for link in links:
                    if link and dominio_base in link:
                        cola.append((link.split("#")[0], profundidad + 1))

                # Extraer formularios
                forms = page.evaluate("""() => {
                    return Array.from(document.forms).map(f => ({
                        action: f.action,
                        method: f.method,
                        inputs: Array.from(f.elements).map(e => ({
                            name: e.name,
                            type: e.type,
                            value: e.value
                        }))
                    }));
                }""")
                for form in forms:
                    if form.get("inputs"):
                        metadata.formularios.append(form)

                # Extraer endpoints de localStorage (SPA state)
                try:
                    ls = page.evaluate("() => JSON.parse(JSON.stringify(localStorage))")
                    if isinstance(ls, dict):
                        metadata.localStorage.update(ls)
                        for key, val in ls.items():
                            if isinstance(val, str) and ("/api/" in val or "/rest/" in val):
                                metadata.endpoints_api.add(val)
                except Exception:
                    pass

                # Clickar botones para revelar contenido dinámico
                self._clickar_botones(page, metadata)

                logger.debug(f"[Profundidad {profundidad}] {url_actual} ({len(links)} links, {len(forms)} forms)")

            browser.close()

        logger.info(f"Crawling headless completado.")
        logger.info(metadata.resumen())
        return metadata

    def _clickar_botones(self, page, metadata: MetadataCrawlDinamico):
        """Clica botones para revelar contenido dinámico."""
        selectores = [
            "button:not([disabled])",
            "a.btn",
            "[role=button]",
            ".load-more",
            ".show-more",
            "#loadMore",
            "button[aria-expanded=false]",
            "[data-toggle=collapse]",
        ]
        for selector in selectores:
            try:
                btns = page.query_selector_all(selector)
                for btn in btns[:5]:
                    try:
                        btn.click(timeout=2000)
                        page.wait_for_timeout(500)
                    except Exception:
                        pass
            except Exception:
                pass
