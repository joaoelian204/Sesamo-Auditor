"""
core/browser_interaction.py — Helper de Interacción con Navegador Headless (Playwright)

Permite automatizar interacciones de segundo paso sobre Single Page Applications (SPA),
haciendo click en botones, rellenando formularios, capturando logs de la consola
(para detectar XSS/errores) y monitorizando eventos de red.
"""

from typing import Optional, Any
from core.logger import get_logger

logger = get_logger("browser_interaction")

try:
    # type: ignore
    from playwright.sync_api import sync_playwright, Browser, Page
    PLAYWRIGHT_DISPONIBLE = True
except ImportError:
    PLAYWRIGHT_DISPONIBLE = False
    logger.warning("Playwright no está instalado. Instálalo con: pip install playwright && playwright install chromium")


class BrowserInteractionHelper:
    """
    Clase utilitaria para interactuar con páginas dinámicas usando Playwright
    de forma síncrona y segura.
    """

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._playwright = None
        self._browser: Optional[Any] = None
        self.consola_logs: list[dict] = []

    def iniciar(self) -> bool:
        """Inicializa Playwright y el navegador Chromium."""
        if not PLAYWRIGHT_DISPONIBLE:
            return False

        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)
            logger.info("Navegador Chromium headless iniciado correctamente.")
            return True
        except Exception as e:
            logger.error(f"Error iniciando Playwright/Chromium: {e}")
            self.cerrar()
            return False

    def obtener_pagina(self) -> Optional[Any]:
        """Obtiene una nueva pestaña (Page) con listeners de consola y red."""
        if not self._browser:
            return None

        try:
            context = self._browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720}
            )
            page = context.new_page()

            # Listener de consola para capturar canarios XSS o errores JS
            def on_console(msg):
                self.consola_logs.append({
                    "tipo": msg.type,
                    "texto": msg.text,
                    "location": msg.location
                })
                logger.debug(f"[Consola Browser] [{msg.type}] {msg.text}")

            page.on("console", on_console)
            return page
        except Exception as e:
            logger.error(f"Error creando nueva página: {e}")
            return None

    def interactuar_formulario(
        self,
        url: str,
        campos_input: dict[str, str],
        submit_selector: Optional[str] = None,
        esperar_selector: Optional[str] = None,
        timeout_ms: int = 5000
    ) -> bool:
        """
        Navega a la URL, rellena los campos indicados y hace submit.

        Args:
            url: URL base de la página.
            campos_input: Diccionario { 'selector_o_name': 'valor_payload' }
            submit_selector: Selector CSS del botón a hacer click. Si es None, pulsa Enter.
            esperar_selector: Esperar a que este selector aparezca en el DOM tras submit.
            timeout_ms: Tiempo de espera en milisegundos.

        Returns:
            True si se completó la interacción con éxito sin excepciones.
        """
        page = self.obtener_pagina()
        if not page:
            return False

        try:
            self.consola_logs.clear()
            logger.info(f"Navegando a {url} para interacción Headless...")
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)

            # Rellenar inputs
            for selector, valor in campos_input.items():
                # Primero intentar selector genérico o atributo name
                try:
                    if page.locator(selector).count() > 0:
                        page.fill(selector, valor)
                    elif page.locator(f"input[name='{selector}']").count() > 0:
                        page.fill(f"input[name='{selector}']", valor)
                    elif page.locator(f"textarea[name='{selector}']").count() > 0:
                        page.fill(f"textarea[name='{selector}']", valor)
                except Exception as e:
                    logger.debug(f"No se pudo rellenar el input {selector}: {e}")

            # Hacer submit
            if submit_selector and page.locator(submit_selector).count() > 0:
                page.click(submit_selector)
            else:
                # Pulsar Enter en el último elemento modificado
                page.keyboard.press("Enter")

            # Esperar a respuesta de red o DOM
            if esperar_selector:
                try:
                    page.wait_for_selector(esperar_selector, timeout=timeout_ms)
                except Exception:
                    logger.debug(f"Timeout esperando selector {esperar_selector}")
            else:
                page.wait_for_timeout(1000) # Espera neutral para animaciones/JS

            return True

        except Exception as e:
            logger.warning(f"Error interactuando en navegador Headless en {url}: {e}")
            return False
        finally:
            try:
                page.close()
            except Exception:
                pass

    def cerrar(self):
        """Cierra el navegador y limpia la sesión de Playwright."""
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        self._browser = None
        self._playwright = None
