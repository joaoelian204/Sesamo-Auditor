"""
plugins/dast/xss_scanner.py — Plugin de Cross-Site Scripting (XSS)

Detecta vulnerabilidades de XSS reflejado inyectando payloads con
tokens canary únicos en formularios y parámetros de URL, y verificando
si el canary aparece sin sanitizar en la respuesta HTTP.

Categoría OWASP: A03:2021 — Injection
CWE: CWE-79 (Cross-site Scripting)
"""

import secrets
from urllib.parse import urljoin, urlparse, parse_qs

from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import (
    CategoriaOWASP,
    Confianza,
    Hallazgo,
    Severidad,
)

logger = get_logger("xss_scanner")


class XSSPlugin(BasePlugin):
    """
    Plugin de detección de XSS reflejado con canary tokens.

    Cada payload contiene un placeholder {CANARY} que se reemplaza
    por un token único por prueba para confirmar reflexión exacta.
    """

    @property
    def nombre(self) -> str:
        return "XSS Reflected Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A03_INJECTION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def _generar_canary(self) -> str:
        """Genera un token canary único para esta prueba."""
        return f"sesamo_xss_{secrets.token_hex(4)}"

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        """Ejecuta el escaneo XSS contra formularios y URLs con parámetros."""
        hallazgos = []

        try:
            payloads_template = self.cargar_payloads("xss_payloads.txt")
        except FileNotFoundError:
            logger.error("Archivo xss_payloads.txt no encontrado.")
            return hallazgos

        logger.info(f"Payloads cargados: {len(payloads_template)}")

        # ─── Probar formularios ───
        formularios = metadata.get("formularios", [])
        logger.info(f"Probando {len(formularios)} formularios...")

        for formulario in formularios:
            hallazgos_form = self._probar_formulario(
                formulario, payloads_template, http_client, target_url
            )
            hallazgos.extend(hallazgos_form)

        # ─── Probar query strings ───
        urls = metadata.get("urls_descubiertas", [])
        urls_con_params = [u for u in urls if "?" in u]
        logger.info(f"Probando {len(urls_con_params)} URLs con parámetros...")

        for url in urls_con_params:
            hallazgos_url = self._probar_query_string(
                url, payloads_template, http_client
            )
            hallazgos.extend(hallazgos_url)

        return hallazgos

    def _probar_formulario(
        self, formulario: dict, payloads_template: list[str],
        http_client, target_url: str
    ) -> list[Hallazgo]:
        """Prueba payloads XSS contra un formulario específico."""
        hallazgos = []
        action = formulario.get("action", "")
        method = formulario.get("method", "GET").upper()
        inputs = formulario.get("inputs", [])

        tipos_inyectables = {"text", "search", "email", "url", "hidden"}
        campos = [
            inp for inp in inputs
            if inp.get("type", "text").lower() in tipos_inyectables
        ]

        if not campos:
            return hallazgos

        datos_base = {inp["name"]: inp.get("value", "test") for inp in inputs}
        url_form = action if action.startswith("http") else urljoin(target_url, action)

        for campo in campos:
            nombre_campo = campo["name"]

            for payload_template in payloads_template:
                canary = self._generar_canary()
                payload = payload_template.replace("{CANARY}", canary)

                datos = datos_base.copy()
                datos[nombre_campo] = payload

                if method == "POST":
                    response = http_client.post(url_form, data=datos)
                else:
                    response = http_client.get(url_form, params=datos)

                if response is None:
                    continue

                # Verificar si el canary aparece en la respuesta sin sanitizar
                if canary in response.text:
                    # Determinar severidad según contexto de reflexión
                    severidad, contexto = self._determinar_severidad(
                        payload, canary, response.text
                    )

                    hallazgo = Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=severidad,
                        confianza=Confianza.FIRME,
                        url_afectada=url_form,
                        parametro=nombre_campo,
                        metodo_http=method,
                        payload_usado=payload,
                        evidencia=(
                            f"Canary '{canary}' reflejado en respuesta {contexto}. "
                            f"HTTP {response.status_code}"
                        ),
                        cwe_id="CWE-79",
                        remediacion=(
                            "Sanitizar y encodear todo input del usuario antes de "
                            "renderizarlo en HTML. Usar funciones de escape apropiadas "
                            "para el contexto (HTML, atributo, JS, URL). "
                            "Implementar Content-Security-Policy (CSP)."
                        ),
                    )
                    hallazgos.append(hallazgo)

                    logger.warning(
                        f"  🟠 XSS detectado en {url_form} "
                        f"[campo: {nombre_campo}] [{contexto}]"
                    )
                    break  # Un hallazgo por campo

        return hallazgos

    def _probar_query_string(
        self, url: str, payloads_template: list[str], http_client
    ) -> list[Hallazgo]:
        """Prueba payloads XSS contra parámetros de query string."""
        hallazgos = []
        parsed = urlparse(url)
        params_originales = parse_qs(parsed.query, keep_blank_values=True)

        if not params_originales:
            return hallazgos

        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params_originales:
            for payload_template in payloads_template:
                canary = self._generar_canary()
                payload = payload_template.replace("{CANARY}", canary)

                params = {k: v[0] for k, v in params_originales.items()}
                params[param_name] = payload

                response = http_client.get(url_base, params=params)
                if response is None:
                    continue

                if canary in response.text:
                    severidad, contexto = self._determinar_severidad(
                        payload, canary, response.text
                    )

                    hallazgo = Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=severidad,
                        confianza=Confianza.FIRME,
                        url_afectada=url,
                        parametro=param_name,
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=(
                            f"Canary '{canary}' reflejado en query param {contexto}. "
                            f"HTTP {response.status_code}"
                        ),
                        cwe_id="CWE-79",
                        remediacion=(
                            "Encodear output HTML. Implementar CSP. "
                            "Validar y sanitizar parámetros de URL."
                        ),
                    )
                    hallazgos.append(hallazgo)

                    logger.warning(
                        f"  🟠 XSS detectado en {url_base} "
                        f"[param: {param_name}] [{contexto}]"
                    )
                    break

        return hallazgos

    def _determinar_severidad(
        self, payload: str, canary: str, respuesta: str
    ) -> tuple[Severidad, str]:
        """
        Determina la severidad del XSS según el contexto de reflexión.

        Returns:
            Tupla (severidad, descripción_contexto).
        """
        # Si el payload completo con tags <script> se refleja, es ALTA
        if f"<script>" in payload.lower() and payload in respuesta:
            return Severidad.ALTA, "en contexto HTML con script ejecutable"

        # Si se refleja dentro de un event handler (on*=), es ALTA
        if "onerror" in payload.lower() or "onload" in payload.lower():
            if payload in respuesta:
                return Severidad.ALTA, "en event handler HTML"

        # Si solo el canary se refleja (sin tags), es MEDIA
        if canary in respuesta and f"<{canary}>" not in respuesta:
            return Severidad.MEDIA, "texto reflejado sin sanitización"

        return Severidad.MEDIA, "reflexión detectada"

    def validar_hallazgo(self, hallazgo: Hallazgo, http_client, browser_helper = None) -> bool:
        """
        Validación de segundo paso con navegador Headless (Playwright).
        Si browser_helper está disponible, re-ejecuta el ataque dentro del navegador real,
        comprobando si ocurren alertas o excepciones de consola relacionadas.
        """
        # Si no hay helper de navegador, no descartamos (retorna True)
        if browser_helper is None:
            return True

        if not hallazgo.payload_usado:
            return True

        # Determinar si el payload pretendía ejecutar javascript
        inyecta_script = any(x in hallazgo.payload_usado.lower() for x in ["script", "alert", "console.log", "onerror", "onload"])
        if not inyecta_script:
            # Si solo era reflexión de texto plano, no se requiere confirmación por JS
            return True

        logger.info(f"Validando XSS dinámicamente con navegador headless en {hallazgo.url_afectada}...")

        # Mapear inputs para el navegador
        campos_inputs = {}
        if hallazgo.parametro and hallazgo.parametro != "body":
            campos_inputs[hallazgo.parametro] = hallazgo.payload_usado

        # Intentar interactuar con el formulario/URL en el navegador headless
        exito = browser_helper.interactuar_formulario(
            url=hallazgo.url_afectada,
            campos_input=campos_inputs,
            timeout_ms=4000
        )

        if not exito:
            # En caso de error de conexión en Playwright, mantenemos el hallazgo por seguridad
            return True

        # Analizar los logs de consola capturados para confirmar XSS
        for log in browser_helper.consola_logs:
            # Si se disparan errores de sintaxis inducidos por el payload, o canarios específicos
            if "sesamo_xss" in log["texto"] or "xss" in log["texto"].lower():
                logger.info(f"  ✓ XSS dinámico confirmado vía log de consola del navegador: {log['texto']}")
                hallazgo.confianza = Confianza.CONFIRMADA
                return True

        # También verificamos si hay excepciones JS generales lanzadas por el payload
        logs_error = [l for l in browser_helper.consola_logs if l["tipo"] in ["error", "warning"]]
        if logs_error:
            logger.info(f"  ✓ XSS dinámico sospechado por {len(logs_error)} logs de error/excepciones JS en navegador.")
            hallazgo.confianza = Confianza.CONFIRMADA
            return True

        # Si el navegador renderizó la página y no ejecutó ningún JS del payload ni dio errores
        logger.debug(f"  XSS dinámico descartado por falta de ejecución JS en navegador real para {hallazgo.url_afectada}")
        return False
