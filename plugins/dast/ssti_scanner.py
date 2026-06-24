"""
plugins/dast/ssti_scanner.py — Plugin de Server-Side Template Injection

Detecta SSTI en múltiples motores de templates (Jinja2, Twig, Freemarker,
Velocity, Jade/Pug, Smarty, ERB, Tornado, Handlebars, etc.) mediante
inyección de payloads matemáticos y de RCE.

Categoría OWASP: A03:2021 — Injection
CWE: CWE-1336 (Server-Side Template Injection)
"""

from urllib.parse import urljoin, urlparse, parse_qs
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("ssti_scanner")

_FIRMAS_EVALUACION = {
    "49": "Template evaluation (7*7=49)",
    "7'7": "Template evaluation (7*'7'=7777777)",
    "SESAMO_SSTI": "Template RCE (os.popen)",
    "SI": "Template conditional",
    "__mro__": "Template object introspection",
    "__class__": "Template object introspection",
    "__globals__": "Template globals access",
    "smarty": "Smarty template engine",
    "constructor": "JS template constructor",
}


class SSTIScannerPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "SSTI Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A03_INJECTION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        try:
            payloads = self.cargar_payloads("ssti_payloads.txt")
        except FileNotFoundError:
            logger.error("Archivo ssti_payloads.txt no encontrado.")
            return hallazgos

        logger.info(f"Payloads SSTI cargados: {len(payloads)}")

        urls = metadata.get("urls_descubiertas", [])
        formularios = metadata.get("formularios", [])

        for url in urls:
            hallazgos.extend(self._probar_url(url, payloads, http_client))

        for formulario in formularios:
            hallazgos.extend(self._probar_formulario(formulario, payloads, http_client, target_url))

        return hallazgos

    def _probar_url(self, url: str, payloads: list[str], http_client) -> list[Hallazgo]:
        hallazgos = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return hallazgos
        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        baseline_len = 0
        baseline_resp = http_client.get(url_base, params={k: v[0] for k, v in params.items()})
        if baseline_resp:
            baseline_len = len(baseline_resp.content)

        for param_name in params:
            for payload in payloads:
                p = {k: v[0] for k, v in params.items()}
                p[param_name] = payload
                response = http_client.get(url_base, params=p)
                if response is None:
                    continue

                match = self._analizar_respuesta(payload, response.text)
                if match and len(response.content) != baseline_len:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.FIRME,
                        url_afectada=url,
                        parametro=param_name,
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=f"SSTI detectada: {match}",
                        cwe_id="CWE-1336",
                        remediacion="No renderizar input del usuario en templates del lado del servidor. Usar sandboxing o motores sin acceso a objetos peligrosos.",
                    ))
                    logger.warning(f"  🔴 SSTI en {url_base} [param: {param_name}]")
                    break
        return hallazgos

    def _probar_formulario(self, formulario: dict, payloads: list[str], http_client, target_url: str) -> list[Hallazgo]:
        hallazgos = []
        action = formulario.get("action", "")
        method = formulario.get("method", "GET").upper()
        inputs = formulario.get("inputs", [])
        campos = [i for i in inputs if i.get("type", "text") in ("text", "search", "email", "url", "hidden")]
        if not campos:
            return hallazgos
        url_form = action if action.startswith("http") else urljoin(target_url, action)
        datos_base = {i["name"]: i.get("value", "test") for i in inputs}

        for campo in campos:
            for payload in payloads:
                datos = datos_base.copy()
                datos[campo["name"]] = payload
                response = http_client.post(url_form, data=datos) if method == "POST" else http_client.get(url_form, params=datos)
                if response is None:
                    continue
                match = self._analizar_respuesta(payload, response.text)
                if match:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.FIRME,
                        url_afectada=url_form,
                        parametro=campo["name"],
                        metodo_http=method,
                        payload_usado=payload,
                        evidencia=f"SSTI detectada en formulario: {match}",
                        cwe_id="CWE-1336",
                        remediacion="No renderizar input del usuario en templates.",
                    ))
                    logger.warning(f"  🔴 SSTI en formulario {url_form} [campo: {campo['name']}]")
                    break
        return hallazgos

    def _analizar_respuesta(self, payload: str, texto: str) -> str | None:
        texto_lower = texto.lower()
        for firma, desc in _FIRMAS_EVALUACION.items():
            if firma.lower() in texto_lower:
                return desc
        return None
