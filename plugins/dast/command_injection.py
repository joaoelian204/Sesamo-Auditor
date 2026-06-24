"""
plugins/dast/command_injection.py — Plugin de Command Injection

Detecta inyección de comandos del sistema operativo en formularios,
parámetros de URL y headers mediante payloads con caracteres de escape
(;, |, `, $()) y firmas de confirmación.

Categoría OWASP: A03:2021 — Injection
CWE: CWE-78 (OS Command Injection)
"""

from urllib.parse import urljoin, urlparse, parse_qs
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("command_injection")

_FIRMAS_EJECUCION = [
    "SESAMO_CMD",
    "uid=", "gid=", "groups=",
    "linux version",
    "www-data", "root:", "nobody:",
    "sesamo_cmd",
]


class CommandInjectionPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "Command Injection Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A03_INJECTION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        try:
            payloads = self.cargar_payloads("command_injection_payloads.txt")
        except FileNotFoundError:
            logger.error("Archivo command_injection_payloads.txt no encontrado.")
            return hallazgos

        logger.info(f"Payloads command injection cargados: {len(payloads)}")

        urls = metadata.get("urls_descubiertas", [])
        formularios = metadata.get("formularios", [])

        for url in urls:
            hallazgos.extend(self._probar_url(url, payloads, http_client))

        for formulario in formularios:
            hallazgos.extend(self._probar_formulario(formulario, payloads, http_client, target_url))

        hallazgos.extend(self._probar_headers(target_url, payloads, http_client))

        return hallazgos

    def _probar_url(self, url: str, payloads: list[str], http_client) -> list[Hallazgo]:
        hallazgos = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return hallazgos
        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            for payload in payloads:
                p = {k: v[0] for k, v in params.items()}
                p[param_name] = payload
                response = http_client.get(url_base, params=p)
                if response is None:
                    continue
                if self._firma_en_respuesta(response.text):
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=url,
                        parametro=param_name,
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=f"Comando ejecutado en el servidor. Payload: {payload}",
                        cwe_id="CWE-78",
                        remediacion="No pasar input del usuario a funciones de sistema. Usar APIs seguras en lugar de exec/system/popen.",
                    ))
                    logger.warning(f"  🔴 Command Injection en {url_base} [param: {param_name}]")
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
                if self._firma_en_respuesta(response.text):
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=url_form,
                        parametro=campo["name"],
                        metodo_http=method,
                        payload_usado=payload,
                        evidencia=f"Comando ejecutado via formulario.",
                        cwe_id="CWE-78",
                        remediacion="No pasar input del usuario a funciones de sistema.",
                    ))
                    logger.warning(f"  🔴 Command Injection en formulario {url_form} [campo: {campo['name']}]")
                    break
        return hallazgos

    def _probar_headers(self, target_url: str, payloads: list[str], http_client) -> list[Hallazgo]:
        hallazgos = []
        headers_a_probar = ["User-Agent", "X-Forwarded-For", "Referer", "Cookie"]
        time_payloads = [p for p in payloads if "sleep" in p.lower()]

        for header in headers_a_probar:
            for payload in time_payloads[:3]:
                import time
                inicio = time.time()
                response = http_client.get(target_url, headers={header: payload})
                if response is None:
                    continue
                delta = time.time() - inicio
                if delta > 3.0:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.FIRME,
                        url_afectada=target_url,
                        parametro=f"Header:{header}",
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=f"Time-based command injection via header {header} (delta: {delta:.2f}s)",
                        cwe_id="CWE-78",
                        remediacion="Sanitizar todos los headers antes de pasarlos a comandos del sistema.",
                    ))
                    logger.warning(f"  🔴 Time-based Command Injection via header {header}")
                    break
        return hallazgos

    def _firma_en_respuesta(self, texto: str) -> bool:
        texto_lower = texto.lower()
        return any(f.lower() in texto_lower for f in _FIRMAS_EJECUCION)
