"""
plugins/dast/open_redirect.py — Plugin de Open Redirect

Detecta vulnerabilidades de open redirect en parámetros de URL que
controlan destinos de redirección (?url=, ?next=, ?redirect=, etc.).

Categoría OWASP: A01:2021 — Broken Access Control
CWE: CWE-601 (URL Redirection to Untrusted Site)
"""

from urllib.parse import urljoin, urlparse, parse_qs
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("open_redirect")


class OpenRedirectPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "Open Redirect Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.MEDIA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        try:
            payloads = self.cargar_payloads("open_redirect_payloads.txt")
        except FileNotFoundError:
            logger.error("Archivo open_redirect_payloads.txt no encontrado.")
            return hallazgos

        logger.info(f"Payloads open redirect cargados: {len(payloads)}")

        params_redir = {"url", "next", "redirect", "return", "to", "dest",
                        "redir", "domain", "callback", "file", "load",
                        "read", "view", "goto", "page", "link", "target"}

        urls = metadata.get("urls_descubiertas", [])
        dominios_externos = set()

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            dominio_objetivo = urlparse(target_url).netloc

            for param_name in params:
                if param_name.lower() in params_redir:
                    for payload in payloads:
                        response = http_client.get(
                            url_base,
                            params={param_name: payload},
                            allow_redirects=False,
                        )
                        if response is None:
                            continue

                        location = response.headers.get("Location", "")
                        if not location:
                            continue

                        if "evil.com" in location.lower() or "evil" in location.lower():
                            hallazgos.append(Hallazgo(
                                plugin_nombre=self.nombre,
                                categoria_owasp=self.categoria_owasp,
                                severidad=Severidad.MEDIA,
                                confianza=Confianza.CONFIRMADA,
                                url_afectada=url,
                                parametro=param_name,
                                metodo_http="GET",
                                payload_usado=payload,
                                evidencia=f"Open redirect detectado — Location: {location[:100]}",
                                cwe_id="CWE-601",
                                remediacion="No redirigir basándose en input del usuario. Usar una whitelist de dominios permitidos o un mapping de IDs a URLs.",
                            ))
                            logger.warning(f"  🟡 Open redirect en {url_base} [param: {param_name}] → {location[:60]}")
                            break

                        dominio_redirect = urlparse(location).netloc
                        if dominio_redirect and dominio_redirect != dominio_objetivo and dominio_objetivo not in location:
                            dominios_externos.add((url_base, param_name, payload, location))

        for url_base, param, payload, location in dominios_externos:
            hallazgos.append(Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.BAJA,
                confianza=Confianza.TENTATIVA,
                url_afectada=url_base,
                parametro=param,
                metodo_http="GET",
                payload_usado=payload,
                evidencia=f"Posible open redirect — Location: {location[:100]}",
                cwe_id="CWE-601",
                remediacion="Validar que todos los redirects apunten a dominios controlados.",
            ))

        return hallazgos
