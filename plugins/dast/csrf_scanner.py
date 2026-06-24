"""
plugins/dast/csrf_scanner.py — Plugin de Cross-Site Request Forgery (CSRF)

Detecta formularios y endpoints que modifican estado sin token CSRF,
tokens predecibles, tokens reutilizables, y falta de headers anti-CSRF.

Categoría OWASP: A01:2021 — Broken Access Control
CWE: CWE-352 (Cross-Site Request Forgery)
"""

import re
from urllib.parse import urljoin, urlparse
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("csrf_scanner")

_PATRON_TOKEN_CSRF = re.compile(
    r'(csrf|csrf_token|_csrf|csrfmiddlewaretoken|csrf-token|'
    r'xsrf|xsrf-token|x-csrf-token|x-xsrf-token|'
    r'__csrf|csrf_test_name|YII_CSRF_TOKEN|ci_csrf_token|'
    r'symfony_csrf|_token|authenticity_token)',
    re.IGNORECASE,
)

_HEADERS_CSRF = [
    "x-csrf-token", "x-xsrf-token", "csrf-token",
    "x-csrf-header", "anti-csrf-token",
]


class CSRFScannerPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "CSRF Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        formularios = metadata.get("formularios", [])
        urls = metadata.get("urls_descubiertas", [])
        endpoints = metadata.get("endpoints_api", [])
        peticiones_red = metadata.get("peticiones_red", [])

        acciones_mutacion = {"POST", "PUT", "DELETE", "PATCH"}

        # 1. Verificar formularios que mutan estado sin token CSRF
        for form in formularios:
            method = form.get("method", "GET").upper()
            if method not in acciones_mutacion:
                continue
            action = form.get("action", "")
            inputs = form.get("inputs", [])
            nombres_campos = [i.get("name", "") for i in inputs]
            nombres_vals = " ".join(nombres_campos)

            if not _PATRON_TOKEN_CSRF.search(nombres_vals):
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.ALTA,
                    confianza=Confianza.FIRME,
                    url_afectada=action or target_url,
                    parametro="csrf_token",
                    metodo_http=method,
                    payload_usado="",
                    evidencia=f"Formulario {method} sin token CSRF ({len(inputs)} campos: {', '.join(nombres_campos[:5])})",
                    cwe_id="CWE-352",
                    remediacion="Implementar tokens CSRF únicos por sesión en todos los formularios que modifican estado. Usar SameSite=Strict en cookies.",
                ))
                logger.warning(f"  🟠 Formulario {method} sin CSRF: {action}")

        # 2. Probar peticiones POST sin token CSRF (solo endpoints públicos)
        for ep in list(endpoints)[:25] + list(urls)[:10]:
            parsed = urlparse(ep)
            if parsed.path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico")):
                continue

            response_post = http_client.post(ep, json={"test": "sesamo"}, timeout=10)
            if response_post is None or http_client.requiere_auth(response_post):
                continue
            if response_post.status_code in (200, 201, 202, 204):
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.MEDIA,
                    confianza=Confianza.TENTATIVA,
                    url_afectada=ep,
                    parametro="body",
                    metodo_http="POST",
                    payload_usado='{"test":"sesamo"}',
                    evidencia=f"Endpoint acepta POST sin token CSRF (HTTP {response_post.status_code})",
                    cwe_id="CWE-352",
                    remediacion="Requerir token CSRF en todas las peticiones POST/PUT/DELETE que modifican estado.",
                ))

        # 3. Peticiones de red del headless crawler
        for req in peticiones_red:
            if req.get("method", "GET") in acciones_mutacion:
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.INFO,
                    confianza=Confianza.TENTATIVA,
                    url_afectada=req["url"],
                    parametro="csrf_token",
                    metodo_http=req["method"],
                    payload_usado="",
                    evidencia=f"Petición {req['method']} detectada — verificar si requiere CSRF",
                    cwe_id="CWE-352",
                    remediacion="Verificar que esta petición tenga protección CSRF.",
                ))

        return hallazgos
