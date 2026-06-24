"""
plugins/dast/idor_scanner.py — Plugin de Insecure Direct Object References (IDOR)

Detecta IDOR probando acceso a recursos de otros usuarios mediante
manipulación de IDs numéricos secuenciales, GUIDs, y referencias
a objetos en URLs y APIs.

Categoría OWASP: A01:2021 — Broken Access Control
CWE: CWE-639 (Insecure Direct Object Reference)
"""

import re
from urllib.parse import urlparse, parse_qs
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("idor_scanner")

_PATRON_ID = re.compile(r'(\d{3,8})$')
_PARAMS_IDOR = {"id", "user", "userId", "customer", "account", "order",
                "basket", "cart", "profile", "uid", "pid", "cid", "sid",
                "token", "ref", "invoice", "transaction", "payment",
                "document", "file_id", "attachment", "msg_id", "ticket"}


class IDORScannerPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "IDOR Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        urls = metadata.get("urls_descubiertas", [])
        endpoints = list(metadata.get("endpoints_api", []))
        todas = list(set(urls) | set(endpoints))

        for url in todas:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Extraer IDs de la ruta misma (ej: /api/users/123)
            match_path = _PATRON_ID.search(parsed.path.rstrip("/"))
            if match_path:
                id_original = match_path.group(1)
                id_int = int(id_original)

                for nuevo_id in [id_int + 1, id_int - 1, id_int + 100, 1, 999999]:
                    if nuevo_id == id_int or nuevo_id <= 0:
                        continue
                    nueva_ruta = parsed.path.replace(f"/{id_original}", f"/{nuevo_id}", 1)
                    nueva_url = f"{parsed.scheme}://{parsed.netloc}{nueva_ruta}"

                    response = http_client.get(nueva_url)
                    if response and response.status_code == 200 and len(response.text) > 10:
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.ALTA,
                            confianza=Confianza.TENTATIVA,
                            url_afectada=nueva_url,
                            parametro="path:id",
                            metodo_http="GET",
                            payload_usado=str(nuevo_id),
                            evidencia=f"Posible IDOR — acceso a ID {nuevo_id} (original: {id_original}) HTTP {response.status_code} ({len(response.text)} bytes)",
                            cwe_id="CWE-639",
                            remediacion="Implementar autorización por usuario en todos los endpoints. Usar UUIDs no secuenciales. Verificar propiedad del recurso en backend.",
                        ))
                        logger.warning(f"  🟠 Posible IDOR: {nueva_url} (ID {nuevo_id} vs original {id_original})")
                        break

            # Extraer IDs de parámetros de query
            for param_name in params:
                if param_name.lower() not in _PARAMS_IDOR:
                    continue
                valor_actual = params[param_name][0]
                match_param = _PATRON_ID.match(valor_actual)
                if not match_param:
                    continue
                id_original = match_param.group(1)
                id_int = int(id_original)

                for nuevo_id in [id_int + 1, id_int - 1, id_int + 100, 1, 999999]:
                    if nuevo_id == id_int or nuevo_id <= 0:
                        continue
                    p = {k: v[0] for k, v in params.items()}
                    p[param_name] = str(nuevo_id)
                    response = http_client.get(url_base, params=p)
                    if response and response.status_code == 200 and len(response.text) > 10:
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.ALTA,
                            confianza=Confianza.TENTATIVA,
                            url_afectada=url_base,
                            parametro=param_name,
                            metodo_http="GET",
                            payload_usado=str(nuevo_id),
                            evidencia=f"Posible IDOR — {param_name}={nuevo_id} (original: {id_original}) HTTP {response.status_code} ({len(response.text)} bytes)",
                            cwe_id="CWE-639",
                            remediacion="Implementar autorización. Usar UUIDs. Verificar propiedad.",
                        ))
                        logger.warning(f"  🟠 Posible IDOR: {url_base}?{param_name}={nuevo_id}")
                        break

        return hallazgos
