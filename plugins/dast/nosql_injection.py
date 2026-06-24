"""
plugins/dast/nosql_injection.py — Plugin de NoSQL Injection

Detecta inyección NoSQL en MongoDB mediante payloads con operadores
$ne, $gt, $regex, $where en parámetros de URL y forms.

Categoría OWASP: A03:2021 — Injection
CWE: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
"""

import json
from urllib.parse import urljoin, urlparse, parse_qs
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("nosql_injection")


class NoSQLInjectionPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "NoSQL Injection Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A03_INJECTION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        try:
            payloads = self.cargar_payloads("nosql_payloads.txt")
        except FileNotFoundError:
            logger.error("Archivo nosql_payloads.txt no encontrado.")
            return hallazgos

        logger.info(f"Payloads NoSQL cargados: {len(payloads)}")

        urls = metadata.get("urls_descubiertas", [])
        formularios = metadata.get("formularios", [])
        endpoints = metadata.get("endpoints_api", [])

        todas_urls = set(urls) | set(endpoints)

        for url in todas_urls:
            hallazgos.extend(self._probar_url(url, payloads, http_client))

        for formulario in formularios:
            hallazgos.extend(self._probar_formulario(formulario, payloads, http_client, target_url))

        hallazgos.extend(self._probar_json_api(list(endpoints)[:10], payloads, http_client))

        return hallazgos

    def _probar_url(self, url: str, payloads: list[str], http_client) -> list[Hallazgo]:
        hallazgos = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return hallazgos
        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            baseline = http_client.get(url_base, params={param_name: "test123"})
            if baseline is None or http_client.requiere_auth(baseline):
                continue
            baseline_len = len(baseline.content)
            baseline_status = baseline.status_code

            for payload in payloads:
                if "[" in payload or "{" in payload:
                    continue
                key, val = payload.split("=", 1) if "=" in payload else (payload, "1")
                p = {k: v[0] for k, v in params.items()}
                # Handle $ operators
                if param_name in p:
                    del p[param_name]
                p[f"{param_name}[{key}]"] = val

                response = http_client.get(url_base, params=p)
                if response is None:
                    continue
                if response.status_code == baseline_status and abs(len(response.content) - baseline_len) > 30:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.ALTA,
                        confianza=Confianza.FIRME,
                        url_afectada=url,
                        parametro=f"{param_name}[{key}]",
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=f"Posible NoSQL injection — respuesta cambió de {baseline_len} a {len(response.content)} bytes (status {response.status_code})",
                        cwe_id="CWE-943",
                        remediacion="Validar y sanitizar inputs. No pasar operadores $ directamente a queries de MongoDB. Usar ORM/ODM con validación de esquemas.",
                    ))
                    logger.warning(f"  🟠 NoSQL injection potencial en {url_base} [param: {param_name}[{key}]]")
                    break
        return hallazgos

    def _probar_formulario(self, formulario: dict, payloads: list[str], http_client, target_url: str) -> list[Hallazgo]:
        hallazgos = []
        action = formulario.get("action", "")
        method = formulario.get("method", "GET").upper()
        inputs = formulario.get("inputs", [])
        campos = [i for i in inputs if i.get("type", "text") in ("text", "email", "password", "url", "hidden")]
        if not campos:
            return hallazgos
        url_form = action if action.startswith("http") else urljoin(target_url, action)

        for campo in campos:
            baseline = http_client.post(url_form, data={campo["name"]: "test123"}) if method == "POST" else http_client.get(url_form, params={campo["name"]: "test123"})
            if baseline is None:
                continue
            baseline_len = len(baseline.content)
            baseline_status = baseline.status_code

            for payload in payloads:
                if "[" not in payload and "{" not in payload and "=" in payload:
                    key, val = payload.split("=", 1)
                    if method == "POST":
                        response = http_client.post(url_form, data={f"{campo['name']}[{key}]": val})
                    else:
                        response = http_client.get(url_form, params={f"{campo['name']}[{key}]": val})
                    if response is None:
                        continue
                    if http_client.requiere_auth(response):
                        continue
                    if response.status_code == baseline_status and abs(len(response.content) - baseline_len) > 30:
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.ALTA,
                            confianza=Confianza.FIRME,
                            url_afectada=url_form,
                            parametro=f"{campo['name']}[{key}]",
                            metodo_http=method,
                            payload_usado=payload,
                            evidencia=f"NoSQL injection via formulario — respuesta cambió de tamaño",
                            cwe_id="CWE-943",
                            remediacion="Validar inputs de formulario contra operadores NoSQL.",
                        ))
                        logger.warning(f"  🟠 NoSQL injection en formulario {url_form}")
                        break
        return hallazgos

    def _probar_json_api(self, endpoints: list[str], payloads: list[str], http_client) -> list[Hallazgo]:
        hallazgos = []
        json_payloads = [p for p in payloads if "{" in p or "$ne" in p or "$gt" in p]

        for endpoint in endpoints:
            # Saltar endpoints que requieren auth
            test_resp = http_client.get(endpoint)
            if test_resp and http_client.requiere_auth(test_resp):
                continue
            for payload_str in json_payloads:
                try:
                    payload = json.loads(payload_str)
                except json.JSONDecodeError:
                    continue
                response = http_client.post(endpoint, json=payload)
                if response is None:
                    continue
                if response.status_code in (200, 201, 403, 500):
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.ALTA,
                        confianza=Confianza.TENTATIVA,
                        url_afectada=endpoint,
                        parametro="body",
                        metodo_http="POST",
                        payload_usado=payload_str,
                        evidencia=f"NoSQL injection via JSON body — HTTP {response.status_code}",
                        cwe_id="CWE-943",
                        remediacion="Validar y sanear JSON bodies contra operadores NoSQL.",
                    ))
                    logger.warning(f"  🟠 NoSQL injection en API {endpoint}")
                    break
        return hallazgos

    def validar_hallazgo(self, hallazgo: Hallazgo, http_client) -> bool:
        """
        Validación activa diferencial para NoSQL Injection:
        1. Envía un JSON plano con valor inexistente (ej: {"username": "sesamo_non_existent"}). Debería fallar/dar vacío.
        2. Envía el payload NoSQL inyectado (ej: {"username": {"$ne": "sesamo_non_existent"}}). Debería dar éxito/registros.
        3. Si hay comportamiento diferencial en respuestas, confirmamos vulnerabilidad.
        """
        if not hallazgo.payload_usado or hallazgo.metodo_http != "POST":
            return True

        try:
            # Parsear el payload original
            try:
                original_body = json.loads(hallazgo.payload_usado)
            except Exception:
                return True

            # Si no es un diccionario/JSON estructurado con operadores NoSQL en los valores, saltar validación diferencial
            if not isinstance(original_body, dict):
                return True

            # Encontrar el campo que tiene el operador NoSQL
            campo_inyectado = None
            for k, v in original_body.items():
                if isinstance(v, dict) and any(key.startswith("$") for key in v.keys()):
                    campo_inyectado = k
                    break

            if not campo_inyectado:
                return True

            # 1. Petición A: Valor plano inexistente (debe devolver vacío/error/404)
            body_plano = original_body.copy()
            body_plano[campo_inyectado] = "sesamo_non_existent_fake_val"
            
            resp_plana = http_client.post(hallazgo.url_afectada, json=body_plano, timeout=10)
            
            # 2. Petición B: Operador NoSQL (debe devolver éxito/registros)
            body_nosql = original_body.copy()
            body_nosql[campo_inyectado] = {"$ne": "sesamo_non_existent_fake_val"}
            
            resp_nosql = http_client.post(hallazgo.url_afectada, json=body_nosql, timeout=10)

            if resp_plana is None or resp_nosql is None:
                return True

            # Comparación diferencial
            # Si el endpoint es vulnerable a NoSQL, el operador $ne devolverá datos exitosos (ej: registros o token de admin),
            # mientras que el valor plano 'sesamo_non_existent_fake_val' no debería devolver nada o dar error 404/401.
            # Si ambos dan exactamente el mismo código de estado (ej: ambos 500 o ambos 400), no es NoSQL Injection real.
            if resp_nosql.status_code in (200, 201) and resp_plana.status_code not in (200, 201):
                logger.info(f"  ✓ NoSQL confirmada diferencialmente en {hallazgo.url_afectada} [campo: {campo_inyectado}]")
                hallazgo.confianza = Confianza.CONFIRMADA
                return True
                
            # Si la respuesta de NoSQL es exitosa y devuelve datos, pero el plano devuelve vacío/mensaje diferente
            if resp_nosql.status_code == resp_plana.status_code == 200:
                if len(resp_nosql.content) != len(resp_plana.content):
                    logger.info(f"  ✓ NoSQL confirmada diferencialmente (tamaño de contenido) en {hallazgo.url_afectada}")
                    hallazgo.confianza = Confianza.CONFIRMADA
                    return True

            logger.debug(f"  NoSQL descartada por validación diferencial en {hallazgo.url_afectada}")
            return False

        except Exception as e:
            logger.warning(f"Error en validación diferencial de NoSQL: {e}")
            return True

