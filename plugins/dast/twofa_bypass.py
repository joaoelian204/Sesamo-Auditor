"""
plugins/dast/twofa_bypass.py — Plugin de 2FA Bypass Detection

Analiza la configuración de doble factor de autenticación buscando
endpoints que omitan 2FA, tokens predecibles, y falta de verificación
en APIs.

Categoría OWASP: A07:2021 — Identification and Authentication Failures
CWE: CWE-308 (Use of Single-factor Authentication)
"""

import re
import time
from urllib.parse import urljoin, urlparse
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("twofa_bypass")

_INDICADORES_2FA = [
    "two-factor", "two factor", "2fa", "2-fa", "mfa", "multi-factor",
    "authenticator", "otp", "one-time", "one time", "totp", "hotp",
    "verification code", "security code", "2-step", "two step",
    "google authenticator", "authy", "duo security",
]

_RUTAS_2FA = [
    "/2fa", "/2fa/verify", "/2fa/setup", "/mfa", "/mfa/verify",
    "/totp", "/totp/verify", "/otp", "/otp/verify",
    "/auth/2fa", "/auth/mfa", "/api/2fa", "/api/mfa",
    "/verification", "/verify-2fa", "/two-factor",
    "/login/2fa", "/login/mfa",
]

_ENDPOINTS_SIN_2FA = [
    "/api/login", "/api/auth", "/api/token", "/api/authenticate",
    "/login", "/auth/login", "/signin", "/api/signin",
    "/oauth/token", "/api/oauth/token",
]


class TwoFABypassPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "2FA Bypass Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A07_AUTH_FAILURES

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        urls = metadata.get("urls_descubiertas", [])
        endpoints = list(metadata.get("endpoints_api", []))
        todas = set(urls) | set(endpoints)

        # 1. Detectar si hay 2FA implementado
        tiene_2fa = False
        for url in todas:
            path = urlparse(url).path.lower()
            if any(r in path for r in _RUTAS_2FA):
                tiene_2fa = True
                break
            response = http_client.get(url, timeout=10)
            if response:
                texto = response.text.lower()
                if any(ind in texto for ind in _INDICADORES_2FA):
                    tiene_2fa = True
                    break

        if not tiene_2fa:
            logger.info("No se detectó 2FA en la aplicación.")
            return hallazgos

        logger.info("2FA detectado. Verificando posibles bypasses...")

        dominio_base = urlparse(target_url).netloc

        # 2. Verificar si endpoints de login directo funcionan sin 2FA
        for ep in _ENDPOINTS_SIN_2FA:
            url_test = urljoin(target_url, ep)
            if url_test not in todas:
                response = http_client.post(url_test, json={"username": "test", "password": "test"}, timeout=10)
                if response and response.status_code in (200, 201):
                    # Solo consideramos bypass si la respuesta parece indicar éxito (contiene tokens o info de sesión)
                    texto_lower = response.text.lower()
                    indicadores_login = ["token", "session", "jwt", "bearer", "success", "authenticated"]
                    if any(ind in texto_lower for ind in indicadores_login):
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.ALTA,
                            confianza=Confianza.TENTATIVA,
                            url_afectada=url_test,
                            parametro="endpoint",
                            metodo_http="POST",
                            payload_usado='{"username":"test","password":"test"}',
                            evidencia=f"Endpoint de autenticación sin 2FA responde HTTP {response.status_code} con datos de sesión — bypass de 2FA",
                            cwe_id="CWE-308",
                            remediacion="Asegurar que 2FA es requerido en TODOS los endpoints de autenticación. Verificar que no haya endpoints legacy sin 2FA.",
                        ))
                        logger.warning(f"  🟠 Endpoint sin 2FA (Bypass exitoso): {url_test} (HTTP {response.status_code})")

        # 3. Probar OTP predecible / débil
        for url in todas:
            path = urlparse(url).path.lower()
            if "verify" in path or "validate" in path or "confirm" in path:
                for otp in ["000000", "123456", "111111", "999999", "123123", "000001"]:
                    response = http_client.post(url, json={"code": otp, "token": otp, "otp": otp}, timeout=10)
                    if response and response.status_code not in (401, 403, 404, 405, 400):
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.CRITICA,
                            confianza=Confianza.CONFIRMADA,
                            url_afectada=url,
                            parametro="otp",
                            metodo_http="POST",
                            payload_usado=otp,
                            evidencia=f"OTP débil '{otp}' aceptado en endpoint de verificación (HTTP {response.status_code})",
                            cwe_id="CWE-330",
                            remediacion="Usar OTPs aleatorios de 6+ dígitos con rate-limiting. Implementar bloqueo tras intentos fallidos.",
                        ))
                        logger.warning(f"  🔴 OTP débil aceptado: {otp} en {url}")
                        break

        # 4. Detectar si hay rate-limiting en 2FA
        if hallazgos:
            return hallazgos

        for url in todas:
            path = urlparse(url).path.lower()
            if "verify" in path or "validate" in path or "confirm" in path:
                intentos_rapidos = 0
                for _ in range(10):
                    response = http_client.post(url, json={"code": "999999"}, timeout=10)
                    if response and response.status_code != 429:
                        intentos_rapidos += 1
                    time.sleep(0.05)
                if intentos_rapidos >= 8:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.MEDIA,
                        confianza=Confianza.FIRME,
                        url_afectada=url,
                        parametro="rate-limit",
                        metodo_http="POST",
                        payload_usado="10 intentos rápidos sin bloqueo",
                        evidencia=f"Endpoint 2FA sin rate-limiting — {intentos_rapidos}/10 intentos aceptados sin HTTP 429",
                        cwe_id="CWE-307",
                        remediacion="Implementar rate-limiting en endpoints de verificación 2FA. Bloquear tras 3-5 intentos fallidos.",
                    ))
                    logger.warning(f"  🟠 Sin rate-limiting en 2FA: {url}")
                break

        return hallazgos
