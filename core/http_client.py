"""
core/http_client.py — Cliente HTTP Unificado de Sésamo Auditor

Proporciona un cliente HTTP centralizado construido sobre requests.Session
con las siguientes características:
- Sesiones persistentes (cookies compartidas entre requests)
- Rate-limiting configurable (delay entre requests)
- Retry con backoff exponencial (3 reintentos: 1s → 2s → 4s)
- Timeout global configurable
- Headers por defecto (User-Agent personalizado)
- Soporte de proxy (para enrutar a ZAP/Burp)
- Logging integrado de cada request/response

Uso:
    from core.http_client import HttpClient

    client = HttpClient(config={
        "timeout_segundos": 10,
        "rate_limit_delay": 0.5,
        "user_agent": "SesamoAuditor/1.0",
    })

    response = client.get("https://target.com/api/users")
    response = client.post("https://target.com/login", data={"user": "admin"})
"""

import time
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.logger import get_logger

logger = get_logger("http_client")

_CONFIG_DEFECTO = {
    "timeout_segundos": 10,
    "rate_limit_delay": 0.5,
    "max_reintentos": 3,
    "user_agent": "SesamoAuditor/1.0",
    "proxy": None,
}

_FIRMAS_AUTH = [
    "unauthorized", "forbidden", "access denied",
    "authorization header", "no token", "invalid token",
    "not authenticated", "authentication required",
    "login required", "permission denied",
    "401", "403",
]


class HttpClient:
    """
    Cliente HTTP unificado con sesiones, rate-limiting y retry.

    Este cliente es compartido por todos los plugins via inyección de
    dependencias. Ningún plugin debe crear su propia sesión HTTP.

    Attributes:
        timeout: Timeout en segundos para cada request.
        rate_limit_delay: Segundos de espera entre requests.
        session: Instancia de requests.Session con retry configurado.
    """

    def __init__(self, config: dict | None = None):
        """
        Inicializa el cliente HTTP con la configuración proporcionada.

        Args:
            config: Diccionario de configuración. Claves opcionales:
                - timeout_segundos (int): Timeout por request (default: 10)
                - rate_limit_delay (float): Delay entre requests (default: 0.5)
                - max_reintentos (int): Número de reintentos (default: 3)
                - user_agent (str): User-Agent header (default: "SesamoAuditor/1.0")
                - proxy (str|None): URL del proxy (ej: "http://127.0.0.1:8080")
        """
        self._config = {**_CONFIG_DEFECTO, **(config or {})}
        self.timeout: int = self._config["timeout_segundos"]
        self.rate_limit_delay: float = self._config["rate_limit_delay"]
        self._ultimo_request: float = 0.0
        self._errores_consecutivos: int = 0
        self._circuit_breaker_limite: int = 5
        self._circuit_abierto: bool = False
        self.target_url: str = self._config.get("target_url", "")
        self.target_domain: str = ""
        if self.target_url:
            from urllib.parse import urlparse
            self.target_domain = urlparse(self.target_url).netloc

        # Crear sesión con retry strategy
        self.session = requests.Session()
        self._configurar_retry()
        self._configurar_headers()
        self._configurar_proxy()

        logger.info(
            f"HttpClient inicializado | "
            f"timeout={self.timeout}s | "
            f"rate_limit={self.rate_limit_delay}s | "
            f"proxy={self._config['proxy'] or 'ninguno'}"
        )

    def _configurar_retry(self) -> None:
        """Configura la estrategia de retry con backoff exponencial."""
        max_reintentos = self._config["max_reintentos"]

        retry_strategy = Retry(
            total=max_reintentos,
            backoff_factor=1,  # 1s, 2s, 4s
            status_forcelist=[429, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
            raise_on_status=False,
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        logger.debug(f"Retry configurado: {max_reintentos} reintentos con backoff exponencial")

    def _configurar_headers(self) -> None:
        """Configura los headers por defecto de la sesión."""
        self.session.headers.update({
            "User-Agent": self._config["user_agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

    def _configurar_proxy(self) -> None:
        """Configura el proxy si está definido en la configuración."""
        proxy_url = self._config["proxy"]
        if proxy_url:
            self.session.proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }
            # Desactivar verificación SSL cuando se usa proxy (ZAP/Burp)
            self.session.verify = False
            logger.info(f"Proxy configurado: {proxy_url}")

    def _aplicar_rate_limit(self) -> None:
        """
        Aplica el rate-limit entre requests consecutivos.
        Espera el tiempo restante si la última request fue muy reciente.
        """
        if self.rate_limit_delay <= 0:
            return

        ahora = time.time()
        tiempo_transcurrido = ahora - self._ultimo_request
        tiempo_espera = self.rate_limit_delay - tiempo_transcurrido

        if tiempo_espera > 0:
            logger.debug(f"Rate-limit: esperando {tiempo_espera:.2f}s")
            time.sleep(tiempo_espera)

        self._ultimo_request = time.time()

    def request(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data: Any = None,
        json: Any = None,
        headers: dict | None = None,
        cookies: dict | None = None,
        allow_redirects: bool = True,
        timeout: int | None = None,
    ) -> requests.Response | None:
        """
        Realiza una petición HTTP genérica con rate-limiting y logging.

        Este es el método base que todos los métodos de conveniencia
        (get, post, put, delete) llaman internamente.

        Args:
            method: Método HTTP ("GET", "POST", "PUT", "DELETE", etc.)
            url: URL completa del endpoint.
            params: Query parameters para la URL.
            data: Body de la petición (form-encoded).
            json: Body de la petición (JSON).
            headers: Headers adicionales (se mezclan con los base).
            cookies: Cookies adicionales para esta petición.
            allow_redirects: Si seguir redirects automáticamente.
            timeout: Timeout específico para esta petición (sobreescribe el global).

        Returns:
            requests.Response si la petición fue exitosa,
            None si hubo un error de conexión irrecuperable.
        """
        # ── Filtro de dominio: bloquear peticiones fuera del scope ──
        if self.target_domain:
            from urllib.parse import urlparse
            dominio_request = urlparse(url).netloc
            if dominio_request and dominio_request != self.target_domain:
                logger.debug(
                    f"⛔ Bloqueada petición fuera de scope: {dominio_request} "
                    f"(scope: {self.target_domain})"
                )
                return None

        # ── Circuit breaker: si el target está caído, abortar rápido ──
        if self._circuit_abierto:
            logger.debug(f"⛔ Circuit breaker abierto — omitiendo {url}")
            return None

        # ── Anti-CSRF token automatic regeneration hook ──
        if method in ("POST", "PUT", "DELETE"):
            self._regenerar_csrf_token(url, params, data, json, headers)

        self._aplicar_rate_limit()

        request_timeout = timeout or self.timeout

        logger.debug(f"{method} {url}")
        if params:
            logger.debug(f"  Params: {params}")
        if data:
            logger.debug(f"  Data: {data}")

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                cookies=cookies,
                allow_redirects=allow_redirects,
                timeout=request_timeout,
            )

            logger.debug(
                f"  → {response.status_code} | "
                f"{len(response.content)} bytes | "
                f"{response.elapsed.total_seconds():.2f}s"
            )

            # Conexión exitosa: resetear contador de errores
            self._errores_consecutivos = 0
            return response

        except requests.exceptions.ConnectionError as e:
            self._errores_consecutivos += 1
            if self._errores_consecutivos >= self._circuit_breaker_limite:
                self._circuit_abierto = True
                logger.error(
                    f"🔴 Circuit breaker activado tras {self._errores_consecutivos} "
                    f"errores consecutivos. Target parece estar caído. "
                    f"Abortando peticiones restantes."
                )
            else:
                logger.error(f"Error de conexión a {url}: {e}")
            return None

        except requests.exceptions.Timeout:
            logger.error(f"Timeout ({request_timeout}s) al conectar a {url}")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Error en request {method} {url}: {e}")
            return None

    def get(self, url: str, **kwargs) -> requests.Response | None:
        """Realiza una petición GET."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response | None:
        """Realiza una petición POST."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response | None:
        """Realiza una petición PUT."""
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response | None:
        """Realiza una petición DELETE."""
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response | None:
        """Realiza una petición HEAD (solo headers, sin body)."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response | None:
        """Realiza una petición OPTIONS."""
        return self.request("OPTIONS", url, **kwargs)

    def obtener_cookies(self) -> dict:
        """Retorna todas las cookies actuales de la sesión como diccionario."""
        return dict(self.session.cookies)

    def limpiar_cookies(self) -> None:
        """Limpia todas las cookies de la sesión."""
        self.session.cookies.clear()
        logger.debug("Cookies de sesión limpiadas")

    def cerrar(self) -> None:
        """Cierra la sesión HTTP y libera recursos."""
        self.session.close()
        logger.debug("Sesión HTTP cerrada")

    @staticmethod
    def requiere_auth(response) -> bool:
        """Verifica si una respuesta indica que el endpoint requiere autenticación."""
        if response is None:
            return False
        if response.status_code in (401, 403):
            return True
        texto = response.text[:500].lower()
        return any(f in texto for f in _FIRMAS_AUTH)

    def __enter__(self):
        """Soporte para context manager (with HttpClient() as client: ...)."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cierra la sesión al salir del context manager."""
        self.cerrar()
        return False

    def _regenerar_csrf_token(self, url: str, params: dict | None, data: Any, json_body: Any, headers: dict | None) -> None:
        """
        Busca un token CSRF en los parámetros o cabeceras y, de encontrarlo, realiza
        una petición GET al target para obtener un token nuevo y lo reemplaza.
        """
        patrones_csrf = ["csrf", "xsrf", "token", "anticsrf"]
        csrf_clave = None
        donde = None

        # 1. Buscar en headers
        if headers:
            for k in headers:
                if any(p in k.lower() for p in patrones_csrf):
                    csrf_clave = k
                    donde = "header"
                    break

        # 2. Buscar en params
        if not csrf_clave and params:
            for k in params:
                if any(p in k.lower() for p in patrones_csrf):
                    csrf_clave = k
                    donde = "param"
                    break

        # 3. Buscar en form data
        if not csrf_clave and isinstance(data, dict):
            for k in data:
                if any(p in k.lower() for p in patrones_csrf):
                    csrf_clave = k
                    donde = "data"
                    break

        if not csrf_clave:
            return

        # Regeneración: Hacer GET a la página principal para refrescar cookies/tokens
        try:
            logger.debug(f"Refrescando token anti-CSRF para clave: {csrf_clave} ({donde})")
            # Desactivar temporalmente la regeneración en este GET para evitar loops infinitos
            original_headers = self.session.headers.copy()
            resp = self.session.get(self.target_url or url, timeout=self.timeout)
            if resp:
                import re
                # Buscar token en html (patrón simple: input hidden con name/value)
                match = re.search(r'name=["\']' + re.escape(csrf_clave) + r'["\']\s+value=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                if not match:
                    # Alternativo: value antes que name
                    match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']' + re.escape(csrf_clave) + r'["\']', resp.text, re.IGNORECASE)
                
                nuevo_val = None
                if match:
                    nuevo_val = match.group(1)
                else:
                    # Buscar en cookies
                    for cookie in self.session.cookies:
                        if any(p in cookie.name.lower() for p in patrones_csrf):
                            nuevo_val = cookie.value
                            break

                if nuevo_val:
                    logger.debug(f"Nuevo token CSRF obtenido: {nuevo_val[:15]}...")
                    if donde == "header" and headers:
                        headers[csrf_clave] = nuevo_val
                    elif donde == "param" and params:
                        params[csrf_clave] = nuevo_val
                    elif donde == "data" and isinstance(data, dict):
                        data[csrf_clave] = nuevo_val
        except Exception as e:
            logger.warning(f"Error regenerando token anti-CSRF: {e}")

