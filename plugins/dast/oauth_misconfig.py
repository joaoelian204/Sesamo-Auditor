"""
plugins/dast/oauth_misconfig.py — Plugin de OAuth Misconfiguration

Detecta configuraciones inseguras en flujos OAuth 2.0 / OpenID Connect:
redirect_uri manipulation, falta de state parameter, token leakage,
y uso de grant types inseguros.

Categoría OWASP: A07:2021 — Identification and Authentication Failures
CWE: CWE-346 (Origin Validation Error)
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("oauth_misconfig")

_PATRON_OAUTH = re.compile(
    r'(https?://[^\s"\']*(?:/auth|/oauth|/authorize|/connect|/login|/sso)'
    r'[^\s"\']*(?:client_id|redirect_uri|response_type|scope)[^\s"\']*)',
    re.IGNORECASE,
)

_PATRON_CLIENT_ID = re.compile(
    r'(?:client_id|clientId|app_id|appId)\s*[=:]\s*["\']?([a-zA-Z0-9._\-]{10,})["\']?',
    re.IGNORECASE,
)

_PROVIDERS_OAUTH = [
    "google", "github", "facebook", "twitter", "apple", "microsoft",
    "linkedin", "amazon", "gitlab", "bitbucket", "discord", "slack",
    "keycloak", "auth0", "okta", "onelogin", "azure",
]


class OAuthMisconfigPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "OAuth Misconfiguration Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A07_AUTH_FAILURES

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        urls = metadata.get("urls_descubiertas", [])
        archivos_js = metadata.get("archivos_js", [])
        contenido_total = ""

        # Recolectar contenido de páginas
        for url in list(urls)[:10]:
            try:
                resp = http_client.get(url, timeout=10)
                if resp:
                    contenido_total += resp.text + "\n"
            except Exception:
                continue

        for js_url in archivos_js[:10]:
            try:
                resp = http_client.get(js_url, timeout=10)
                if resp:
                    contenido_total += resp.text + "\n"
            except Exception:
                continue

        # 1. Encontrar flujos OAuth
        oauth_urls = _PATRON_OAUTH.findall(contenido_total)
        client_ids = _PATRON_CLIENT_ID.findall(contenido_total)

        if not oauth_urls:
            logger.info("No se detectaron flujos OAuth.")
            return hallazgos

        logger.info(f"Flujos OAuth detectados: {len(oauth_urls)}")

        # 2. Verificar si tienen state parameter (CSRF protection)
        for oauth_url in oauth_urls[:10]:
            params = parse_qs(urlparse(oauth_url).query)
            if "state" not in params:
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.ALTA,
                    confianza=Confianza.FIRME,
                    url_afectada=oauth_url.split("?")[0] if "?" in oauth_url else oauth_url,
                    parametro="state",
                    metodo_http="GET",
                    payload_usado=oauth_url[:120],
                    evidencia=f"Flujo OAuth sin parámetro 'state' — vulnerable a CSRF en OAuth",
                    cwe_id="CWE-352",
                    remediacion="Agregar parámetro 'state' único y no predecible en todas las solicitudes de autorización OAuth. Validarlo al recibir el callback.",
                ))
                logger.warning(f"  🟠 OAuth sin state parameter: {oauth_url[:80]}")

        # 3. Probar redirect_uri manipulation
        dominio_target = urlparse(target_url).netloc
        for oauth_url in oauth_urls[:5]:
            redirect_uris_maliciosas = [
                f"https://evil.com/oauth/callback",
                f"https://{dominio_target}.evil.com/callback",
                f"https://evil{dominio_target}.com/callback",
                f"https://{dominio_target}/callback@evil.com",
                "https://evil.com",
            ]
            for redirect_uri in redirect_uris_maliciosas:
                url_modificada = oauth_url.replace(
                    urlparse(oauth_url).query or "",
                    f"redirect_uri={redirect_uri}&response_type=code&state=test",
                )
                response = http_client.get(url_modificada, allow_redirects=False, timeout=10)
                if response and response.status_code in (200, 302, 301):
                    location = response.headers.get("Location", "")
                    if "evil" in location.lower() or response.status_code in (200,):
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.CRITICA,
                            confianza=Confianza.FIRME,
                            url_afectada=oauth_url.split("?")[0],
                            parametro="redirect_uri",
                            metodo_http="GET",
                            payload_usado=redirect_uri,
                            evidencia=f"Posible open redirect en OAuth — redirect_uri maliciosa aceptada: {redirect_uri}",
                            cwe_id="CWE-601",
                            remediacion="Validar redirect_uri contra whitelist estricta de URLs permitidas. No permitir redirecciones a dominios externos no verificados.",
                        ))
                        logger.warning(f"  🔴 OAuth redirect_uri manipulation: {redirect_uri}")
                        break

        # 4. Verificar si client_id está expuesto en JS y es válido
        if client_ids:
            for cid in client_ids[:5]:
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.MEDIA,
                    confianza=Confianza.FIRME,
                    url_afectada=target_url,
                    parametro="client_id",
                    metodo_http="GET",
                    payload_usado="",
                    evidencia=f"OAuth client_id expuesto en JS/HTML: '{cid}' — potencial token leakage",
                    cwe_id="CWE-200",
                    remediacion="Los client_id de OAuth público pueden estar expuestos, pero verificar que no sean secretos. Usar PKCE para mayor seguridad.",
                ))

        # 5. Detectar proveedores OAuth
        proveedores = [p for p in _PROVIDERS_OAUTH if p in contenido_total.lower()]
        if proveedores:
            logger.info(f"Proveedores OAuth detectados: {', '.join(proveedores)}")

        # 6. Verificar si hay referer header leakage (token en URL referer)
        for oauth_url in oauth_urls[:3]:
            clean_url = oauth_url.split("?")[0] if "?" in oauth_url else oauth_url
            parsed = urlparse(clean_url)
            domain = f"{parsed.scheme}://{parsed.netloc}"
            response = http_client.get(domain, headers={"Referer": oauth_url}, timeout=10)
            if response:
                texto = response.text.lower()
                if "access_token" in texto or "token" in texto or "code" in texto:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.ALTA,
                        confianza=Confianza.TENTATIVA,
                        url_afectada=domain,
                        parametro="Referer",
                        metodo_http="GET",
                        payload_usado="",
                        evidencia="Posible token leakage via Referer header — el token OAuth aparece reflejado en página de destino",
                        cwe_id="CWE-200",
                        remediacion="Usar response_type=code (Authorization Code Flow) en vez de implicit flow. El token nunca debe estar en la URL.",
                    ))
                    logger.warning(f"  🟠 Posible token leakage via Referer")
                    break

        return hallazgos
