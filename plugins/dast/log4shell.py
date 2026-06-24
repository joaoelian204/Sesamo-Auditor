"""
plugins/dast/log4shell.py — Plugin de Log4Shell (CVE-2021-44228)

Detecta la vulnerabilidad Log4Shell inyectando payloads JNDI en headers
HTTP comunes (User-Agent, X-Forwarded-For, Referer, Cookie) y verificando
si el servidor intenta resolver el callback (time-based detection como fallback
cuando no hay OOB callback server disponible).

Categoría OWASP: A06:2021 — Vulnerable and Outdated Components
CWE: CWE-502 (Deserialization of Untrusted Data)
"""

import re
import time
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("log4shell")

_CALLBACK_TOKEN = "SESAMO_CALLBACK"
_DELAY_THRESHOLD = 3.0


class Log4ShellPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "Log4Shell Scanner (CVE-2021-44228)"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A06_VULNERABLE_COMPONENTS

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        try:
            raw_payloads = self.cargar_payloads("log4shell_payloads.txt")
        except FileNotFoundError:
            logger.error("Archivo log4shell_payloads.txt no encontrado.")
            return hallazgos

        callback_host = f"sesamo-{int(time.time())}.burpcollaborator.net"
        payloads = [p.replace(_CALLBACK_TOKEN, callback_host) for p in raw_payloads]

        logger.info(f"Payloads Log4Shell cargados: {len(payloads)}")

        # Probar en headers comunes
        headers_a_probar = ["User-Agent", "X-Forwarded-For", "X-Api-Version",
                            "Referer", "Cookie", "X-Forwarded-Host",
                            "X-Client-IP", "X-Remote-IP", "X-Originating-IP",
                            "X-Remote-Addr", "X-Real-IP", "X-Request-ID"]

        total = len(payloads) * len(headers_a_probar)
        tested = 0

        for payload in payloads:
            for header in headers_a_probar:
                tested += 1
                inicio = time.time()
                response = http_client.get(target_url, headers={header: payload})
                if response is None:
                    continue
                delta = time.time() - inicio

                if delta > _DELAY_THRESHOLD:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.FIRME,
                        url_afectada=target_url,
                        parametro=f"Header:{header}",
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=f"Log4Shell detectado — respuesta tardó {delta:.2f}s (payload JNDI en header {header})",
                        cwe_id="CWE-502",
                        remediacion="Actualizar Log4j a versión 2.17.0+ o parchar con -Dlog4j2.formatMsgNoLookups=true. Aplicar parches de seguridad del proveedor.",
                    ))
                    logger.warning(f"  🔴 Log4Shell detectado via {header} (delta: {delta:.2f}s)")
                    break

                # Buscar reflejo del callback en respuesta (parcial)
                if callback_host[:20] in response.text:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=target_url,
                        parametro=f"Header:{header}",
                        metodo_http="GET",
                        payload_usado=payload,
                        evidencia=f"Log4Shell confirmado — callback hostname reflejado en respuesta",
                        cwe_id="CWE-502",
                        remediacion="Actualizar Log4j inmediatamente.",
                    ))
                    logger.warning(f"  🔴 Log4Shell confirmado — callback reflejado en respuesta")
                    break

            if hallazgos:
                break

        if not hallazgos:
            logger.info(f"Log4Shell: no se detectaron indicaciones ({tested} combinaciones probadas)")

        return hallazgos
