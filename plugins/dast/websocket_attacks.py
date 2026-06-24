"""
plugins/dast/websocket_attacks.py — Plugin de Ataques WebSocket

Detecta endpoints WebSocket en la aplicación, se conecta y envía
payloads de inyección (SQLi, XSS, Command Injection) a través del
canal WebSocket, analizando las respuestas en busca de firmas.

Categoría OWASP: A03:2021 — Injection
CWE: CWE-138 (Improper Sanitization of Special Elements)
"""

import json
import re
import time
from urllib.parse import urlparse, urljoin
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("websocket_attacks")

_PATRON_WS = re.compile(r'(wss?://[a-zA-Z0-9._/\-?:&=]+)', re.IGNORECASE)

_PAYLOADS_WS = {
    "SQLi": ["' OR 1=1 --", "' UNION SELECT 1 --", "${7*7}"],
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "Command Injection": ["; id", "| id", "$(id)"],
    "NoSQL": ['{"$ne": "1"}', '{"$gt": ""}'],
    "SSTI": ["{{7*7}}", "${7*7}"],
}

_FIRMAS_INYECCION = {
    "sql error": "SQL",
    "mysql_fetch": "SQL",
    "sqlite": "SQL",
    "postgresql": "SQL",
    "alert(1)": "XSS",
    "stack trace": "Command",
    "uid=": "Command",
    "root:": "Command",
    "49": "SSTI (7*7)",
}


class WebSocketAttacksPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "WebSocket Attacks Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A03_INJECTION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []

        urls_descubiertas = metadata.get("urls_descubiertas", [])
        archivos_js = metadata.get("archivos_js", [])
        paginas_analizar = list(urls_descubiertas)[:10] + archivos_js[:10]

        ws_endpoints = set()

        for url in paginas_analizar:
            try:
                response = http_client.get(url, timeout=10)
                if response:
                    encontrados = _PATRON_WS.findall(response.text)
                    ws_endpoints.update(encontrados)
            except Exception:
                continue

        ws_endpoints = {w for w in ws_endpoints if w.startswith(("ws://", "wss://"))}

        if not ws_endpoints:
            urls_abs = set()
            for url in urls_descubiertas:
                parsed = urlparse(url)
                ws_base = f"ws://{parsed.netloc}" if parsed.scheme == "http" else f"wss://{parsed.netloc}"
                urls_abs.add(ws_base)
            ws_endpoints.update(urls_abs)

        if not ws_endpoints:
            logger.info("No se encontraron endpoints WebSocket.")
            return hallazgos

        logger.info(f"Endpoints WebSocket encontrados: {len(ws_endpoints)}")

        for ws_url in list(ws_endpoints)[:5]:
            hallazgos.extend(self._probar_websocket(ws_url, target_url))

        return hallazgos

    def _probar_websocket(self, ws_url: str, target_url: str) -> list[Hallazgo]:
        hallazgos = []

        try:
            import websocket
        except ImportError:
            logger.warning("websocket-client no instalado. Usa: pip install websocket-client")
            logger.info(f"  Endpoint WebSocket encontrado (no probado): {ws_url}")
            return []

        for tipo, payloads in _PAYLOADS_WS.items():
            for payload in payloads:
                try:
                    ws = websocket.create_connection(ws_url, timeout=5)
                    ws.send(payload)
                    time.sleep(0.5)
                    respuesta = ws.recv()
                    ws.close()
                except Exception:
                    continue

                evidencia = self._analizar_respuesta_ws(respuesta, tipo)
                if evidencia:
                    hallazgos.append(Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.CRITICA,
                        confianza=Confianza.FIRME,
                        url_afectada=ws_url,
                        parametro=tipo,
                        metodo_http="WEBSOCKET",
                        payload_usado=payload[:80],
                        evidencia=f"Inyección {tipo} via WebSocket: {evidencia}",
                        cwe_id="CWE-138",
                        remediacion="Sanitizar todo input recibido por WebSocket. Implementar validación server-side igual que para HTTP.",
                    ))
                    logger.warning(f"  🔴 Inyección {tipo} via WebSocket en {ws_url}")
                    break

        return hallazgos

    def _analizar_respuesta_ws(self, respuesta: str, tipo: str) -> str | None:
        texto = respuesta.lower() if isinstance(respuesta, str) else str(respuesta).lower()
        for firma, categoria in _FIRMAS_INYECCION.items():
            if firma in texto:
                return f"Firma '{firma}' en respuesta ({categoria})"
        if "49" in texto and tipo in ("SSTI",):
            return "Evaluación de template detectada"
        return None
