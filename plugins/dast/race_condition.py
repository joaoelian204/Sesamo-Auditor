"""
plugins/dast/race_condition.py — Plugin de Race Condition / TOCTOU

Detecta condiciones de carrera enviando múltiples peticiones concurrentes
a endpoints que modifican estado (cupones, votaciones, transferencias)
y analizando si más de una es aceptada.

Categoría OWASP: A01:2021 — Broken Access Control
CWE: CWE-362 (Concurrent Execution using Shared Resource)
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("race_condition")


class RaceConditionPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "Race Condition Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []
        formularios = metadata.get("formularios", [])
        endpoints = list(metadata.get("endpoints_api", []))

        # Endpoints de interés para race condition
        acciones_mutacion = {"POST", "PUT", "DELETE", "PATCH"}
        endpoints_a_probar = []

        for form in formularios:
            if form.get("method", "GET").upper() in acciones_mutacion:
                action = form.get("action", "")
                url_form = action if action.startswith("http") else urljoin(target_url, action)
                inputs = form.get("inputs", [])
                data = {i["name"]: i.get("value", "test") for i in inputs} if inputs else {"test": "sesamo"}
                endpoints_a_probar.append((url_form, "POST", data))

        for ep in endpoints[:10]:
            if any(kw in ep.lower() for kw in ("coupon", "voucher", "discount", "redeem",
                                                 "vote", "rating", "review", "comment",
                                                 "transfer", "payment", "checkout",
                                                 "order", "purchase", "buy", "claim",
                                                 "like", "favorite", "follow", "unfollow",
                                                 "apply", "submit", "register", "signup")):
                endpoints_a_probar.append((ep, "POST", {"test": "sesamo"}))

        if not endpoints_a_probar:
            logger.info("No se encontraron endpoints candidatos para race condition.")
            return hallazgos

        logger.info(f"Probando {len(endpoints_a_probar)} endpoints para race condition...")

        for url, method, data in endpoints_a_probar[:10]:
            resultados = []
            num_peticiones = 15

            def enviar():
                try:
                    if method == "POST":
                        resp = http_client.post(url, data=data, timeout=10)
                    elif method == "PUT":
                        resp = http_client.put(url, json=data, timeout=10)
                    else:
                        resp = http_client.delete(url, timeout=10)
                    return (resp.status_code if resp else None, len(resp.content) if resp else 0)
                except Exception:
                    return (None, 0)

            with ThreadPoolExecutor(max_workers=num_peticiones) as pool:
                futuros = [pool.submit(enviar) for _ in range(num_peticiones)]
                for f in as_completed(futuros):
                    try:
                        resultados.append(f.result())
                    except Exception:
                        continue

            exitosos = [r for r in resultados if r[0] in (200, 201, 202, 204)]
            if len(exitosos) >= 2:
                hallazgos.append(Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=Severidad.ALTA,
                    confianza=Confianza.TENTATIVA,
                    url_afectada=url,
                    parametro=method,
                    metodo_http=method,
                    payload_usado=str(data)[:80],
                    evidencia=f"Posible race condition — {len(exitosos)}/{num_peticiones} peticiones concurrentes exitosas (HTTP {set(r[0] for r in exitosos)})",
                    cwe_id="CWE-362",
                    remediacion="Implementar locks pesimistas o transacciones atómicas. Usar colas para operaciones críticas. Validar estado antes de modificar recursos compartidos.",
                ))
                logger.warning(f"  🟠 Race condition potencial: {url} ({len(exitosos)}/{num_peticiones} exitosas)")

        return hallazgos
