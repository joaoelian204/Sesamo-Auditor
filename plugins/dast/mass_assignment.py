"""
plugins/dast/mass_assignment.py — Plugin de Mass Assignment

Detecta vulnerabilidades de asignación masiva añadiendo parámetros
extra a JSON bodies y formularios (admin=true, role=admin, etc.).

Categoría OWASP: A01:2021 — Broken Access Control
CWE: CWE-915 (Mass Assignment)
"""

import json
from urllib.parse import urljoin, urlparse
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("mass_assignment")

_PAYLOADS_CAMPOS = {
    "admin": [True, "true", 1, "1"],
    "role": ["admin", "administrator", "superadmin", "owner"],
    "isAdmin": [True, "true", 1],
    "is_admin": [True, "true", 1],
    "permissions": ["*", "all", "admin", "read_write"],
    "is_verified": [True, "true"],
    "is_active": [True, "true"],
    "is_premium": [True, "true", 1],
    "is_staff": [True, "true", 1],
    "is_superuser": [True, "true", 1],
    "access_level": [9999, "admin", "root"],
    "account_type": ["admin", "premium", "enterprise"],
    "group": ["admin", "administrators", "sudo"],
    "role_id": [1, 0, 999],
    "balance": [999999, -1, 0],
    "price": [0, -1, 0.01],
    "discount": [100, 999],
    "credit": [99999],
    "is_approved": [True, "true"],
    "email_verified": [True, "true"],
    "phone_verified": [True, "true"],
    "kyc_verified": [True, "true"],
    "twofa_enabled": [False, "false"],
    "mfa_enabled": [False, "false"],
}


class MassAssignmentPlugin(BasePlugin):

    @property
    def nombre(self) -> str:
        return "Mass Assignment Scanner"

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

        # 1. Probar formularios con campos extra
        for form in formularios:
            if form.get("method", "GET").upper() not in ("POST", "PUT", "PATCH"):
                continue
            action = form.get("action", "")
            url_form = action if action.startswith("http") else urljoin(target_url, action)
            inputs = form.get("inputs", [])
            datos_base = {i["name"]: i.get("value", "test") for i in inputs}

            for campo, valores in _PAYLOADS_CAMPOS.items():
                for valor in valores:
                    datos = datos_base.copy()
                    datos[campo] = valor
                    response = http_client.post(url_form, data=datos)
                    if response and response.status_code in (200, 201, 202, 204, 302):
                        if http_client.requiere_auth(response):
                            continue
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.ALTA,
                            confianza=Confianza.TENTATIVA,
                            url_afectada=url_form,
                            parametro=campo,
                            metodo_http="POST",
                            payload_usado=f"{campo}={valor}",
                            evidencia=f"Posible mass assignment — campo '{campo}={valor}' aceptado (HTTP {response.status_code})",
                            cwe_id="CWE-915",
                            remediacion="Usar DTOs/objetos de transferencia de datos explícitos. No pasar directamente request.body a modelos/entidades. Implementar whitelist de campos permitidos.",
                        ))
                        logger.warning(f"  🟠 Mass assignment: {url_form} aceptó campo extra '{campo}'")
                        break
                if hallazgos:
                    break

        # 2. Probar APIs REST con JSON bodies
        for ep in endpoints[:15]:
            parsed = urlparse(ep)
            if parsed.path.endswith((".js", ".css", ".js.map", ".html")):
                continue

            for campo, valores in _PAYLOADS_CAMPOS.items():
                for valor in valores:
                    body = {campo: valor}
                    response = http_client.post(ep, json=body, timeout=10)
                    if response and response.status_code in (200, 201, 202, 204):
                        if http_client.requiere_auth(response):
                            continue
                        hallazgos.append(Hallazgo(
                            plugin_nombre=self.nombre,
                            categoria_owasp=self.categoria_owasp,
                            severidad=Severidad.ALTA,
                            confianza=Confianza.TENTATIVA,
                            url_afectada=ep,
                            parametro="body",
                            metodo_http="POST",
                            payload_usado=json.dumps(body),
                            evidencia=f"Posible mass assignment en API — campo '{campo}' en JSON body aceptado (HTTP {response.status_code})",
                            cwe_id="CWE-915",
                            remediacion="Usar DTOs. Validar contra whitelist de campos permitidos.",
                        ))
                        logger.warning(f"  🟠 Mass assignment en API: {ep} aceptó '{{'{campo}': {valor}}}'")
                        break
                if hallazgos:
                    break

        # 3. Probar PUT/PATCH con campos extra en endpoints de usuario/perfil
        for ep in endpoints[:15]:
            if "user" in ep.lower() or "profile" in ep.lower() or "account" in ep.lower():
                for campo, valores in _PAYLOADS_CAMPOS.items():
                    for valor in valores:
                        body = {campo: valor}
                        response = http_client.put(ep, json=body, timeout=10)
                        if response and response.status_code in (200, 201, 202, 204):
                            hallazgos.append(Hallazgo(
                                plugin_nombre=self.nombre,
                                categoria_owasp=self.categoria_owasp,
                                severidad=Severidad.CRITICA,
                                confianza=Confianza.FIRME,
                                url_afectada=ep,
                                parametro="body",
                                metodo_http="PUT",
                                payload_usado=json.dumps(body),
                                evidencia=f"Mass assignment en endpoint de perfil — campo '{campo}' aceptado via PUT (HTTP {response.status_code})",
                                cwe_id="CWE-915",
                                remediacion="Nunca pasar campos sensibles como role/admin/permissions en peticiones de usuario.",
                            ))
                            logger.warning(f"  🔴 Mass assignment CRÍTICO en perfil: {ep}")
                            break
                    if hallazgos:
                        break

        return hallazgos

    def validar_hallazgo(self, hallazgo: Hallazgo, http_client) -> bool:
        """
        Validación activa de segundo paso para Mass Assignment:
        Realiza un GET al recurso afectado y verifica si la propiedad inyectada
        (por ejemplo, 'admin' o 'role') realmente se refleja persistida en la respuesta.
        """
        try:
            # Intentar obtener el recurso actual
            response = http_client.get(hallazgo.url_afectada, timeout=10)
            if response is None or response.status_code != 200:
                # Si no podemos hacer GET con 200 (ej: es un endpoint solo POST),
                # mantenemos el hallazgo con confianza TENTATIVA
                return True

            # Buscar la propiedad inyectada
            # Intentar parsear como JSON
            try:
                datos = response.json()
            except Exception:
                datos = response.text.lower()

            propiedad_a_buscar = None
            if hallazgo.payload_usado:
                try:
                    payload_json = json.loads(hallazgo.payload_usado)
                    propiedad_a_buscar = list(payload_json.keys())[0]
                except Exception:
                    if "=" in hallazgo.payload_usado:
                        propiedad_a_buscar = hallazgo.payload_usado.split("=")[0].strip()

            if not propiedad_a_buscar:
                return True

            # Verificar si la propiedad existe y no es el valor por defecto
            prop_lower = propiedad_a_buscar.lower()
            if isinstance(datos, dict):
                # Buscar en primer nivel o anidado simple
                claves_dict = {k.lower(): v for k, v in datos.items()}
                if prop_lower in claves_dict:
                    val = claves_dict[prop_lower]
                    if val in (True, "true", 1, "admin", "administrator"):
                        logger.info(f"  ✓ Mass Assignment confirmado: propiedad '{propiedad_a_buscar}' persistida en {hallazgo.url_afectada} (valor: {val})")
                        hallazgo.confianza = Confianza.CONFIRMADA
                        return True
            elif isinstance(datos, str):
                if f'"{propiedad_a_buscar}"' in datos or f"'{propiedad_a_buscar}'" in datos:
                    # Encontrar indicios de la clave en el texto de respuesta
                    logger.info(f"  ✓ Mass Assignment confirmado: clave '{propiedad_a_buscar}' encontrada en texto de {hallazgo.url_afectada}")
                    hallazgo.confianza = Confianza.CONFIRMADA
                    return True

            logger.debug(f"  Mass Assignment descartado: clave '{propiedad_a_buscar}' no guardada en el target")
            return False

        except Exception as e:
            logger.warning(f"Error validando Mass Assignment: {e}")
            return True
