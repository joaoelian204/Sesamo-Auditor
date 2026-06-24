"""
plugins/dast/nuclei_scanner.py — Plugin de escaneo con Nuclei

Ejecuta Nuclei (ProjectDiscovery) como scanner externo, parsea su
output JSON y traduce los findings al modelo Hallazgo de Sésamo.

Requiere: nuclei instalado en el PATH (https://github.com/projectdiscovery/nuclei)
"""

import json
import subprocess
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad

logger = get_logger("nuclei_scanner")

_SEVERIDAD_MAP = {
    "info": Severidad.INFO,
    "low": Severidad.BAJA,
    "medium": Severidad.MEDIA,
    "high": Severidad.ALTA,
    "critical": Severidad.CRITICA,
}

_CATEGORIA_MAP = {
    "cve": CategoriaOWASP.A06_VULNERABLE_COMPONENTS,
    "cwe": CategoriaOWASP.A06_VULNERABLE_COMPONENTS,
    "misconfiguration": CategoriaOWASP.A05_SECURITY_MISCONFIGURATION,
    "exposure": CategoriaOWASP.A05_SECURITY_MISCONFIGURATION,
    "injection": CategoriaOWASP.A03_INJECTION,
    "xss": CategoriaOWASP.A03_INJECTION,
    "ssrf": CategoriaOWASP.A10_SSRF,
    "lfi": CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL,
    "rfi": CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL,
    "auth": CategoriaOWASP.A07_AUTH_FAILURES,
    "default-login": CategoriaOWASP.A07_AUTH_FAILURES,
    "debug": CategoriaOWASP.A05_SECURITY_MISCONFIGURATION,
}


class NucleiScannerPlugin(BasePlugin):
    """
    Plugin que delega el escaneo de vulnerabilidades a Nuclei.

    Ejecuta `nuclei -u target -json` via subprocess, captura el output
    NDJSON y traduce cada finding al modelo Hallazgo.
    """

    @property
    def nombre(self) -> str:
        return "Nuclei Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A06_VULNERABLE_COMPONENTS

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def _mapear_categoria(self, finding: dict) -> CategoriaOWASP:
        tags = [t.lower() for t in finding.get("info", {}).get("tags", [])]
        for tag, cat in _CATEGORIA_MAP.items():
            if any(tag in t for t in tags):
                return cat
        name = finding.get("info", {}).get("name", "").lower()
        for keyword, cat in [("xss", CategoriaOWASP.A03_INJECTION),
                              ("sql", CategoriaOWASP.A03_INJECTION),
                              ("ssrf", CategoriaOWASP.A10_SSRF),
                              ("lfi", CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL),
                              ("exposure", CategoriaOWASP.A05_SECURITY_MISCONFIGURATION)]:
            if keyword in name:
                return cat
        return CategoriaOWASP.A05_SECURITY_MISCONFIGURATION

    def _extraer_cwe(self, finding: dict) -> str:
        cwe_list = finding.get("info", {}).get("classification", {}).get("cwe-id", [])
        if cwe_list:
            cwe_raw = cwe_list[0] if isinstance(cwe_list, list) else cwe_list
            cwe_str = str(cwe_raw).strip()
            if not cwe_str.startswith("CWE-"):
                cwe_str = f"CWE-{cwe_str}"
            return cwe_str
        return "CWE-200"

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        hallazgos = []

        try:
            subprocess.run(["nuclei", "-version"],
                           capture_output=True, check=True, timeout=10)
        except (FileNotFoundError, subprocess.CalledProcessError, PermissionError):
            logger.warning("nuclei no está instalado en el PATH. Omitiendo NucleiScanner.")
            logger.warning("Instálalo desde: https://github.com/projectdiscovery/nuclei")
            return hallazgos

        logger.info("Ejecutando Nuclei scan...")

        try:
            proc = subprocess.run(
                ["nuclei", "-u", target_url, "-json", "-silent"],
                capture_output=True, text=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Nuclei excedió el tiempo máximo (600s). Omitiendo.")
            return hallazgos
        except Exception as e:
            logger.error(f"Error ejecutando Nuclei: {e}")
            return hallazgos

        lineas = [l for l in proc.stdout.strip().split("\n") if l.strip()]
        logger.info(f"Nuclei completado: {len(lineas)} findings crudos")

        if not lineas:
            return hallazgos

        # Filtrar solo findings de severidad BAJA+ (omitir INFO)
        for linea in lineas:
            try:
                finding = json.loads(linea)
            except json.JSONDecodeError:
                continue

            info = finding.get("info", {})
            severity_str = info.get("severity", "info").lower()
            severidad = _SEVERIDAD_MAP.get(severity_str, Severidad.INFO)

            if severidad == Severidad.INFO:
                continue

            template = info.get("name", "Desconocido")
            url = finding.get("matched-at", finding.get("host", target_url))
            extracted = finding.get("extracted-results", "")
            desc = info.get("description", "")

            hallazgo = Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self._mapear_categoria(finding),
                severidad=severidad,
                confianza=Confianza.FIRME,
                url_afectada=url,
                parametro=finding.get("matched-line", ""),
                metodo_http=finding.get("type", "GET").upper(),
                payload_usado="",
                evidencia=f"[{template}] {desc}" + (f" | Extraído: {extracted[:200]}" if extracted else ""),
                cwe_id=self._extraer_cwe(finding),
                remediacion=info.get("remediation", "Revisar la plantilla de Nuclei para más detalles."),
            )
            hallazgos.append(hallazgo)

        logger.info(f"Nuclei: {len(hallazgos)} hallazgos relevantes reportados")
        return hallazgos
