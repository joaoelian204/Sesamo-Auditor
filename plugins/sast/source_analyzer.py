"""
plugins/sast/source_analyzer.py — Plugin de Análisis de Código Fuente Expuesto

Detecta archivos de código fuente, source maps, configuración, backups
y archivos de control de versiones expuestos en el servidor web.

Categoría OWASP: A05:2021 — Security Misconfiguration
CWE: CWE-540 (Inclusion of Sensitive Information in Source Code)
"""

from urllib.parse import urljoin

from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import (
    CategoriaOWASP,
    Confianza,
    Hallazgo,
    Severidad,
)

logger = get_logger("source_analyzer")


class SourceAnalyzerPlugin(BasePlugin):
    """
    Plugin que detecta código fuente, source maps, backups y archivos
    de configuración expuestos en el servidor.
    """

    @property
    def nombre(self) -> str:
        return "Source Code Exposure Analyzer"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A05_SECURITY_MISCONFIGURATION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.ALTA

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        """Ejecuta el análisis de exposición de código fuente."""
        hallazgos = []

        # ─── 1. Verificar source maps de archivos JS ───
        archivos_js = metadata.get("archivos_js", [])
        logger.info(f"Verificando source maps de {len(archivos_js)} archivos JS...")

        for js_url in archivos_js:
            map_url = f"{js_url}.map"
            response = http_client.get(map_url)

            if response and response.status_code == 200:
                # Verificar que es realmente un source map (contiene "mappings")
                if "mappings" in response.text or "sources" in response.text:
                    hallazgo = Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.ALTA,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=map_url,
                        parametro="",
                        metodo_http="GET",
                        payload_usado=".map",
                        evidencia=(
                            f"Source map accesible ({len(response.text)} bytes). "
                            f"Expone el código fuente original de la aplicación."
                        ),
                        cwe_id="CWE-540",
                        remediacion=(
                            "Eliminar archivos .map del servidor de producción. "
                            "Configurar el servidor web para bloquear acceso a *.map."
                        ),
                    )
                    hallazgos.append(hallazgo)
                    logger.warning(f"  🟠 Source map expuesto: {map_url}")

        # ─── 2. Verificar archivos de configuración y control de versiones ───
        archivos_sensibles = [
            (".git/config", Severidad.CRITICA, "CWE-538",
             "Repositorio Git expuesto — permite clonar código fuente completo"),
            (".git/HEAD", Severidad.CRITICA, "CWE-538",
             "Repositorio Git expuesto"),
            (".env", Severidad.CRITICA, "CWE-540",
             "Archivo .env con variables de entorno/secretos expuesto"),
            (".svn/entries", Severidad.ALTA, "CWE-538",
             "Repositorio SVN expuesto"),
            ("package.json.bak", Severidad.MEDIA, "CWE-530",
             "Backup de package.json expuesto"),
            ("docker-compose.yml", Severidad.ALTA, "CWE-540",
             "Docker Compose con configuración de infraestructura expuesto"),
            ("Dockerfile", Severidad.MEDIA, "CWE-540",
             "Dockerfile expuesto — revela stack tecnológico"),
            (".htaccess", Severidad.MEDIA, "CWE-540",
             "Archivo .htaccess con reglas del servidor expuesto"),
            ("web.config", Severidad.ALTA, "CWE-540",
             "Archivo web.config con configuración IIS expuesto"),
            ("wp-config.php.bak", Severidad.CRITICA, "CWE-530",
             "Backup de wp-config con credenciales de BD"),
        ]

        logger.info("Verificando archivos de configuración expuestos...")

        # Detectar si es SPA
        es_spa = False
        spa_text = ""
        for test_path in ["/xx_spa_test_1", "/xx_spa_test_2"]:
            test_url = urljoin(target_url, test_path)
            resp = http_client.get(test_url)
            if resp:
                if not spa_text:
                    spa_text = resp.text
                elif resp.text == spa_text:
                    es_spa = True
                else:
                    es_spa = False
                    break

        # Obtener baseline para detectar redirecciones catch-all
        baseline_len = 0
        baseline_resp = http_client.get(target_url)
        if baseline_resp:
            baseline_len = len(baseline_resp.content)

        inexistente_url = urljoin(target_url, "/recurso_inexistente_sesamo_sast_999")
        inexistente_resp = http_client.get(inexistente_url)
        inexistente_len = 0
        if inexistente_resp:
            inexistente_len = len(inexistente_resp.content)

        for archivo, severidad, cwe, descripcion in archivos_sensibles:
            url_test = urljoin(target_url, f"/{archivo}")
            response = http_client.get(url_test)

            if response and response.status_code == 200 and len(response.text) > 5:
                # Comprobar contra baselines de redirección catch-all
                longitud_actual = len(response.content)
                if longitud_actual == baseline_len or longitud_actual == inexistente_len:
                    continue
                if baseline_len > 0 and abs(longitud_actual - baseline_len) / baseline_len < 0.02:
                    continue
                # Si es SPA y coincide con index.html, ignorar
                if es_spa and response.text == spa_text:
                    continue

                # Verificar que no es una página de error 404 disfrazada
                if "<html" not in response.text[:200].lower() or archivo.endswith((".yml", ".yaml", ".json", ".env")):
                    hallazgo = Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=severidad,
                        confianza=Confianza.CONFIRMADA,
                        url_afectada=url_test,
                        parametro="",
                        metodo_http="GET",
                        payload_usado=archivo,
                        evidencia=f"{descripcion} ({len(response.text)} bytes)",
                        cwe_id=cwe,
                        remediacion=(
                            f"Eliminar '{archivo}' del servidor de producción "
                            f"o bloquear acceso en la configuración del servidor web."
                        ),
                    )
                    hallazgos.append(hallazgo)
                    logger.warning(f"  {severidad.icono} Archivo expuesto: {archivo}")

        # ─── 3. Verificar archivos de backup de URLs conocidas ───
        urls_descubiertas = metadata.get("urls_descubiertas", [])
        extensiones_backup = [".bak", ".old", ".orig", ".swp", "~", ".save", ".tmp"]

        logger.info("Verificando archivos de backup...")

        # Solo probar con una selección de URLs (las más interesantes)
        urls_interesantes = [
            u for u in urls_descubiertas
            if any(ext in u for ext in [".php", ".js", ".html", ".json", ".yml", ".xml", ".config"])
        ][:20]  # Limitar a 20 URLs

        for url in urls_interesantes:
            for ext in extensiones_backup:
                url_backup = url + ext
                response = http_client.get(url_backup)

                if response and response.status_code == 200 and len(response.text) > 10:
                    hallazgo = Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.MEDIA,
                        confianza=Confianza.FIRME,
                        url_afectada=url_backup,
                        parametro="",
                        metodo_http="GET",
                        payload_usado=ext,
                        evidencia=(
                            f"Archivo de backup accesible ({len(response.text)} bytes). "
                            f"Puede contener código fuente o configuración antigua."
                        ),
                        cwe_id="CWE-530",
                        remediacion=(
                            "Eliminar archivos de backup del servidor. "
                            "Configurar el servidor para bloquear acceso a "
                            "extensiones de backup (.bak, .old, .swp, ~)."
                        ),
                    )
                    hallazgos.append(hallazgo)
                    logger.warning(f"  🟡 Backup encontrado: {url_backup}")

        # ─── 4. Buscar comentarios reveladores en HTML ───
        logger.info("Buscando comentarios reveladores en HTML...")

        import re
        patron_comentario = re.compile(r"<!--(.*?)-->", re.DOTALL)
        palabras_clave = ["todo", "fixme", "hack", "bug", "password",
                          "secret", "key", "token", "credential", "debug"]

        for url in urls_descubiertas[:30]:
            response = http_client.get(url)
            if response is None or response.status_code != 200:
                continue

            comentarios = patron_comentario.findall(response.text)
            for comentario in comentarios:
                comentario_lower = comentario.lower().strip()
                if any(kw in comentario_lower for kw in palabras_clave):
                    # Truncar comentario largo
                    comentario_truncado = comentario.strip()[:100]
                    if len(comentario.strip()) > 100:
                        comentario_truncado += "..."

                    hallazgo = Hallazgo(
                        plugin_nombre=self.nombre,
                        categoria_owasp=self.categoria_owasp,
                        severidad=Severidad.BAJA,
                        confianza=Confianza.TENTATIVA,
                        url_afectada=url,
                        parametro="HTML comment",
                        metodo_http="GET",
                        payload_usado="",
                        evidencia=f"Comentario HTML revelador: <!-- {comentario_truncado} -->",
                        cwe_id="CWE-615",
                        remediacion=(
                            "Eliminar comentarios de desarrollo del código de producción. "
                            "Usar un proceso de build que elimine comentarios."
                        ),
                    )
                    hallazgos.append(hallazgo)

        return hallazgos
