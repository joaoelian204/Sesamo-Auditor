"""
core/engine.py — Motor de Ejecución de Sésamo Auditor

Orquestador central del framework que ejecuta el pipeline de auditoría
en 4 fases:
1. Crawling — Descubre la superficie de ataque
2. Ejecución — Carga y ejecuta plugins dinámicamente
3. Validación — Segundo paso para eliminar falsos positivos
4. Reportes — Genera el reporte en el formato elegido

Uso:
    from core.engine import AuditEngine

    engine = AuditEngine(config)
    resultado = engine.iniciar_auditoria("https://target.com")
"""

import importlib
import importlib.util
import inspect
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from core.crawler import Crawler, MetadataCrawl
from core.http_client import HttpClient
from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import ResultadoEscaneo, Severidad
from core.scanner import Scanner

logger = get_logger("engine")


class AuditEngine:
    """
    Motor principal de auditoría de Sésamo Auditor.

    Orquesta el pipeline completo de escaneo: carga dinámica de plugins,
    crawling de superficie, ejecución de pruebas, validación de hallazgos
    y generación de reportes.

    Attributes:
        config: Configuración global del escaneo.
        http_client: Cliente HTTP compartido por todos los plugins.
        crawler: Instancia del crawler de superficie.
        scanner: Instancia del motor de escaneo de plugins.
        plugins: Lista de plugins cargados dinámicamente.
        resultado: Resultado del escaneo con todos los hallazgos validados.
    """

    def __init__(self, config: dict):
        """
        Inicializa el motor de auditoría con la configuración global.

        Args:
            config: Diccionario de configuración global (desde config.json).
                    Debe contener las claves: target, crawler, http_client,
                    reportes, plugins.
        """
        self.config = config
        http_config = {**config.get("http_client", {})}
        # Inyectar target_url para que HttpClient pueda filtrar dominios externos
        target_url_config = config.get("target", {}).get("url", "")
        if target_url_config:
            http_config["target_url"] = target_url_config
        self.http_client = HttpClient(http_config)
        self.crawler = Crawler(self.http_client, config.get("crawler", {}))
        self.scanner = Scanner(self.config, self.http_client)
        self.plugins: list[BasePlugin] = []
        self.resultado: Optional[ResultadoEscaneo] = None

    def cargar_plugins(
        self,
        solo_dast: bool = False,
        solo_sast: bool = False,
        excluir: list[str] | None = None,
    ) -> list[BasePlugin]:
        """
        Carga dinámicamente todos los plugins desde el directorio plugins/.

        Escanea los subdirectorios plugins/dast/ y plugins/sast/ buscando
        archivos .py que contengan clases que hereden de BasePlugin.
        La carga es automática — no es necesario registrar plugins manualmente.

        Args:
            solo_dast: Si True, solo carga plugins de plugins/dast/.
            solo_sast: Si True, solo carga plugins de plugins/sast/.
            excluir: Lista de nombres de plugins a excluir.

        Returns:
            Lista de instancias de plugins cargados.
        """
        excluir = excluir or self.config.get("plugins", {}).get("excluir", [])
        directorios = []

        # Determinar qué directorios escanear
        ruta_plugins = Path(__file__).parent.parent / "plugins"

        config_plugins = self.config.get("plugins", {})
        habilitar_dast = config_plugins.get("habilitar_dast", True)
        habilitar_sast = config_plugins.get("habilitar_sast", True)

        if solo_dast:
            directorios = [ruta_plugins / "dast"]
        elif solo_sast:
            directorios = [ruta_plugins / "sast"]
        else:
            if habilitar_dast:
                directorios.append(ruta_plugins / "dast")
            if habilitar_sast:
                directorios.append(ruta_plugins / "sast")

        self.plugins = []

        for directorio in directorios:
            if not directorio.exists():
                logger.warning(f"Directorio de plugins no encontrado: {directorio}")
                continue

            plugins_dir = self._escanear_directorio(directorio, excluir)
            self.plugins.extend(plugins_dir)

        # Ordenar por severidad máxima descendente (críticos primero)
        self.plugins.sort(key=lambda p: p.severidad_maxima.nivel, reverse=True)

        logger.info(f"{len(self.plugins)} plugins cargados:")
        for plugin in self.plugins:
            logger.info(
                f"  {plugin.severidad_maxima.icono} {plugin.nombre} "
                f"({plugin.categoria_owasp.codigo})"
            )

        return self.plugins

    def _escanear_directorio(
        self, directorio: Path, excluir: list[str]
    ) -> list[BasePlugin]:
        """
        Escanea un directorio buscando clases que hereden de BasePlugin.

        Para cada archivo .py (excepto __init__.py), importa el módulo
        dinámicamente y busca clases que sean subclases de BasePlugin.

        Args:
            directorio: Path al directorio a escanear.
            excluir: Lista de nombres de plugins a excluir.

        Returns:
            Lista de instancias de plugins encontrados.
        """
        plugins_encontrados = []

        for archivo in sorted(directorio.glob("*.py")):
            if archivo.name.startswith("_"):
                continue

            try:
                # Importar módulo dinámicamente
                nombre_modulo = f"plugins.{directorio.name}.{archivo.stem}"
                spec = importlib.util.spec_from_file_location(
                    nombre_modulo, archivo
                )
                if spec is None or spec.loader is None:
                    continue

                modulo = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(modulo)

                # Buscar clases que hereden de BasePlugin
                for nombre, clase in inspect.getmembers(modulo, inspect.isclass):
                    if (
                        issubclass(clase, BasePlugin)
                        and clase is not BasePlugin
                        and not inspect.isabstract(clase)
                    ):
                        instancia = clase()
                        if instancia.nombre not in excluir:
                            plugins_encontrados.append(instancia)
                            logger.debug(
                                f"Plugin descubierto: {instancia.nombre} "
                                f"en {archivo.name}"
                            )
                        else:
                            logger.debug(f"Plugin excluido: {instancia.nombre}")

            except Exception as e:
                logger.error(f"Error al cargar plugin desde {archivo.name}: {e}")

        return plugins_encontrados

    def iniciar_auditoria(
        self,
        target_url: str,
        solo_dast: bool = False,
        solo_sast: bool = False,
    ) -> ResultadoEscaneo:
        """
        Ejecuta el pipeline completo de auditoría de seguridad.

        Pipeline de 4 fases:
        1. CRAWLING — Descubre superficie de ataque
        2. EJECUCIÓN — Ejecuta cada plugin sobre los targets descubiertos
        3. VALIDACIÓN — Segundo paso para confirmar hallazgos
        4. FINALIZACIÓN — Deduplicar, calcular score, preparar resultado

        Args:
            target_url: URL base del objetivo a auditar.
            solo_dast: Si True, solo ejecuta plugins DAST.
            solo_sast: Si True, solo ejecuta plugins SAST.

        Returns:
            ResultadoEscaneo con todos los hallazgos validados.
        """
        self.resultado = ResultadoEscaneo(target_url=target_url)

        logger.info("=" * 60)
        logger.info("🛡️  SÉSAMO AUDITOR — Iniciando Auditoría de Seguridad")
        logger.info("=" * 60)
        logger.info(f"Target: {target_url}")

        # ─── FASE 1: Crawling (estático + headless opcional) ───
        logger.info("")
        logger.info("━━━ FASE 1: Crawling y Descubrimiento ━━━")
        exclusiones = self.config.get("target", {}).get("exclusiones", [])
        metadata = self.crawler.rastrear(target_url, exclusiones)
        metadata_dict = metadata.to_dict()

        # Crawling headless (Playwright) — opcional, mejora cobertura de SPAs
        headless_config = self.config.get("crawler", {}).get("headless", {})
        if headless_config.get("habilitar", False):
            try:
                from integraciones.playwright_crawler import PlaywrightCrawler
                pw_crawler = PlaywrightCrawler(headless_config)
                metadata_dinamica = pw_crawler.rastrear(target_url, exclusiones)
                dyn_dict = metadata_dinamica.to_dict()
                metadata_dict["urls_descubiertas"] = list(
                    set(metadata_dict.get("urls_descubiertas", [])) | set(dyn_dict.get("urls_descubiertas", []))
                )
                metadata_dict["endpoints_api"] = list(
                    set(metadata_dict.get("endpoints_api", [])) | set(dyn_dict.get("endpoints_api", []))
                )
                metadata_dict["formularios"].extend(dyn_dict.get("formularios", []))
                metadata_dict["peticiones_red"] = dyn_dict.get("peticiones_red", [])
                logger.info(f"Crawling combinado: {len(metadata_dict['urls_descubiertas'])} URLs totales")
            except Exception as e:
                logger.warning(f"Error en crawling headless: {e}. Continuando con crawling estático.")

        self.resultado.urls_escaneadas = len(metadata_dict.get("urls_descubiertas", []))

        # ─── FASE 1.5: Autenticación automática ───
        logger.info("")
        logger.info("━━━ FASE 1.5: Autenticación Automática ━━━")
        auth_config = self.config.get("auth", {})
        if auth_config.get("habilitar", True):
            try:
                from integraciones.auth_engine import AuthEngine
                auth = AuthEngine(self.http_client, target_url)
                if auth.intentar_acceso():
                    metadata_dict["autenticado"] = True
                    metadata_dict["es_admin"] = auth.es_admin
                    metadata_dict["token"] = auth.token
                    metadata_dict["auth_headers"] = auth.obtener_headers_auth()
                    logger.info(f"  Autenticado como {'admin' if auth.es_admin else 'usuario'} — token: {auth.token[:30] if auth.token else 'N/A'}...")

                    if auth.token:
                        auth_headers = auth.obtener_headers_auth()
                        self.http_client.session.headers.update(auth_headers)
                        nuevos_urls = set()
                        for ep in metadata_dict.get("endpoints_api", []):
                            resp = self.http_client.get(ep, timeout=10)
                            if resp and resp.status_code == 200:
                                nuevos_urls.add(ep)
                        if nuevos_urls:
                            metadata_dict["urls_autenticadas"] = list(nuevos_urls)
                            logger.info(f"  {len(nuevos_urls)} endpoints adicionales accesibles con autenticación")
                else:
                    metadata_dict["autenticado"] = False
                    logger.info("  No se pudo autenticar — escaneando solo endpoints públicos")
            except Exception as e:
                logger.warning(f"Error en autenticación: {e}")
                metadata_dict["autenticado"] = False
        else:
            metadata_dict["autenticado"] = False

        # Inicializar el proceso por host (HostProcess) para el target actual
        host_proc = self.scanner.crear_host_process(target_url)

        if not self.plugins:
            self.cargar_plugins(solo_dast=solo_dast, solo_sast=solo_sast)

        # Obtener el threshold de alerta global (default MEDIUM)
        global_threshold = self.config.get("plugins", {}).get("alert_threshold", "MEDIUM").upper()

        # Filtrar plugins incompatibles con la tecnología detectada antes de ejecutar o desactivados
        plugins_filtrados = []
        for plugin in self.plugins:
            # Asignar threshold global si no se ha definido uno customizado
            if not getattr(plugin, "_alert_threshold", None):
                plugin.alert_threshold = global_threshold

            if plugin.alert_threshold == "OFF":
                logger.info(f"  🔌 Saltando plugin {plugin.nombre}: desactivado por configuración (OFF)")
                self.resultado.plugins_ejecutados.append(f"{plugin.nombre} (desactivado)")
                continue

            if host_proc.plugin_aplica_a_tecnologia(plugin):
                plugins_filtrados.append(plugin)
            else:
                logger.info(f"  🔌 Saltando plugin {plugin.nombre}: no aplica a las tecnologías del target")
                self.resultado.plugins_ejecutados.append(f"{plugin.nombre} (saltado por tecnología)")

        max_workers = self.config.get("plugins", {}).get("max_workers", 4)
        logger.info(f"Ejecutando {len(plugins_filtrados)} plugins compatibles con {max_workers} workers (Umbral Global: {global_threshold})...")

        # Excluir parámetros por defecto en la metadata para todos los plugins
        metadata_filtrada = metadata_dict.copy()
        if "formularios" in metadata_filtrada:
            formularios_filtrados = []
            for form in metadata_filtrada["formularios"]:
                inputs_filtrados = [
                    inp for inp in form.get("inputs", [])
                    if not host_proc.parametro_excluido(inp.get("name", ""))
                ]
                new_form = form.copy()
                new_form["inputs"] = inputs_filtrados
                formularios_filtrados.append(new_form)
            metadata_filtrada["formularios"] = formularios_filtrados

        # Inicializar el helper de interacción con el navegador headless si está habilitado
        from core.browser_interaction import BrowserInteractionHelper
        
        with BrowserInteractionHelper(headless=True) as browser_helper:
            browser_helper_iniciado = browser_helper._browser is not None

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futuros = {}
                for plugin in plugins_filtrados:
                    sig = inspect.signature(plugin.ejecutar)
                    kwargs = {
                        "target_url": target_url,
                        "http_client": self.http_client,
                        "metadata": metadata_filtrada,
                    }
                    if "browser_helper" in sig.parameters:
                        kwargs["browser_helper"] = browser_helper if browser_helper_iniciado else None
                    
                    futuros[executor.submit(plugin.ejecutar, **kwargs)] = plugin

                for futuro in as_completed(futuros):
                    plugin = futuros[futuro]
                    try:
                        hallazgos = futuro.result() or []

                        # Filtrar hallazgos basados en el AlertThreshold del plugin
                        if plugin.alert_threshold == "HIGH":
                            from core.modelos import Confianza
                            hallazgos_filtrados_umbral = [h for h in hallazgos if h.confianza != Confianza.TENTATIVA]
                            if len(hallazgos_filtrados_umbral) < len(hallazgos):
                                logger.info(
                                    f"  🛡️ Umbral HIGH: descartados {len(hallazgos) - len(hallazgos_filtrados_umbral)} "
                                    f"hallazgos de confianza TENTATIVA en {plugin.nombre}."
                                )
                                hallazgos = hallazgos_filtrados_umbral

                        # Aplicar max_alerts_per_rule (límite de alertas por regla / plugin)
                        if plugin.max_alerts_per_rule > 0 and len(hallazgos) > plugin.max_alerts_per_rule:
                            logger.warning(
                                f"  ⚠️ {plugin.nombre} superó max_alerts_per_rule ({plugin.max_alerts_per_rule}). "
                                f"Recortando de {len(hallazgos)} a {plugin.max_alerts_per_rule} hallazgos."
                            )
                            hallazgos = hallazgos[:plugin.max_alerts_per_rule]

                        if hallazgos:
                            logger.info(f"  ✓ {plugin.nombre}: {len(hallazgos)} hallazgo(s)")
                        else:
                            logger.info(f"  ✓ {plugin.nombre}: Sin hallazgos")
                        self.resultado.hallazgos.extend(hallazgos)
                        self.resultado.plugins_ejecutados.append(plugin.nombre)
                    except Exception as e:
                        logger.error(f"  ✗ Error en plugin {plugin.nombre}: {e}")
                        self.resultado.plugins_ejecutados.append(
                            f"{plugin.nombre} (error)"
                        )


        # ─── FASE 3: Validación de Segundo Paso ───
        logger.info("")
        logger.info("━━━ FASE 3: Validación de Hallazgos ━━━")

        hallazgos_antes = len(self.resultado.hallazgos)
        hallazgos_validados = []

        for hallazgo in self.resultado.hallazgos:
            # Buscar el plugin que generó este hallazgo
            plugin = self._buscar_plugin(hallazgo.plugin_nombre)

            if plugin:
                try:
                    es_valido = plugin.validar_hallazgo(hallazgo, self.http_client)
                    if es_valido:
                        hallazgos_validados.append(hallazgo)
                    else:
                        logger.debug(
                            f"  Hallazgo descartado por validación: "
                            f"{hallazgo.cwe_id} en {hallazgo.url_afectada}"
                        )
                except Exception as e:
                    # Si la validación falla, conservar el hallazgo
                    logger.warning(
                        f"  Error en validación de {hallazgo.plugin_nombre}: {e}. "
                        f"Conservando hallazgo."
                    )
                    hallazgos_validados.append(hallazgo)
            else:
                # Plugin no encontrado, conservar hallazgo
                hallazgos_validados.append(hallazgo)

        self.resultado.hallazgos = hallazgos_validados

        # ─── WAF / Bloqueos Genéricos Repetitivos Detector ───
        # Si un WAF o regla de routing bloquea o responde igual a múltiples ataques,
        # detectamos esa firma de respuesta repetitiva y la silenciamos como FP.
        firmas_bloqueo = {}
        for h in self.resultado.hallazgos:
            if h.evidencia:
                # Firma basada en método y primeros 80 caracteres de la evidencia
                firma = (h.metodo_http, h.evidencia[:80].lower())
                if firma not in firmas_bloqueo:
                    firmas_bloqueo[firma] = []
                firmas_bloqueo[firma].append(h)

        for (met, ev_firma), lista_hallazgos in firmas_bloqueo.items():
            # Si hay 6 o más hallazgos con la misma firma en diferentes URLs
            if len(lista_hallazgos) >= 6:
                urls_unicas = set(h.url_afectada for h in lista_hallazgos)
                if len(urls_unicas) >= 3:
                    logger.warning(
                        f"  ⚠️ Detectada firma repetitiva genérica ({len(lista_hallazgos)} ocurrencias en {len(urls_unicas)} URLs): '{ev_firma}'. "
                        f"Clasificando estas alertas como Falsos Positivos de WAF/Bloqueo."
                    )
                    from core.modelos import Confianza
                    for h in lista_hallazgos:
                        h.confianza = Confianza.FALSE_POSITIVE

        # Deduplicar hallazgos
        self.resultado.deduplicar()

        hallazgos_despues = len(self.resultado.hallazgos)
        descartados = hallazgos_antes - hallazgos_despues

        if descartados > 0:
            logger.info(
                f"  {descartados} hallazgo(s) descartado(s) "
                f"(falsos positivos / duplicados)"
            )
        logger.info(f"  {hallazgos_despues} hallazgo(s) validado(s) final(es)")

        # ─── FASE 4: Finalización ───
        self.resultado.finalizar()

        logger.info("")
        logger.info("━━━ RESULTADO FINAL ━━━")
        resumen = self.resultado.resumen()
        logger.info(f"  Score de Riesgo: {resumen['score_riesgo']}/100")
        logger.info(f"  URLs escaneadas: {resumen['urls_escaneadas']}")
        logger.info(f"  Plugins ejecutados: {resumen['plugins_ejecutados']}")
        logger.info(f"  Duración: {resumen['duracion']}")

        for etiqueta, conteo in resumen["por_severidad"].items():
            if conteo > 0:
                logger.info(f"    {etiqueta}: {conteo}")

        logger.info("=" * 60)
        logger.info("🛡️  Auditoría completada")
        logger.info("=" * 60)

        return self.resultado

    def _buscar_plugin(self, nombre: str) -> Optional[BasePlugin]:
        """Busca un plugin por nombre en la lista de plugins cargados."""
        for plugin in self.plugins:
            if plugin.nombre == nombre:
                return plugin
        return None

    def listar_plugins(self) -> list[dict]:
        """
        Lista todos los plugins disponibles con su información.

        Returns:
            Lista de diccionarios con info de cada plugin.
        """
        if not self.plugins:
            self.cargar_plugins()

        return [
            {
                "nombre": p.nombre,
                "categoria_owasp": str(p.categoria_owasp),
                "severidad_maxima": p.severidad_maxima.etiqueta,
                "icono_severidad": p.severidad_maxima.icono,
                "tipo": "DAST" if "dast" in p.__module__ else "SAST",
            }
            for p in self.plugins
        ]

    def cerrar(self) -> None:
        """Libera recursos del motor (cierra la sesión HTTP)."""
        self.http_client.cerrar()
        logger.debug("Motor de auditoría cerrado")
