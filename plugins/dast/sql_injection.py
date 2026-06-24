"""
plugins/dast/sql_injection.py — Plugin de Inyección SQL

Detecta vulnerabilidades de inyección SQL en formularios y query strings
mediante la inyección de payloads y análisis de firmas de error de BD.

Técnicas implementadas:
- Error-Based: Provocar errores de BD con firmas identificables
- Login Bypass: Intentar autenticación con payloads de bypass
- UNION-Based: Detección de inyección basada en UNION SELECT

Categoría OWASP: A03:2021 — Injection
CWE: CWE-89 (SQL Injection)
"""

from urllib.parse import urlencode, urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.interfaces import BasePlugin
from core.logger import get_logger
from core.modelos import (
    CategoriaOWASP,
    Confianza,
    Hallazgo,
    Severidad,
)

logger = get_logger("sql_injection")


class SQLInjectionPlugin(BasePlugin):
    """
    Plugin de detección de inyección SQL.

    Carga payloads y firmas de error desde archivos externos en wordlists/.
    Prueba cada payload contra formularios descubiertos por el crawler
    y parámetros de query strings, buscando firmas de error de BD
    en las respuestas HTTP.
    """

    def __init__(self):
        self._payloads: list[str] = []
        self._firmas: dict[str, list[str]] = {}

    @property
    def nombre(self) -> str:
        return "SQL Injection Scanner"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A03_INJECTION

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.CRITICA

    def _cargar_firmas(self) -> dict[str, list[str]]:
        """
        Carga las firmas de error de BD desde el archivo externo.

        Returns:
            Dict con clave=nombre_db, valor=lista_de_firmas.
        """
        firmas: dict[str, list[str]] = {}
        try:
            lineas = self.cargar_payloads("sqli_error_signatures.txt")
            for linea in lineas:
                if ":" in linea:
                    partes = linea.split(":", 1)
                    db = partes[0].strip().lower()
                    firma = partes[1].strip()
                    if db not in firmas:
                        firmas[db] = []
                    firmas[db].append(firma)
        except FileNotFoundError:
            logger.warning(
                "Archivo sqli_error_signatures.txt no encontrado. "
                "Usando firmas vacías."
            )
        return firmas

    def _buscar_firma_en_respuesta(self, texto_respuesta: str) -> tuple[str, str] | None:
        """
        Busca firmas de error de BD en el texto de una respuesta HTTP.

        Args:
            texto_respuesta: Texto completo de la respuesta HTTP.

        Returns:
            Tupla (nombre_db, firma_encontrada) si hay match, None si no.
        """
        texto_lower = texto_respuesta.lower()
        for db, firmas_db in self._firmas.items():
            for firma in firmas_db:
                if firma.lower() in texto_lower:
                    return (db, firma)
        return None

    def ejecutar(self, target_url: str, http_client, metadata: dict) -> list[Hallazgo]:
        """
        Ejecuta el escaneo de inyección SQL.

        Prueba payloads SQLi contra:
        1. Formularios HTML descubiertos por el crawler
        2. Parámetros de query strings de URLs descubiertas

        Args:
            target_url: URL base del objetivo.
            http_client: Cliente HTTP compartido.
            metadata: Metadata del crawler con formularios y URLs.

        Returns:
            Lista de Hallazgos de inyección SQL detectados.
        """
        hallazgos = []

        # Cargar payloads y firmas desde archivos externos
        try:
            self._payloads = self.cargar_payloads("sqli_payloads.txt")
        except FileNotFoundError:
            logger.error(
                "Archivo sqli_payloads.txt no encontrado. "
                "No se puede ejecutar el escaneo de SQLi."
            )
            return hallazgos

        self._firmas = self._cargar_firmas()

        logger.info(
            f"Payloads cargados: {len(self._payloads)} | "
            f"Firmas: {sum(len(v) for v in self._firmas.values())}"
        )

        # ─── Probar formularios ───
        formularios = metadata.get("formularios", [])
        logger.info(f"Probando {len(formularios)} formularios...")

        for formulario in formularios:
            hallazgos_form = self._probar_formulario(
                formulario, http_client, target_url
            )
            hallazgos.extend(hallazgos_form)

        # ─── Probar query strings de URLs descubiertas y endpoints API ───
        urls = metadata.get("urls_descubiertas", [])
        endpoints = metadata.get("endpoints_api", [])

        # Combinar URLs del crawler y de APIs encontradas
        urls_totales = set(urls)
        for ep in endpoints:
            urls_totales.add(ep)

        urls_con_params = [u for u in urls_totales if "?" in u]

        # Para endpoints sin params, probar parámetros comunes
        # pero SOLO si el endpoint responde de forma útil
        params_comunes = ["id", "q", "search", "query"]
        for ep in endpoints:
            if "?" not in ep:
                for param in params_comunes:
                    response = http_client.get(ep, params={param: "test123"})
                    if response and response.status_code not in (401, 403, 404, 500):
                        urls_con_params.append(f"{ep}?{param}=test123")
                        logger.debug(
                            f"  Endpoint {ep}?{param}= responde "
                            f"{response.status_code} — incluido para pruebas"
                        )
                    else:
                        status = response.status_code if response else "sin respuesta"
                        logger.debug(
                            f"  Endpoint {ep}?{param}= no testeable "
                            f"({status}) — omitido"
                        )

        total_urls = len(urls_con_params)
        logger.info(f"Probando {total_urls} URLs y endpoints de API con parámetros...")

        for idx, url in enumerate(urls_con_params, 1):
            if idx % 5 == 0 or idx == 1 or idx == total_urls:
                logger.info(f"  [Progreso] Probando URL/Endpoint {idx}/{total_urls} ({int(idx/total_urls*100)}%)...")
            hallazgos_url = self._probar_query_string(url, http_client)
            hallazgos.extend(hallazgos_url)

        return hallazgos

    def _probar_formulario(
        self, formulario: dict, http_client, target_url: str
    ) -> list[Hallazgo]:
        hallazgos = []
        action = formulario.get("action", "")
        method = formulario.get("method", "GET").upper()
        inputs = formulario.get("inputs", [])

        tipos_inyectables = {"text", "email", "password", "search", "tel", "url", "hidden"}
        campos_inyectables = [
            inp for inp in inputs
            if inp.get("type", "text").lower() in tipos_inyectables
        ]

        if not campos_inyectables:
            return hallazgos

        datos_base = {inp["name"]: inp.get("value", "test") for inp in inputs}
        url_form = action if action.startswith("http") else urljoin(target_url, action)

        payload_chunks = [self._payloads[i:i + 20] for i in range(0, len(self._payloads), 20)]

        with ThreadPoolExecutor(max_workers=5) as executor:
            for campo in campos_inyectables:
                nombre_campo = campo["name"]
                for chunk in payload_chunks:
                    futuros = {}
                    for payload in chunk:
                        datos = datos_base.copy()
                        datos[nombre_campo] = payload
                        futuros[
                            executor.submit(
                                http_client.post if method == "POST" else http_client.get,
                                url_form,
                                data=datos if method == "POST" else None,
                                params=datos if method != "POST" else None,
                            )
                        ] = payload

                    for futuro in as_completed(futuros):
                        payload = futuros[futuro]
                        try:
                            response = futuro.result()
                        except Exception:
                            continue
                        if response is None:
                            continue

                        match = self._buscar_firma_en_respuesta(response.text)
                        if match:
                            db_nombre, firma = match
                            hallazgo = Hallazgo(
                                plugin_nombre=self.nombre,
                                categoria_owasp=self.categoria_owasp,
                                severidad=Severidad.CRITICA,
                                confianza=Confianza.FIRME,
                                url_afectada=url_form,
                                parametro=nombre_campo,
                                metodo_http=method,
                                payload_usado=payload,
                                evidencia=f"Firma de error {db_nombre.upper()} detectada: '{firma}' "
                                          f"(HTTP {response.status_code})",
                                cwe_id="CWE-89",
                                remediacion=(
                                    "Usar consultas parametrizadas (prepared statements) "
                                    "en lugar de concatenar input del usuario en queries SQL. "
                                    "Implementar validación de entrada y ORM seguro."
                                ),
                            )
                            hallazgos.append(hallazgo)
                            logger.warning(
                                f"  🔴 SQLi detectada en {url_form} "
                                f"[campo: {nombre_campo}] "
                                f"[DB: {db_nombre}]"
                            )
                            break

                        if response.status_code == 200 and "login" in url_form.lower():
                            indicadores_exito = [
                                "dashboard", "welcome", "logout", "token",
                                "success", "authenticated", "session",
                            ]
                            texto_lower = response.text.lower()
                            if any(ind in texto_lower for ind in indicadores_exito):
                                hallazgo = Hallazgo(
                                    plugin_nombre=self.nombre,
                                    categoria_owasp=self.categoria_owasp,
                                    severidad=Severidad.CRITICA,
                                    confianza=Confianza.FIRME,
                                    url_afectada=url_form,
                                    parametro=nombre_campo,
                                    metodo_http=method,
                                    payload_usado=payload,
                                    evidencia=(
                                        f"Login bypass exitoso — respuesta HTTP {response.status_code} "
                                        f"contiene indicadores de autenticación exitosa."
                                    ),
                                    cwe_id="CWE-89",
                                    remediacion=(
                                        "Usar consultas parametrizadas para la autenticación. "
                                        "Nunca concatenar input del usuario en queries de login."
                                    ),
                                )
                                hallazgos.append(hallazgo)
                                logger.warning(
                                    f"  🔴 Login bypass detectado en {url_form} "
                                    f"[campo: {nombre_campo}]"
                                )
                                break

                    # Si encontramos algo en este campo, pasar al siguiente
                    if any(h.parametro == nombre_campo for h in hallazgos):
                        break

        return hallazgos

    def _probar_query_string(self, url: str, http_client) -> list[Hallazgo]:
        hallazgos = []
        parsed = urlparse(url)
        params_originales = parse_qs(parsed.query, keep_blank_values=True)

        if not params_originales:
            return hallazgos

        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        payload_chunks = [self._payloads[i:i + 15] for i in range(0, len(self._payloads), 15)]

        for param_name in params_originales:
            baseline_response = http_client.get(
                url_base, params={param_name: "test123"}
            )
            if baseline_response is None:
                continue

            if baseline_response.status_code == 500:
                continue
            if baseline_response.status_code in (401, 403):
                continue

            baseline = {
                "status": baseline_response.status_code,
                "time": baseline_response.elapsed.total_seconds(),
                "length": len(baseline_response.content),
                "text": baseline_response.text,
            }

            baseline_match = self._buscar_firma_en_respuesta(baseline["text"])
            respuesta_and_1_1 = None

            with ThreadPoolExecutor(max_workers=5) as executor:
                for chunk in payload_chunks:
                    futuros = {}
                    for payload in chunk:
                        params = {k: v[0] for k, v in params_originales.items()}
                        params[param_name] = payload
                        futuros[
                            executor.submit(http_client.get, url_base, params=params)
                        ] = payload

                    for futuro in as_completed(futuros):
                        payload = futuros[futuro]
                        try:
                            response = futuro.result()
                        except Exception:
                            continue
                        if response is None:
                            continue

                        match = self._buscar_firma_en_respuesta(response.text)
                        if match and not baseline_match:
                            db_nombre, firma = match
                            hallazgos.append(Hallazgo(
                                plugin_nombre=self.nombre,
                                categoria_owasp=self.categoria_owasp,
                                severidad=Severidad.CRITICA,
                                confianza=Confianza.FIRME,
                                url_afectada=url,
                                parametro=param_name,
                                metodo_http="GET",
                                payload_usado=payload,
                                evidencia=f"Firma de error {db_nombre.upper()} detectada: '{firma}'",
                                cwe_id="CWE-89",
                                remediacion="Usar consultas parametrizadas para todos los inputs.",
                            ))
                            logger.warning(f"  🔴 SQLi en {url_base} [param: {param_name}] [DB: {db_nombre}]")
                            break

                        keywords_time = ["SLEEP", "PG_SLEEP", "WAITFOR", "BENCHMARK"]
                        if any(kw in payload.upper() for kw in keywords_time):
                            delta = response.elapsed.total_seconds() - baseline["time"]
                            if delta > 2.5:
                                hallazgos.append(Hallazgo(
                                    plugin_nombre=self.nombre,
                                    categoria_owasp=self.categoria_owasp,
                                    severidad=Severidad.CRITICA,
                                    confianza=Confianza.FIRME,
                                    url_afectada=url,
                                    parametro=param_name,
                                    metodo_http="GET",
                                    payload_usado=payload,
                                    evidencia=f"Time-based SQLi — delta {delta:.2f}s vs baseline {baseline['time']:.2f}s",
                                    cwe_id="CWE-89",
                                    remediacion="Usar consultas parametrizadas.",
                                ))
                                logger.warning(f"  🔴 Time-based SQLi en {url_base} [param: {param_name}]")
                                break

                        # Boolean-based: AND 1=1 vs AND 1=2
                        if "AND 1=1" in payload and "AND 1=2" not in payload:
                            respuesta_and_1_1 = response
                        elif "AND 1=2" in payload and respuesta_and_1_1 is not None:
                            len_true = len(respuesta_and_1_1.content)
                            len_false = len(response.content)
                            diff = abs(len_true - len_false)
                            if diff > 50 and respuesta_and_1_1.status_code == baseline["status"] and response.status_code == baseline["status"]:
                                hallazgos.append(Hallazgo(
                                    plugin_nombre=self.nombre,
                                    categoria_owasp=self.categoria_owasp,
                                    severidad=Severidad.ALTA,
                                    confianza=Confianza.TENTATIVA,
                                    url_afectada=url,
                                    parametro=param_name,
                                    metodo_http="GET",
                                    payload_usado="' AND 1=1 -- / ' AND 1=2 --",
                                    evidencia=f"Boolean-based SQLi — AND 1=1: {len_true}B, AND 1=2: {len_false}B (diff: {diff}B)",
                                    cwe_id="CWE-89",
                                    remediacion="Usar consultas parametrizadas.",
                                ))
                                logger.warning(f"  🟠 Boolean-based SQLi en {url_base} [param: {param_name}]")
                                break

                    if any(h.parametro == param_name for h in hallazgos):
                        break

        return hallazgos

    def validar_hallazgo(self, hallazgo: Hallazgo, http_client) -> bool:
        """
        Validación de segundo paso diferencial:
        1. Comprobar que el payload ofensivo sigue disparando el error.
        2. Enviar un payload neutralizador (ej: comillas neutralizadas o un boolean true).
        3. Si el payload neutralizador resuelve/limpia el error de BD, confirmamos vulnerabilidad.
        """
        if not hallazgo.payload_usado:
            return True

        # Determinar neutralizador según el payload
        payload_neutralizador = None
        if "'" in hallazgo.payload_usado:
            if "OR" in hallazgo.payload_usado.upper():
                payload_neutralizador = "' OR '1'='1"
            else:
                payload_neutralizador = "test' --"

        try:
            # 1. Re-verificar payload ofensivo
            if hallazgo.metodo_http == "POST":
                resp_ofensiva = http_client.post(
                    hallazgo.url_afectada,
                    data={hallazgo.parametro: hallazgo.payload_usado},
                )
            else:
                resp_ofensiva = http_client.get(
                    hallazgo.url_afectada,
                    params={hallazgo.parametro: hallazgo.payload_usado},
                )

            if resp_ofensiva is None:
                return True # Mantener si hay timeout/caída en re-verificación

            error_ofensivo = self._buscar_firma_en_respuesta(resp_ofensiva.text)
            if not error_ofensivo:
                # Ya no da error con el payload ofensivo original
                return False

            # Si no tenemos payload neutralizador, nos guiamos solo por el ofensivo
            if not payload_neutralizador:
                hallazgo.confianza = Confianza.CONFIRMADA
                return True

            # 2. Enviar payload neutralizador
            if hallazgo.metodo_http == "POST":
                resp_neutral = http_client.post(
                    hallazgo.url_afectada,
                    data={hallazgo.parametro: payload_neutralizador},
                )
            else:
                resp_neutral = http_client.get(
                    hallazgo.url_afectada,
                    params={hallazgo.parametro: payload_neutralizador},
                )

            if resp_neutral is None:
                return True

            error_neutral = self._buscar_firma_en_respuesta(resp_neutral.text)

            # Si el neutralizador no da error, se confirma que controlamos la sintaxis SQL
            if not error_neutral:
                logger.info(f"  ✓ SQLi confirmada diferencialmente en {hallazgo.url_afectada} [param: {hallazgo.parametro}]")
                hallazgo.confianza = Confianza.CONFIRMADA
                return True

            # Si el neutralizador también da error, es un comportamiento errático genérico del backend
            logger.debug(f"  SQLi descartada por validación diferencial: {hallazgo.url_afectada}")
            return False

        except Exception as e:
            logger.warning(f"Error en validación diferencial de SQLi: {e}")
            return True
