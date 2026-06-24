"""
plugins/sast/sonarqube_scanner.py — Plugin de SonarQube (SAST via API)

Consulta la API REST de SonarQube para obtener issues de calidad de código,
los traduce al modelo Hallazgo y los incorpora al reporte de Sésamo.

Requiere: SonarQube server accesible con token de autenticación.
Configurar en config.json:

    "sonarqube": {
        "url": "http://tu-servidor-sonarqube:9000",
        "token": "squ_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "project_key": "mi-proyecto",
        "habilitar": true
    },
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30,
                )
                if resp is None or resp.status_code != 200:
                    break
                data = resp.json()
                issues = data.get("issues", [])
                all_issues.extend(issues)
                total = data.get("paging", {}).get("total", 0)
                if page * page_size >= total:
                    break
                page += 1
            except Exception as e:
                logger.warning(f"Error obteniendo issues de SonarQube (página {page}): {e}")
                break

        if not all_issues:
            logger.info("SonarQube: no se encontraron issues abiertos")
            return hallazgos

        logger.info(f"SonarQube: {len(all_issues)} issues obtenidos")

        # 3. Traducir issues a Hallazgos
        for issue in all_issues:
            severity = issue.get("severity", "MAJOR")
            sev = _SONAR_SEV_MAP.get(severity, Severidad.MEDIA)
            issue_type = issue.get("type", "CODE_SMELL")
            categoria = _SONAR_TYPE_MAP.get(issue_type, CategoriaOWASP.A05_SECURITY_MISCONFIGURATION)
            rule = issue.get("rule", "")
            component = issue.get("component", "")
            line = issue.get("line")
            message = issue.get("message", "")
            resolution = issue.get("resolution", "")
            issue_key = issue.get("key", "")
            creation_date = issue.get("creationDate", "")

            # Extraer lenguaje y rule ID para link de referencia
            lang = ""
            rule_id = rule.replace("java:", "").replace("python:", "").replace("javascript:", "").replace("ts:", "").replace("web:", "")
            if ":" in rule:
                lang = rule.split(":")[0]

            # Determinar CWE
            cwe = self._determinar_cwe(message, rule)

            # Determinar confianza
            if resolution:
                confianza = Confianza.TENTATIVA
            elif issue_type == "VULNERABILITY":
                confianza = Confianza.CONFIRMADA
            elif issue_type == "SECURITY_HOTSPOT":
                confianza = Confianza.TENTATIVA
            else:
                confianza = Confianza.FIRME

            remediacion = (
                f"Revisar y corregir el issue {rule} en {component}"
                f"{f':{line}' if line else ''}. "
                f"{self._generar_remediacion(message, rule)}"
            )

            rule_link = _SONAR_RULES_URL.format(language=lang, rule_id=rule_id) if lang else ""

            hallazgos.append(Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=categoria,
                severidad=sev,
                confianza=confianza,
                url_afectada=f"{component}:{line}" if line else component,
                parametro=rule,
                metodo_http="SAST",
                payload_usado="",
                evidencia=(
                    f"[{issue_type}] {message} | "
                    f"Regla: {rule} | "
                    f"Componente: {component}{f':{line}' if line else ''} | "
                    f"Creado: {creation_date[:10] if creation_date else 'N/A'}"
                    f"{f' | Referencia: {rule_link}' if rule_link else ''}"
                ),
                cwe_id=cwe,
                remediacion=remediacion,
            ))

        logger.info(f"SonarQube: {len(hallazgos)} hallazgos traducidos a Sésamo")
        return hallazgos

    def _determinar_cwe(self, message: str, rule: str) -> str:
        msg_lower = message.lower()
        for keyword, cwe in _CWE_KEYWORDS.items():
            if keyword in msg_lower:
                return cwe
        rule_lower = rule.lower()
        if "S" in rule:
            try:
                rule_num = int(rule.split("S")[-1])
                if rule_num in (2076, 3649):
                    return "CWE-89"
                elif rule_num in (5131, 5146, 5147):
                    return "CWE-79"
                elif rule_num in (5167, 5314):
                    return "CWE-22"
                elif rule_num in (5168, 5315):
                    return "CWE-918"
                elif rule_num == 5536:
                    return "CWE-352"
                elif rule_num == 5547:
                    return "CWE-200"
                elif rule_num == 5548:
                    return "CWE-327"
                elif rule_num == 5550:
                    return "CWE-798"
            except ValueError:
                pass
        return "CWE-1104"

    def _generar_remediacion(self, message: str, rule: str) -> str:
        msg_lower = message.lower()
        if "sql" in msg_lower or "injection" in msg_lower:
            return "Usar consultas parametrizadas o prepared statements."
        if "xss" in msg_lower or "cross-site" in msg_lower:
            return "Sanitizar y escapar todo input antes de renderizarlo."
        if "password" in msg_lower or "credential" in msg_lower or "secret" in msg_lower:
            return "Eliminar secretos del código. Usar variables de entorno o gestor de secretos."
        if "csrf" in msg_lower:
            return "Implementar tokens CSRF en formularios y endpoints POST/PUT/DELETE."
        if "cors" in msg_lower:
            return "Restringir CORS a dominios específicos en vez de usar wildcard."
        if "encrypt" in msg_lower or "crypto" in msg_lower:
            return "Usar algoritmos criptográficos fuertes y actualizados."
        if "random" in msg_lower:
            return "Usar generador de números aleatorios criptográficamente seguro."
        if "deserialization" in msg_lower or "deserialize" in msg_lower:
            return "Validar datos deserializados. Usar whitelist de clases permitidas."
        return "Revisar la regla de SonarQube para más detalles sobre la corrección."
