"""
core/interfaces.py — Contratos Abstractos de Sésamo Auditor

Define la interfaz base (BasePlugin) que todo plugin de auditoría
debe implementar obligatoriamente. Cumple con:
- Principio de Inversión de Dependencias (DIP): El engine depende
  de esta abstracción, nunca de implementaciones concretas.
- Principio Abierto/Cerrado (OCP): Nuevos plugins se crean heredando
  de BasePlugin sin modificar el motor de ejecución.

Para crear un nuevo plugin:
1. Crear un archivo .py en plugins/dast/ o plugins/sast/
2. Definir una clase que herede de BasePlugin
3. Implementar todas las propiedades y métodos abstractos
4. El engine lo descubrirá automáticamente vía importlib
"""

from abc import ABC, abstractmethod
from pathlib import Path

from core.modelos import CategoriaOWASP, Confianza, Hallazgo, Severidad


class BasePlugin(ABC):
    """
    Interfaz base abstracta para todos los plugins de auditoría.

    Todo plugin (DAST o SAST) debe heredar de esta clase e implementar
    las propiedades abstractas (nombre, categoria_owasp, severidad_maxima)
    y el método ejecutar().

    El método validar_hallazgo() es opcional — tiene una implementación
    por defecto que siempre retorna True. Los plugins que necesiten
    validación de segundo paso pueden sobreescribirlo.

    El método cargar_payloads() está implementado en la clase base
    y no necesita ser reimplementado. Lee payloads de archivos externos
    en el directorio wordlists/.

    Ejemplo de plugin mínimo:

        class MiPlugin(BasePlugin):
            @property
            def nombre(self) -> str:
                return "Mi Plugin de Seguridad"

            @property
            def categoria_owasp(self) -> CategoriaOWASP:
                return CategoriaOWASP.A03_INJECTION

            @property
            def severidad_maxima(self) -> Severidad:
                return Severidad.ALTA

            def ejecutar(self, target_url, http_client, metadata):
                hallazgos = []
                # ... lógica de auditoría ...
                return hallazgos
    """

    # ─── Propiedades Abstractas (OBLIGATORIAS) ───

    @property
    @abstractmethod
    def nombre(self) -> str:
        """
        Nombre único y descriptivo del plugin.

        Ejemplo: "SQL Injection Scanner", "XSS Reflected Scanner"

        Returns:
            String con el nombre legible del plugin.
        """
        pass

    @property
    @abstractmethod
    def categoria_owasp(self) -> CategoriaOWASP:
        """
        Categoría OWASP Top 10 2021 correspondiente al tipo de vulnerabilidad
        que este plugin detecta.

        Returns:
            Valor del Enum CategoriaOWASP.
        """
        pass

    @property
    @abstractmethod
    def severidad_maxima(self) -> Severidad:
        """
        Severidad máxima que este plugin puede reportar.

        Usado por el engine para ordenar la ejecución de plugins:
        los que pueden detectar vulnerabilidades más críticas se
        ejecutan primero.

        Returns:
            Valor del Enum Severidad.
        """
        pass

    # ─── Propiedades de Configuración Estilo ZAP (Opcionales con default) ───

    @property
    def alert_threshold(self) -> str:
        """
        Nivel de sensibilidad del plugin: 'LOW', 'MEDIUM', 'HIGH', 'OFF' o 'DEFAULT'.
        - LOW: Más sensible, genera más alertas (y potencialmente más falsos positivos).
        - HIGH: Solo reporta con alta confianza.
        """
        return getattr(self, "_alert_threshold", "MEDIUM")

    @alert_threshold.setter
    def alert_threshold(self, value: str):
        self._alert_threshold = value.upper()

    @property
    def max_alerts_per_rule(self) -> int:
        """
        Límite máximo de alertas que este plugin puede levantar antes de detenerse (maxAlertsPerRule).
        0 significa ilimitado.
        """
        return 5

    @property
    def tech_targets(self) -> list[str]:
        """
        Lista de tecnologías aplicables para este plugin (ej. ['mysql', 'php', 'apache']).
        Si se especifica y el motor no detecta esta tecnología, el plugin se salta.
        Vacío significa aplicable a todas las tecnologías.
        """
        return []

    # ─── Métodos Abstractos (OBLIGATORIOS) ───

    @abstractmethod
    def ejecutar(
        self,
        target_url: str,
        http_client,
        metadata: dict,
        browser_helper = None
    ) -> list[Hallazgo]:
        """
        Ejecuta la lógica principal de auditoría del plugin.

        Este es el método core que implementa la detección de vulnerabilidades.
        Recibe el target, un cliente HTTP compartido (inyección de dependencias),
        la metadata del crawler con la superficie de ataque descubierta, y opcionalmente
        un browser_helper (BrowserInteractionHelper) para interacción headless SPA.

        Args:
            target_url: URL base del objetivo a auditar.
            http_client: Instancia compartida de HttpClient (core/http_client.py).
            metadata: Diccionario con la superficie de ataque descubierta.
            browser_helper: Instancia compartida de BrowserInteractionHelper (core/browser_interaction.py)
                            para plugins que necesiten interacción en el navegador (opcional).

        Returns:
            Lista de objetos Hallazgo con las vulnerabilidades detectadas.
        """
        pass

    # ─── Métodos con Implementación Base (OPCIONALES de sobreescribir) ───

    def validar_hallazgo(self, hallazgo: Hallazgo, http_client) -> bool:
        """
        Validación de segundo paso para reducir falsos positivos.

        Este método es invocado por el engine DESPUÉS de ejecutar().
        Para cada hallazgo reportado, el engine llama a este método
        para confirmar que la vulnerabilidad es real.

        La implementación por defecto retorna True (acepta todo).
        Los plugins que necesiten verificación adicional pueden
        sobreescribirlo con lógica de re-verificación.

        Ejemplo de sobreescritura:
            def validar_hallazgo(self, hallazgo, http_client):
                # Re-enviar el payload y verificar que el error persiste
                resp = http_client.get(hallazgo.url_afectada,
                                       params={hallazgo.parametro: hallazgo.payload_usado})
                return "error" in resp.text.lower()

        Args:
            hallazgo: El Hallazgo a validar.
            http_client: Cliente HTTP para hacer requests de verificación.

        Returns:
            True si el hallazgo es válido, False si debe descartarse.
        """
        return True

    def cargar_payloads(self, nombre_archivo: str) -> list[str]:
        """
        Carga payloads desde un archivo externo en el directorio wordlists/.

        Lee el archivo línea por línea, ignorando:
        - Líneas vacías
        - Líneas que empiezan con '#' (comentarios)

        Los payloads se almacenan en archivos externos para cumplir con
        la regla de no embeber datos en código.

        Args:
            nombre_archivo: Nombre del archivo dentro de wordlists/
                           (ej. "sqli_payloads.txt", "xss_payloads.txt")

        Returns:
            Lista de strings, cada uno un payload listo para usar.

        Raises:
            FileNotFoundError: Si el archivo no existe en wordlists/.
        """
        # Resuelve la ruta relativa al directorio raíz del proyecto
        ruta_proyecto = Path(__file__).parent.parent
        ruta_archivo = ruta_proyecto / "wordlists" / nombre_archivo

        if not ruta_archivo.exists():
            raise FileNotFoundError(
                f"Archivo de payloads no encontrado: {ruta_archivo}\n"
                f"Verifica que el archivo '{nombre_archivo}' exista en el "
                f"directorio wordlists/ del proyecto."
            )

        payloads = []
        with open(ruta_archivo, "r", encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                # Ignorar líneas vacías y comentarios
                if linea and not linea.startswith("#"):
                    payloads.append(linea)

        return payloads

    def __repr__(self) -> str:
        """Representación legible del plugin para logs y debugging."""
        return (
            f"<{self.__class__.__name__} "
            f"nombre='{self.nombre}' "
            f"categoria={self.categoria_owasp.codigo} "
            f"severidad_max={self.severidad_maxima.etiqueta}>"
        )
