"""
core/logger.py — Sistema de Logging Dual de Sésamo Auditor

Proporciona logging centralizado con dos destinos simultáneos:
1. Consola: Coloreado por severidad con colorama (INFO+)
2. Archivo: Rotativo con RotatingFileHandler en logs/ (DEBUG+)

Uso:
    from core.logger import get_logger

    logger = get_logger("mi_modulo")
    logger.info("Mensaje informativo")
    logger.warning("Advertencia de severidad media")
    logger.critical("Vulnerabilidad crítica encontrada")
"""

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

# Inicializar colorama para soporte cross-platform
colorama_init(autoreset=True)

# Directorio base de logs (relativo al proyecto)
_RUTA_PROYECTO = Path(__file__).parent.parent
_DIRECTORIO_LOGS = _RUTA_PROYECTO / "logs"

# Configuración por defecto (puede ser sobreescrita por config.json)
_CONFIG_DEFECTO = {
    "nivel_consola": "INFO",
    "nivel_archivo": "DEBUG",
    "max_tamano_mb": 5,
    "max_backups": 5,
}

# Mapeo de niveles de logging a colores de consola
_COLORES_NIVEL = {
    logging.DEBUG: Fore.CYAN,
    logging.INFO: Fore.GREEN,
    logging.WARNING: Fore.YELLOW,
    logging.ERROR: Fore.RED,
    logging.CRITICAL: Fore.RED + Style.BRIGHT,
}

# Mapeo de niveles de logging a iconos
_ICONOS_NIVEL = {
    logging.DEBUG: "🔍",
    logging.INFO: "ℹ️ ",
    logging.WARNING: "🟡",
    logging.ERROR: "🟠",
    logging.CRITICAL: "🔴",
}


class _FormateadorConsola(logging.Formatter):
    """
    Formateador personalizado para la consola que aplica colores
    según el nivel de severidad del mensaje.
    """

    def format(self, record: logging.LogRecord) -> str:
        color = _COLORES_NIVEL.get(record.levelno, Fore.WHITE)
        icono = _ICONOS_NIVEL.get(record.levelno, "  ")
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        nivel = record.levelname.ljust(8)
        modulo = record.name.split(".")[-1]

        mensaje_formateado = (
            f"{Fore.WHITE}{Style.DIM}[{timestamp}]{Style.RESET_ALL} "
            f"{icono} {color}{nivel}{Style.RESET_ALL} "
            f"{Fore.CYAN}[{modulo}]{Style.RESET_ALL} "
            f"{record.getMessage()}"
        )
        return mensaje_formateado


class _FormateadorArchivo(logging.Formatter):
    """
    Formateador para archivos de log — texto plano sin colores ANSI,
    con toda la información necesaria para trazabilidad.
    """

    def __init__(self):
        super().__init__(
            fmt="[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def _asegurar_directorio_logs() -> Path:
    """
    Crea el directorio de logs si no existe.

    Returns:
        Path al directorio de logs.
    """
    _DIRECTORIO_LOGS.mkdir(parents=True, exist_ok=True)
    return _DIRECTORIO_LOGS


def configurar_logging(config: dict | None = None) -> None:
    """
    Configura el sistema de logging global con los parámetros dados.

    Debe llamarse una vez al inicio de la aplicación (desde main.py).
    Si no se llama, get_logger() usará la configuración por defecto.

    Args:
        config: Diccionario con claves opcionales:
            - nivel_consola: str ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
            - nivel_archivo: str (mismo formato)
            - max_tamano_mb: int (tamaño máximo del archivo de log antes de rotar)
            - max_backups: int (cantidad de archivos de backup a mantener)
            - directorio_logs: str (ruta al directorio de logs)
    """
    global _CONFIG_DEFECTO, _DIRECTORIO_LOGS

    if config:
        _CONFIG_DEFECTO.update(config)
        if "directorio_logs" in config:
            _DIRECTORIO_LOGS = Path(config["directorio_logs"])


def get_logger(nombre_modulo: str) -> logging.Logger:
    """
    Obtiene un logger pre-configurado con handlers de consola y archivo.

    Si el logger ya tiene handlers (ya fue configurado), lo retorna tal cual
    para evitar duplicación de mensajes.

    Args:
        nombre_modulo: Nombre del módulo que usa el logger.
                       Se muestra en los mensajes como [nombre_modulo].
                       Ej: "engine", "sql_injection", "crawler"

    Returns:
        Logger de Python configurado con handlers de consola (colorama)
        y archivo (rotativo).

    Ejemplo:
        logger = get_logger("sql_injection")
        logger.info("Iniciando escaneo de inyección SQL...")
        logger.critical("SQLi confirmada en /api/login")
    """
    logger = logging.getLogger(f"sesamo.{nombre_modulo}")

    # Evitar duplicación de handlers si ya fue configurado
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # ─── Handler de Consola (coloreado) ───
    handler_consola = logging.StreamHandler()
    nivel_consola = getattr(
        logging, _CONFIG_DEFECTO["nivel_consola"].upper(), logging.INFO
    )
    handler_consola.setLevel(nivel_consola)
    handler_consola.setFormatter(_FormateadorConsola())
    logger.addHandler(handler_consola)

    # ─── Handler de Archivo (rotativo) ───
    try:
        directorio = _asegurar_directorio_logs()
        fecha = datetime.now().strftime("%Y%m%d")
        ruta_log = directorio / f"sesamo_{fecha}.log"

        max_bytes = _CONFIG_DEFECTO["max_tamano_mb"] * 1024 * 1024
        max_backups = _CONFIG_DEFECTO["max_backups"]

        handler_archivo = RotatingFileHandler(
            filename=str(ruta_log),
            maxBytes=max_bytes,
            backupCount=max_backups,
            encoding="utf-8",
        )
        nivel_archivo = getattr(
            logging, _CONFIG_DEFECTO["nivel_archivo"].upper(), logging.DEBUG
        )
        handler_archivo.setLevel(nivel_archivo)
        handler_archivo.setFormatter(_FormateadorArchivo())
        logger.addHandler(handler_archivo)
    except (OSError, PermissionError) as e:
        # Si no se puede escribir logs a archivo, solo usar consola
        logger.warning(
            f"No se pudo crear el archivo de log: {e}. "
            f"Solo se usará logging de consola."
        )

    return logger
