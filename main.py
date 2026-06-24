#!/usr/bin/env python3
"""
main.py — Punto de Entrada de Sésamo Auditor

CLI interactivo que permite al usuario:
1. Configurar el target URL
2. Elegir qué tipo de plugins ejecutar (DAST, SAST, ambos)
3. Seleccionar el formato de reporte (JSON, Markdown, PDF, Dashboard, todos)
4. Iniciar la auditoría de seguridad

Uso:
    python main.py                          # Modo interactivo
    python main.py --target http://target   # Especificar target directo
    python main.py --config config.json     # Usar config personalizada
"""

import argparse
import json
import sys
from pathlib import Path

from core.engine import AuditEngine
from core.logger import configurar_logging, get_logger
from reportes.generator import ReportGenerator

logger = get_logger("main")


def cargar_config(ruta_config: str = "config.json") -> dict:
    """
    Carga la configuración desde un archivo JSON.

    Args:
        ruta_config: Ruta al archivo de configuración.

    Returns:
        Diccionario de configuración.
    """
    ruta = Path(ruta_config)
    if not ruta.exists():
        logger.warning(f"Archivo de configuración '{ruta_config}' no encontrado. Usando valores por defecto.")
        return {
            "target": {"url": "", "exclusiones": []},
            "crawler": {"max_depth": 10, "max_urls": 500, "respetar_scope": True},
            "http_client": {"timeout_segundos": 10, "rate_limit_delay": 0.5},
            "plugins": {"habilitar_dast": True, "habilitar_sast": True, "excluir": []},
            "reportes": {"formato": "all", "ruta_salida": "./reportes_output/"},
            "logging": {"nivel_consola": "INFO", "nivel_archivo": "DEBUG"},
        }

    with open(ruta, "r", encoding="utf-8") as f:
        config = json.load(f)

    logger.info(f"Configuración cargada desde: {ruta_config}")
    return config


def menu_interactivo(config: dict) -> dict:
    """
    Muestra un menú interactivo para configurar la auditoría.

    Args:
        config: Configuración base a modificar.

    Returns:
        Configuración actualizada con las elecciones del usuario.
    """
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║       🛡️  SÉSAMO AUDITOR v1.0                   ║")
    print("║       Framework DAST/SAST Reutilizable          ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    # 1. Target URL
    target_actual = config.get("target", {}).get("url", "")
    if target_actual:
        print(f"  Target actual: {target_actual}")
        cambiar = input("  ¿Cambiar target? (s/N): ").strip().lower()
        if cambiar == "s":
            target_actual = input("  Nueva URL del target: ").strip()
    else:
        target_actual = input("  URL del target a auditar: ").strip()

    if not target_actual:
        print("  ❌ Debes proporcionar una URL de target.")
        sys.exit(1)

    config.setdefault("target", {})["url"] = target_actual

    # 2. Tipo de plugins
    print()
    print("  ¿Qué tipo de pruebas ejecutar?")
    print("    1. DAST + SAST (completo)")
    print("    2. Solo DAST (pruebas activas)")
    print("    3. Solo SAST (análisis pasivo)")
    tipo_prueba = input("  Elige [1/2/3] (default: 1): ").strip() or "1"

    solo_dast = tipo_prueba == "2"
    solo_sast = tipo_prueba == "3"

    # 3. Formato de reporte
    print()
    print("  ¿En qué formato generar el reporte?")
    print("    1. Todos (JSON + Markdown + PDF)")
    print("    2. JSON")
    print("    3. Markdown")
    print("    4. PDF")
    print("    5. Dashboard Web (servidor local)")
    formato_opcion = input("  Elige [1/2/3/4/5] (default: 1): ").strip() or "1"

    formatos = {"1": "all", "2": "json", "3": "markdown", "4": "pdf", "5": "dashboard"}
    formato = formatos.get(formato_opcion, "all")
    config.setdefault("reportes", {})["formato"] = formato

    print()
    print("  ═══ Configuración Confirmada ═══")
    print(f"  Target:   {target_actual}")
    print(f"  Pruebas:  {'DAST + SAST' if not solo_dast and not solo_sast else 'Solo DAST' if solo_dast else 'Solo SAST'}")
    print(f"  Reporte:  {formato.upper()}")
    print()

    confirmar = input("  ¿Iniciar auditoría? (S/n): ").strip().lower()
    if confirmar == "n":
        print("  Auditoría cancelada.")
        sys.exit(0)

    return config, solo_dast, solo_sast


def main():
    """Punto de entrada principal de la aplicación."""
    # Parsear argumentos CLI
    parser = argparse.ArgumentParser(
        description="🛡️ Sésamo Auditor — Framework DAST/SAST Reutilizable",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", "-t", help="URL del target a auditar")
    parser.add_argument("--config", "-c", default="config.json", help="Ruta al archivo de configuración")
    parser.add_argument("--formato", "-f", choices=["json", "markdown", "pdf", "dashboard", "all"], default=None, help="Formato de reporte")
    parser.add_argument("--solo-dast", action="store_true", help="Solo ejecutar plugins DAST")
    parser.add_argument("--solo-sast", action="store_true", help="Solo ejecutar plugins SAST")
    parser.add_argument("--output", "-o", default=None, help="Ruta de salida para el reporte")

    args = parser.parse_args()

    # Cargar configuración
    config = cargar_config(args.config)

    # Configurar logging
    configurar_logging(config.get("logging", {}))

    # Determinar modo de ejecución
    if args.target:
        # Modo CLI directo
        config.setdefault("target", {})["url"] = args.target
        solo_dast = args.solo_dast
        solo_sast = args.solo_sast
        if args.formato:
            config.setdefault("reportes", {})["formato"] = args.formato
        if args.output:
            config.setdefault("reportes", {})["ruta_salida"] = args.output
    else:
        # Modo interactivo
        config, solo_dast, solo_sast = menu_interactivo(config)

    target_url = config["target"]["url"]
    formato = config.get("reportes", {}).get("formato", "all")
    ruta_salida = config.get("reportes", {}).get("ruta_salida", "./reportes_output/")

    # ─── Ejecutar Auditoría ───
    engine = AuditEngine(config)

    try:
        resultado = engine.iniciar_auditoria(
            target_url=target_url,
            solo_dast=solo_dast,
            solo_sast=solo_sast,
        )

        # ─── Generar Reportes ───
        generator = ReportGenerator()
        generator.generar(resultado, formato=formato, ruta_salida=ruta_salida)

    except KeyboardInterrupt:
        logger.warning("Auditoría interrumpida por el usuario.")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Error fatal: {e}")
        raise
    finally:
        engine.cerrar()


if __name__ == "__main__":
    main()
