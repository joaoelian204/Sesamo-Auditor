"""
reportes/generator.py — Motor de Reportes Multi-Formato

Soporta JSON, Markdown, PDF y Dashboard.
Los archivos se nombran como: {dominio}_{fecha}.{ext}
Se agrupan en carpetas por dominio. Si se re-escannea el mismo
dominio, se sobreescribe el reporte (siempre el más reciente).
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path

import requests

from core.logger import get_logger
from core.modelos import ResultadoEscaneo, Severidad

logger = get_logger("reportes")


def _nombre_pagina(target_url: str) -> str:
    try:
        resp = requests.get(target_url, timeout=5, headers={"User-Agent": "SesamoAuditor/1.0"})
        if resp.status_code == 200:
            match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE)
            if match:
                titulo = match.group(1).strip()
                titulo = re.sub(r"[^\w\s]", "", titulo).strip()
                if titulo:
                    return titulo[:50]
    except Exception:
        pass
    dominio = re.sub(r"https?://", "", target_url).rstrip("/").replace("/", "_").replace(":", "_")
    return dominio


def _sanitizar(nombre: str) -> str:
    return re.sub(r"[^\w\s\-]", "", nombre).strip().replace(" ", "_")[:50]


def _nombre_base(target_url: str) -> str:
    pagina = _sanitizar(_nombre_pagina(target_url))
    fecha = datetime.now().strftime("%Y-%m-%d")
    return f"{pagina}_{fecha}"


def _directorio_dominio(target_url: str, base: str) -> Path:
    pagina = _sanitizar(_nombre_pagina(target_url))
    dir_path = Path(base) / pagina
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


class ReportGenerator:

    def generar(
        self,
        resultado: ResultadoEscaneo,
        formato: str = "json",
        ruta_salida: str = "./reportes_output/",
    ) -> str | None:
        match formato.lower():
            case "json":
                return self._exportar_json(resultado, ruta_salida)
            case "markdown" | "md":
                return self._exportar_markdown(resultado, ruta_salida)
            case "pdf":
                return self._exportar_pdf(resultado, ruta_salida)
            case "dashboard":
                return self._lanzar_dashboard(resultado)
            case "all":
                return self._exportar_todos(resultado, ruta_salida)
            case _:
                logger.error(f"Formato de reporte no soportado: {formato}")
                return None

    def _asegurar_directorio(self, ruta: str) -> Path:
        directorio = Path(ruta)
        if directorio.suffix:
            directorio = directorio.parent
        directorio.mkdir(parents=True, exist_ok=True)
        return directorio

    # ─── JSON ───

    def _exportar_json(self, resultado: ResultadoEscaneo, ruta: str) -> str:
        directorio = _directorio_dominio(resultado.target_url, ruta)
        nombre = _nombre_base(resultado.target_url)
        ruta_archivo = str(directorio / f"{nombre}.json")

        resumen = resultado.resumen()
        datos = {
            "metadata": {
                "tool": "Sésamo Auditor v1.0",
                "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": resultado.target_url,
                "duracion": resumen["duracion"],
            },
            "resumen": {
                "score_riesgo": resumen["score_riesgo"],
                "total_hallazgos": resumen["total_hallazgos"],
                "urls_escaneadas": resumen["urls_escaneadas"],
                "plugins_ejecutados": resumen["plugins_ejecutados"],
                "por_severidad": resumen["por_severidad"],
            },
            "hallazgos": [h.to_dict() for h in resultado.hallazgos_filtrados],
            "plugins": resultado.plugins_ejecutados,
        }

        with open(ruta_archivo, "w", encoding="utf-8") as f:
            json.dump(datos, f, ensure_ascii=False, indent=2)

        logger.info(f"📄 Reporte JSON generado: {ruta_archivo}")
        return ruta_archivo

    # ─── Markdown ───

    def _exportar_markdown(self, resultado: ResultadoEscaneo, ruta: str) -> str:
        directorio = _directorio_dominio(resultado.target_url, ruta)
        nombre = _nombre_base(resultado.target_url)
        ruta_archivo = str(directorio / f"{nombre}.md")

        resumen = resultado.resumen()
        md = []

        md.append(f"""# 🛡️ Sésamo Auditor — Reporte de Seguridad

**Target:** `{resultado.target_url}`
**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Duración:** {resumen['duracion']}
**Score de Riesgo:** {resumen['score_riesgo']}/100
**Total Hallazgos:** {resumen['total_hallazgos']}

## 📊 Resumen por Severidad

""")

        for sev in reversed(list(Severidad)):
            c = resumen["por_severidad"].get(sev.etiqueta, 0)
            if c > 0:
                md.append(f"  {sev.icono}  {sev.etiqueta}: {c}")

        md.append(f"""
  ─────────────────────
  🔌  Plugins: {resumen['plugins_ejecutados']}  |  🌐  URLs: {resumen['urls_escaneadas']}

---

## 🔍 Hallazgos

""")

        for sev in reversed(list(Severidad)):
            hallazgos_sev = resultado.por_severidad(sev)
            if not hallazgos_sev:
                continue

            md.append(f"""### {sev.icono} {sev.etiqueta} — {len(hallazgos_sev)} hallazgo(s)

""")

            for i, h in enumerate(hallazgos_sev, 1):
                payload_line = f"  💥 Payload: `{h.payload_usado}`" if h.payload_usado else ""
                cwe_str = h.cwe_id if h.cwe_id else "—"

                md.append(f"""{'─' * 50}
  #{i}  [{h.severidad.etiqueta.upper()}] {h.plugin_nombre}

  📍 URL:       {h.url_afectada}
  📍 Parámetro: {h.parametro}
  📍 Método:    {h.metodo_http}
  🏷️ OWASP:    {h.categoria_owasp}
  🏷️ CWE:      {cwe_str}
  ✅ Confianza: {h.confianza.etiqueta}
{payload_line}

  📋 Evidencia:
  {h.evidencia}

  💡 Solución:
  {h.remediacion}

""")

        md.append(f"""
---

## 🔌 Plugins Utilizados ({len(resultado.plugins_ejecutados)})

""")
        for p in sorted(set(resultado.plugins_ejecutados)):
            md.append(f"  • {p}")

        md.append("""
---

*Generado por Sésamo Auditor v1.0*
""")

        with open(ruta_archivo, "w", encoding="utf-8") as f:
            f.write("\n".join(md))

        logger.info(f"📄 Reporte Markdown generado: {ruta_archivo}")
        return ruta_archivo

    # ─── PDF ───

    def _exportar_pdf(self, resultado: ResultadoEscaneo, ruta: str) -> str:
        directorio = _directorio_dominio(resultado.target_url, ruta)
        nombre = _nombre_base(resultado.target_url)
        ruta_archivo = str(directorio / f"{nombre}.pdf")

        try:
            from reportes.pdf_exporter import PDFExporter
            exporter = PDFExporter()
            exporter.generar_pdf(resultado, ruta_archivo)
        except ImportError as e:
            logger.error(f"Error al importar PDFExporter: {e}")
        except Exception as e:
            logger.error(f"Error al generar PDF: {e}")

        return ruta_archivo

    # ─── Dashboard ───

    def _lanzar_dashboard(self, resultado: ResultadoEscaneo) -> None:
        for idx, h in enumerate(resultado.hallazgos):
            h.global_idx = idx
        try:
            from dashboard.app import crear_app
            app = crear_app(resultado)
            logger.info("🌐 Dashboard web iniciándose en http://127.0.0.1:5000")
            app.run(host="127.0.0.1", port=5000, debug=False)
        except ImportError as e:
            logger.error(f"Error al importar dashboard: {e}")
        except Exception as e:
            logger.error(f"Error al lanzar dashboard: {e}")
        return None

    # ─── Todos los formatos ───

    def _exportar_todos(self, resultado: ResultadoEscaneo, ruta_base: str) -> str:
        directorio = _directorio_dominio(resultado.target_url, ruta_base)
        self._exportar_json(resultado, ruta_base)
        self._exportar_markdown(resultado, ruta_base)
        self._exportar_pdf(resultado, ruta_base)
        logger.info(f"📦 Todos los reportes generados en: {directorio}")
        return str(directorio)
