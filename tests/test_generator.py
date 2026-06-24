"""
tests/test_generator.py — Pruebas unitarias para reportes/generator.py
"""

import pytest
import os
import json
from tempfile import TemporaryDirectory
from pathlib import Path
from core.modelos import ResultadoEscaneo, Hallazgo, Severidad, Confianza, CategoriaOWASP
from reportes.generator import ReportGenerator


def test_generator_json_and_markdown():
    res = ResultadoEscaneo(target_url="http://example.com")
    res.fecha_inicio = "2026-06-18T00:00:00"
    res.fecha_fin = "2026-06-18T00:01:00"
    res.urls_escaneadas = 10
    res.plugins_ejecutados = ["SQLi Scanner"]

    h = Hallazgo(
        plugin_nombre="SQLi Scanner",
        categoria_owasp=CategoriaOWASP.A03_INJECTION,
        severidad=Severidad.CRITICA,
        confianza=Confianza.CONFIRMADA,
        url_afectada="http://example.com/search",
        parametro="q",
        payload_usado="' OR '1'='1",
        evidencia="SQLite3 error",
        cwe_id="CWE-89",
        remediacion="Parametrize queries"
    )
    res.hallazgos.append(h)

    generator = ReportGenerator()
    with TemporaryDirectory() as tmpdir:
        # El nuevo sistema crea: tmpdir/example.com/example.com_2026-06-18.json
        generator.generar(res, formato="json", ruta_salida=tmpdir)
        generator.generar(res, formato="markdown", ruta_salida=tmpdir)

        dominio_dir_candidatos = [d for d in os.listdir(tmpdir) if os.path.isdir(os.path.join(tmpdir, d))]
        assert len(dominio_dir_candidatos) == 1, f"No se encontró directorio: {os.listdir(tmpdir)}"
        dominio_dir = os.path.join(tmpdir, dominio_dir_candidatos[0])

        archivos = os.listdir(dominio_dir)
        json_files = [f for f in archivos if f.endswith(".json")]
        md_files = [f for f in archivos if f.endswith(".md")]
        assert len(json_files) == 1, f"JSON no encontrado en {archivos}"
        assert len(md_files) == 1, f"MD no encontrado en {archivos}"

        json_path = os.path.join(dominio_dir, json_files[0])
        md_path = os.path.join(dominio_dir, md_files[0])

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["metadata"]["target"] == "http://example.com"
            assert len(data["hallazgos"]) == 1
            assert data["hallazgos"][0]["plugin_nombre"] == "SQLi Scanner"

        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "# 🛡️ Sésamo Auditor — Reporte de Seguridad" in content
            assert "http://example.com/search" in content
            assert "CWE-89" in content
            assert "Parametrize queries" in content
