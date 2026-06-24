"""
tests/test_modelos.py — Pruebas unitarias para core/modelos.py
"""

import pytest
from datetime import datetime
from core.modelos import Severidad, Confianza, CategoriaOWASP, Hallazgo, ResultadoEscaneo


def test_severidad_comparacion():
    assert Severidad.INFO < Severidad.BAJA
    assert Severidad.BAJA < Severidad.MEDIA
    assert Severidad.MEDIA < Severidad.ALTA
    assert Severidad.ALTA < Severidad.CRITICA
    assert Severidad.CRITICA >= Severidad.ALTA


def test_categoria_owasp_str():
    cat = CategoriaOWASP.A03_INJECTION
    assert "A03:2021" in str(cat)
    assert "Injection" in str(cat)


def test_hallazgo_to_dict():
    hallazgo = Hallazgo(
        plugin_nombre="SQLi Scan",
        categoria_owasp=CategoriaOWASP.A03_INJECTION,
        severidad=Severidad.CRITICA,
        confianza=Confianza.CONFIRMADA,
        url_afectada="http://example.com/login",
        parametro="username",
        metodo_http="POST",
        payload_usado="' OR '1'='1",
        evidencia="syntax error near...",
        cwe_id="CWE-89",
        remediacion="Use parametrized queries",
    )
    d = hallazgo.to_dict()
    assert d["plugin_nombre"] == "SQLi Scan"
    assert d["categoria_owasp"]["codigo"] == "A03:2021"
    assert d["severidad"]["etiqueta"] == "Crítica"
    assert d["confianza"]["etiqueta"] == "Confirmada"
    assert d["url_afectada"] == "http://example.com/login"
    assert d["parametro"] == "username"
    assert d["metodo_http"] == "POST"
    assert d["payload_usado"] == "' OR '1'='1"
    assert d["cwe_id"] == "CWE-89"


def test_resultado_escaneo_calculos():
    res = ResultadoEscaneo(target_url="http://example.com")
    assert res.duracion == "En progreso..."

    h1 = Hallazgo(
        plugin_nombre="P1",
        categoria_owasp=CategoriaOWASP.A03_INJECTION,
        severidad=Severidad.ALTA,
        confianza=Confianza.FIRME,
        url_afectada="http://example.com/x",
        cwe_id="CWE-89"
    )
    h2 = Hallazgo(
        plugin_nombre="P2",
        categoria_owasp=CategoriaOWASP.A05_SECURITY_MISCONFIGURATION,
        severidad=Severidad.BAJA,
        confianza=Confianza.TENTATIVA,
        url_afectada="http://example.com/y",
        cwe_id="CWE-523"
    )

    res.hallazgos.extend([h1, h2])
    assert len(res.por_severidad(Severidad.ALTA)) == 1
    assert len(res.por_categoria(CategoriaOWASP.A03_INJECTION)) == 1

    # Score: Alta (10) + Baja (2) = 12
    assert res.score_riesgo() == 12

    # Test finalización y duración
    res.fecha_inicio = "2026-06-18T00:00:00"
    res.fecha_fin = "2026-06-18T01:05:10"
    assert res.duracion == "01:05:10"

    summary = res.resumen()
    assert summary["score_riesgo"] == 12
    assert summary["por_severidad"]["Alta"] == 1
    assert summary["por_severidad"]["Baja"] == 1


def test_resultado_escaneo_deduplicar():
    res = ResultadoEscaneo(target_url="http://example.com")
    h1 = Hallazgo(
        plugin_nombre="P1",
        categoria_owasp=CategoriaOWASP.A03_INJECTION,
        severidad=Severidad.ALTA,
        confianza=Confianza.CONFIRMADA,
        url_afectada="http://example.com/login",
        parametro="id",
        evidencia="sql error",
        cwe_id="CWE-89"
    )
    # Totalmente idéntico según clave_deduplicacion
    h2 = Hallazgo(
        plugin_nombre="P1",
        categoria_owasp=CategoriaOWASP.A03_INJECTION,
        severidad=Severidad.ALTA,
        confianza=Confianza.CONFIRMADA,
        url_afectada="http://example.com/login",
        parametro="id",
        evidencia="sql error",
        cwe_id="CWE-89"
    )
    res.hallazgos.extend([h1, h2])
    res.deduplicar()
    assert len(res.hallazgos) == 1
    assert res.hallazgos[0].severidad == Severidad.ALTA

