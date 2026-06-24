"""
tests/test_sql_injection.py — Pruebas unitarias para plugins/dast/sql_injection.py
"""

import pytest
from unittest.mock import MagicMock, patch, call
from plugins.dast.sql_injection import SQLInjectionPlugin
from core.modelos import Severidad, Confianza, CategoriaOWASP, Hallazgo


def test_sql_injection_metadata():
    plugin = SQLInjectionPlugin()
    assert plugin.nombre == "SQL Injection Scanner"
    assert plugin.categoria_owasp == CategoriaOWASP.A03_INJECTION
    assert plugin.severidad_maxima == Severidad.CRITICA


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_sql_injection_ejecutar_error_based(mock_cargar_payloads):
    # Setup payloads and database error signatures
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' OR '1'='1"],
        "sqli_error_signatures.txt": ["sqlite:syntax error near", "mysql:you have an error in your sql syntax"]
    }[filename]

    plugin = SQLInjectionPlugin()

    # Mock HttpClient response returning SQL error
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "you have an error in your SQL syntax; check the manual..."
    mock_client.post.return_value = mock_response

    metadata = {
        "formularios": [
            {
                "url_pagina": "http://localhost:3000/login",
                "action": "/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"}
                ]
            }
        ],
        "urls_descubiertas": []
    }

    hallazgos = plugin.ejecutar("http://localhost:3000", mock_client, metadata)
    assert len(hallazgos) == 2
    assert hallazgos[0].parametro == "username"
    assert hallazgos[0].payload_usado == "' OR '1'='1"
    assert "mysql" in hallazgos[0].evidencia.lower()


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_sql_injection_validation_passes(mock_cargar_payloads):
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' OR '1'='1"],
        "sqli_error_signatures.txt": ["sqlite:syntax error near"]
    }[filename]

    plugin = SQLInjectionPlugin()
    # Force load signatures
    plugin._firmas = plugin._cargar_firmas()

    mock_client = MagicMock()
    mock_response_err = MagicMock()
    mock_response_err.text = "SQLite3::SQLException: syntax error near..."
    mock_response_clean = MagicMock()
    mock_response_clean.text = "Login successful or normal page content"
    mock_client.post.side_effect = [mock_response_err, mock_response_clean]

    h = Hallazgo(
        plugin_nombre=plugin.nombre,
        categoria_owasp=plugin.categoria_owasp,
        severidad=Severidad.CRITICA,
        confianza=Confianza.FIRME,
        url_afectada="http://localhost:3000/login",
        parametro="username",
        metodo_http="POST",
        payload_usado="' OR '1'='1"
    )

    valid = plugin.validar_hallazgo(h, mock_client)
    assert valid is True
    assert h.confianza == Confianza.CONFIRMADA


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_query_string_baseline_skips_500(mock_cargar_payloads):
    """Endpoints que devuelven 500 con valor normal se omiten (no son SQLi)."""
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' OR 1=1 --"],
        "sqli_error_signatures.txt": []
    }[filename]

    plugin = SQLInjectionPlugin()
    plugin._payloads = ["' OR 1=1 --"]
    plugin._firmas = {}

    mock_client = MagicMock()
    mock_response_500 = MagicMock()
    mock_response_500.status_code = 500
    mock_response_500.text = "Unexpected path: /rest/products"
    mock_response_500.content = b"Unexpected path: /rest/products"
    mock_response_500.elapsed = MagicMock()
    mock_response_500.elapsed.total_seconds.return_value = 0.05
    mock_client.get.return_value = mock_response_500

    hallazgos = plugin._probar_query_string(
        "http://localhost:3000/rest/products?id=1",
        mock_client
    )
    assert len(hallazgos) == 0


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_query_string_baseline_skips_401(mock_cargar_payloads):
    """Endpoints que requieren auth (401) se omiten."""
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' OR 1=1 --"],
        "sqli_error_signatures.txt": []
    }[filename]

    plugin = SQLInjectionPlugin()
    plugin._payloads = ["' OR 1=1 --"]
    plugin._firmas = {}

    mock_client = MagicMock()
    mock_response_401 = MagicMock()
    mock_response_401.status_code = 401
    mock_response_401.text = "Unauthorized"
    mock_response_401.content = b"Unauthorized"
    mock_response_401.elapsed = MagicMock()
    mock_response_401.elapsed.total_seconds.return_value = 0.01
    mock_client.get.return_value = mock_response_401

    hallazgos = plugin._probar_query_string(
        "http://localhost:3000/api/Complaints?id=1",
        mock_client
    )
    assert len(hallazgos) == 0


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_query_string_error_based_with_baseline(mock_cargar_payloads):
    """Detecta SQLi error-based solo cuando el baseline NO tiene la firma."""
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' OR 1=1 --"],
        "sqli_error_signatures.txt": ["sqlite:SQLITE_ERROR"]
    }[filename]

    plugin = SQLInjectionPlugin()
    plugin._payloads = ["' OR 1=1 --"]
    plugin._firmas = {"sqlite": ["SQLITE_ERROR"]}

    mock_client = MagicMock()

    # Baseline: respuesta limpia (200, sin firma de error)
    mock_baseline = MagicMock()
    mock_baseline.status_code = 200
    mock_baseline.text = '{"data": []}'
    mock_baseline.content = b'{"data": []}'
    mock_baseline.elapsed = MagicMock()
    mock_baseline.elapsed.total_seconds.return_value = 0.05

    # Payload: respuesta con firma de error SQL
    mock_payload_resp = MagicMock()
    mock_payload_resp.status_code = 500
    mock_payload_resp.text = "SQLITE_ERROR: near \"'\": syntax error"
    mock_payload_resp.content = b"SQLITE_ERROR: near \"'\": syntax error"
    mock_payload_resp.elapsed = MagicMock()
    mock_payload_resp.elapsed.total_seconds.return_value = 0.06

    mock_client.get.side_effect = [mock_baseline, mock_payload_resp]

    hallazgos = plugin._probar_query_string(
        "http://localhost:3000/rest/products/search?q=test",
        mock_client
    )
    assert len(hallazgos) == 1
    assert hallazgos[0].severidad == Severidad.CRITICA
    assert "SQLITE" in hallazgos[0].evidencia.upper()


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_query_string_time_based_detection(mock_cargar_payloads):
    """Detecta time-based SQLi cuando delta > 2.5s vs baseline."""
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' AND SLEEP(3) --"],
        "sqli_error_signatures.txt": []
    }[filename]

    plugin = SQLInjectionPlugin()
    plugin._payloads = ["' AND SLEEP(3) --"]
    plugin._firmas = {}

    mock_client = MagicMock()

    # Baseline: respuesta rápida
    mock_baseline = MagicMock()
    mock_baseline.status_code = 200
    mock_baseline.text = '{"data": []}'
    mock_baseline.content = b'{"data": []}'
    mock_baseline.elapsed = MagicMock()
    mock_baseline.elapsed.total_seconds.return_value = 0.05

    # SLEEP payload: respuesta lenta (3.1s)
    mock_sleep_resp = MagicMock()
    mock_sleep_resp.status_code = 200
    mock_sleep_resp.text = '{"data": []}'
    mock_sleep_resp.content = b'{"data": []}'
    mock_sleep_resp.elapsed = MagicMock()
    mock_sleep_resp.elapsed.total_seconds.return_value = 3.1

    mock_client.get.side_effect = [mock_baseline, mock_sleep_resp]

    hallazgos = plugin._probar_query_string(
        "http://localhost:3000/rest/products/search?q=test",
        mock_client
    )
    assert len(hallazgos) == 1
    assert "time-based" in hallazgos[0].evidencia.lower()
    assert hallazgos[0].severidad == Severidad.CRITICA


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_query_string_time_based_no_false_positive(mock_cargar_payloads):
    """No reporta time-based cuando delta < 2.5s (era el bug del retry)."""
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' AND SLEEP(3) --"],
        "sqli_error_signatures.txt": []
    }[filename]

    plugin = SQLInjectionPlugin()
    plugin._payloads = ["' AND SLEEP(3) --"]
    plugin._firmas = {}

    mock_client = MagicMock()

    # Baseline: 0.05s
    mock_baseline = MagicMock()
    mock_baseline.status_code = 200
    mock_baseline.text = '{"data": []}'
    mock_baseline.content = b'{"data": []}'
    mock_baseline.elapsed = MagicMock()
    mock_baseline.elapsed.total_seconds.return_value = 0.05

    # SLEEP payload: solo 0.07s (no ejecutó el SLEEP)
    mock_sleep_resp = MagicMock()
    mock_sleep_resp.status_code = 200
    mock_sleep_resp.text = '{"data": []}'
    mock_sleep_resp.content = b'{"data": []}'
    mock_sleep_resp.elapsed = MagicMock()
    mock_sleep_resp.elapsed.total_seconds.return_value = 0.07

    mock_client.get.side_effect = [mock_baseline, mock_sleep_resp]

    hallazgos = plugin._probar_query_string(
        "http://localhost:3000/rest/products/search?q=test",
        mock_client
    )
    assert len(hallazgos) == 0


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_query_string_boolean_based_detection(mock_cargar_payloads):
    """Detecta boolean-based cuando AND 1=1 y AND 1=2 difieren significativamente."""
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' AND 1=1 --", "' AND 1=2 --"],
        "sqli_error_signatures.txt": []
    }[filename]

    plugin = SQLInjectionPlugin()
    plugin._payloads = ["' AND 1=1 --", "' AND 1=2 --"]
    plugin._firmas = {}

    mock_client = MagicMock()

    # Baseline
    mock_baseline = MagicMock()
    mock_baseline.status_code = 200
    mock_baseline.text = '{"data": [{"id": 1, "name": "Apple Juice", "description": "Super long description to ensure difference is greater than 50 bytes"}]}'
    mock_baseline.content = b'{"data": [{"id": 1, "name": "Apple Juice", "description": "Super long description to ensure difference is greater than 50 bytes"}]}'
    mock_baseline.elapsed = MagicMock()
    mock_baseline.elapsed.total_seconds.return_value = 0.05

    # AND 1=1 → devuelve datos (similar a baseline)
    mock_true = MagicMock()
    mock_true.status_code = 200
    mock_true.text = '{"data": [{"id": 1, "name": "Apple Juice", "description": "Super long description to ensure difference is greater than 50 bytes"}]}'
    mock_true.content = b'{"data": [{"id": 1, "name": "Apple Juice", "description": "Super long description to ensure difference is greater than 50 bytes"}]}'
    mock_true.elapsed = MagicMock()
    mock_true.elapsed.total_seconds.return_value = 0.06

    # AND 1=2 → devuelve vacío (diferencia > 50 bytes)
    mock_false = MagicMock()
    mock_false.status_code = 200
    mock_false.text = '{"data": []}'
    mock_false.content = b'{"data": []}'
    mock_false.elapsed = MagicMock()
    mock_false.elapsed.total_seconds.return_value = 0.05

    mock_client.get.side_effect = [mock_baseline, mock_true, mock_false]

    hallazgos = plugin._probar_query_string(
        "http://localhost:3000/rest/products/search?q=test",
        mock_client
    )
    assert len(hallazgos) == 1
    assert "boolean-based" in hallazgos[0].evidencia.lower()
    assert hallazgos[0].severidad == Severidad.ALTA
    assert hallazgos[0].confianza == Confianza.TENTATIVA


@patch.object(SQLInjectionPlugin, "cargar_payloads")
def test_error_based_ignores_baseline_with_same_firma(mock_cargar_payloads):
    """No reporta error-based si el baseline ya contiene la misma firma de error."""
    mock_cargar_payloads.side_effect = lambda filename: {
        "sqli_payloads.txt": ["' OR 1=1 --"],
        "sqli_error_signatures.txt": ["generic:internal server error"]
    }[filename]

    plugin = SQLInjectionPlugin()
    plugin._payloads = ["' OR 1=1 --"]
    plugin._firmas = {"generic": ["internal server error"]}

    mock_client = MagicMock()

    # Baseline: ya contiene "internal server error"
    mock_baseline = MagicMock()
    mock_baseline.status_code = 200
    mock_baseline.text = "Error: internal server error occurred"
    mock_baseline.content = b"Error: internal server error occurred"
    mock_baseline.elapsed = MagicMock()
    mock_baseline.elapsed.total_seconds.return_value = 0.05

    # Payload: misma firma
    mock_payload = MagicMock()
    mock_payload.status_code = 200
    mock_payload.text = "Error: internal server error occurred"
    mock_payload.content = b"Error: internal server error occurred"
    mock_payload.elapsed = MagicMock()
    mock_payload.elapsed.total_seconds.return_value = 0.06

    mock_client.get.side_effect = [mock_baseline, mock_payload]

    hallazgos = plugin._probar_query_string(
        "http://localhost:3000/api/test?q=test",
        mock_client
    )
    assert len(hallazgos) == 0
