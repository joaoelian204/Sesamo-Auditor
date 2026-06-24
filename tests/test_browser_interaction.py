"""
tests/test_browser_interaction.py — Pruebas unitarias para core/browser_interaction.py
y la validación dinámica de XSS.
"""

import pytest
from unittest.mock import MagicMock, patch
from core.browser_interaction import BrowserInteractionHelper
from plugins.dast.xss_scanner import XSSPlugin
from core.modelos import Severidad, Confianza, Hallazgo, CategoriaOWASP


def test_browser_helper_disabled_if_playwright_missing():
    with patch("core.browser_interaction.PLAYWRIGHT_DISPONIBLE", False):
        helper = BrowserInteractionHelper()
        assert helper.iniciar() is False


@patch("core.browser_interaction.PLAYWRIGHT_DISPONIBLE", True)
def test_browser_helper_lifecycle():
    import sys
    from unittest.mock import MagicMock

    mock_sync_api = MagicMock()
    mock_sync_pw = MagicMock()
    mock_pw = MagicMock()
    mock_browser = MagicMock()
    mock_context = MagicMock()
    mock_page = MagicMock()

    mock_sync_api.sync_playwright = mock_sync_pw
    mock_sync_pw.return_value.start.return_value = mock_pw
    mock_pw.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    with patch.dict("sys.modules", {"playwright.sync_api": mock_sync_api}):
        import core.browser_interaction
        # Manually attach mock functions to bypass ImportError gaps
        core.browser_interaction.sync_playwright = mock_sync_pw
        helper = BrowserInteractionHelper(headless=True)
        
        assert helper.iniciar() is True
        assert helper.obtener_pagina() is not None

        # Test execution
        helper.interactuar_formulario(
            url="http://localhost:3000/login",
            campos_input={"username": "<script>alert(1)</script>"},
            submit_selector="#submit"
        )

        helper.cerrar()
        mock_browser.close.assert_called_once()
        mock_pw.stop.assert_called_once()


def test_xss_validation_passes_with_browser_logs():
    plugin = XSSPlugin()
    h = Hallazgo(
        plugin_nombre=plugin.nombre,
        categoria_owasp=plugin.categoria_owasp,
        severidad=Severidad.ALTA,
        confianza=Confianza.FIRME,
        url_afectada="http://localhost:3000/search",
        parametro="q",
        metodo_http="GET",
        payload_usado="<script>console.log('sesamo_xss_test')</script>"
    )

    mock_helper = MagicMock()
    mock_helper.interactuar_formulario.return_value = True
    # Simulate finding our canary in the console logs
    mock_helper.consola_logs = [
        {"tipo": "log", "texto": "Canary reflection: sesamo_xss_test", "location": {}}
    ]

    valid = plugin.validar_hallazgo(h, http_client=None, browser_helper=mock_helper)
    assert valid is True
    assert h.confianza == Confianza.CONFIRMADA


def test_xss_validation_skips_when_no_execution():
    plugin = XSSPlugin()
    h = Hallazgo(
        plugin_nombre=plugin.nombre,
        categoria_owasp=plugin.categoria_owasp,
        severidad=Severidad.ALTA,
        confianza=Confianza.FIRME,
        url_afectada="http://localhost:3000/search",
        parametro="q",
        metodo_http="GET",
        payload_usado="<script>alert(1)</script>"
    )

    mock_helper = MagicMock()
    mock_helper.interactuar_formulario.return_value = True
    mock_helper.consola_logs = [] # No console logs at all

    valid = plugin.validar_hallazgo(h, http_client=None, browser_helper=mock_helper)
    assert valid is False
