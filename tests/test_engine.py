"""
tests/test_engine.py — Pruebas unitarias para core/engine.py
"""

import pytest
from unittest.mock import MagicMock, patch
from core.engine import AuditEngine
from core.interfaces import BasePlugin
from core.modelos import CategoriaOWASP, Severidad, Confianza, Hallazgo


class MockTestPlugin(BasePlugin):
    @property
    def nombre(self) -> str:
        return "Mock Test Plugin"

    @property
    def categoria_owasp(self) -> CategoriaOWASP:
        return CategoriaOWASP.A01_BROKEN_ACCESS_CONTROL

    @property
    def severidad_maxima(self) -> Severidad:
        return Severidad.MEDIA

    def ejecutar(self, target_url, http_client, metadata):
        return [
            Hallazgo(
                plugin_nombre=self.nombre,
                categoria_owasp=self.categoria_owasp,
                severidad=Severidad.MEDIA,
                confianza=Confianza.CONFIRMADA,
                url_afectada=f"{target_url}/vulnerable",
                cwe_id="CWE-200"
            )
        ]

    def validar_hallazgo(self, hallazgo, http_client) -> bool:
        return True


def test_engine_cargar_y_ejecutar():
    config = {
        "http_client": {"rate_limit_delay": 0},
        "crawler": {"max_depth": 1, "max_urls": 5},
        "plugins": {"habilitar_dast": True, "habilitar_sast": True}
    }
    
    engine = AuditEngine(config)
    
    # Mocking crawler
    mock_metadata = MagicMock()
    mock_metadata.urls_descubiertas = {"http://localhost:3000"}
    mock_metadata.to_dict.return_value = {
        "urls_descubiertas": ["http://localhost:3000"],
        "formularios": [],
        "endpoints_api": [],
        "archivos_js": [],
    }
    engine.crawler.rastrear = MagicMock(return_value=mock_metadata)
    
    # Direct injection of our test plugin to bypass filesystem scanning
    plugin_instance = MockTestPlugin()
    engine.plugins = [plugin_instance]
    
    res = engine.iniciar_auditoria("http://localhost:3000")
    
    assert res is not None
    assert res.target_url == "http://localhost:3000"
    assert len(res.hallazgos) == 1
    assert res.hallazgos[0].plugin_nombre == "Mock Test Plugin"
    assert res.hallazgos[0].severidad == Severidad.MEDIA
    assert res.score_riesgo() == 5
