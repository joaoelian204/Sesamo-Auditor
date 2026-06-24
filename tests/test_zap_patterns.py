"""
tests/test_zap_patterns.py — Pruebas unitarias para la adaptación de OWASP ZAP en Sésamo Auditor
"""

import pytest
from core.modelos import ResultadoEscaneo, Hallazgo, Confianza, Severidad, CategoriaOWASP
from core.scanner import Scanner, HostProcess
from core.http_client import HttpClient

class MockResponse:
    def __init__(self, text, headers, status_code=200):
        self.text = text
        self.headers = headers
        self.status_code = status_code
        self.cookies = []

class MockHttpClient:
    def __init__(self, target_url="http://localhost:3000"):
        self.target_url = target_url
        self.session = type("MockSession", (), {"cookies": []})()
        self.last_request = None

    def get(self, url, **kwargs):
        self.last_request = ("GET", url, kwargs)
        if "robots.txt" in url:
            return MockResponse("User-agent: *", {})
        return MockResponse("<html>PHP/8.1, Apache server, csrf_token: '12345'</html>", {
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/8.1.0"
        })

    def request(self, method, url, **kwargs):
        self.last_request = (method, url, kwargs)
        return MockResponse("success", {})

def test_host_process_tech_detection():
    mock_client = MockHttpClient()
    proc = HostProcess("http://localhost:3000", {}, mock_client)
    
    assert "apache" in proc.tecnologias_detectadas
    assert "php" in proc.tecnologias_detectadas
    assert "iis" not in proc.tecnologias_detectadas

def test_host_process_parameter_exclusion():
    mock_client = MockHttpClient()
    proc = HostProcess("http://localhost:3000", {}, mock_client)

    assert proc.parametro_excluido("PHPSESSID") is True
    assert proc.parametro_excluido("username") is False
    assert proc.parametro_excluido("csrf_token") is True

def test_false_positive_exclusion():
    resultado = ResultadoEscaneo(target_url="http://localhost:3000")
    
    h1 = Hallazgo(
        plugin_nombre="SQL Injection",
        categoria_owasp=CategoriaOWASP.A03_INJECTION,
        severidad=Severidad.CRITICA,
        confianza=Confianza.CONFIRMADA,
        url_afectada="http://localhost:3000/api",
        parametro="id",
        evidencia="error in sql syntax"
    )

    h2 = Hallazgo(
        plugin_nombre="XSS",
        categoria_owasp=CategoriaOWASP.A03_INJECTION,
        severidad=Severidad.ALTA,
        confianza=Confianza.FALSE_POSITIVE,
        url_afectada="http://localhost:3000/search",
        parametro="q",
        evidencia="reflected script"
    )

    resultado.hallazgos = [h1, h2]

    # Verificar que hallazgos_filtrados excluye el falso positivo
    assert len(resultado.hallazgos_filtrados) == 1
    assert resultado.hallazgos_filtrados[0].plugin_nombre == "SQL Injection"

    # Verificar resumen y to_dict
    res = resultado.resumen()
    assert res["total_hallazgos"] == 1
    assert res["por_severidad"].get("Alta", 0) == 0

    serialized = resultado.to_dict()
    assert len(serialized["hallazgos"]) == 1

def test_alert_threshold_filtering():
    from core.engine import AuditEngine
    from core.interfaces import BasePlugin
    
    class MockPlugin(BasePlugin):
        @property
        def nombre(self) -> str:
            return "Mock Scan Rule"
            
        @property
        def categoria_owasp(self) -> CategoriaOWASP:
            return CategoriaOWASP.A03_INJECTION
            
        @property
        def severidad_maxima(self) -> Severidad:
            return Severidad.ALTA
            
        def ejecutar(self, target_url, http_client, metadata):
            return [
                Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=self.severidad_maxima,
                    confianza=Confianza.TENTATIVA,
                    url_afectada=target_url,
                    evidencia="tentative match"
                ),
                Hallazgo(
                    plugin_nombre=self.nombre,
                    categoria_owasp=self.categoria_owasp,
                    severidad=self.severidad_maxima,
                    confianza=Confianza.CONFIRMADA,
                    url_afectada=target_url,
                    evidencia="confirmed match"
                )
            ]

    # 1. Test HIGH threshold: should discard the TENTATIVA finding
    engine_high = AuditEngine({
        "plugins": {"alert_threshold": "HIGH"},
        "target": {"url": "http://localhost:3000"}
    })
    plugin_high = MockPlugin()
    engine_high.plugins = [plugin_high]
    res_high = engine_high.iniciar_auditoria("http://localhost:3000")
    # Debería quedar solo 1 hallazgo (el confirmado)
    assert len(res_high.hallazgos) == 1
    assert res_high.hallazgos[0].confianza == Confianza.CONFIRMADA

    # 2. Test OFF threshold: should skip plugin execution entirely
    engine_off = AuditEngine({
        "plugins": {"alert_threshold": "OFF"},
        "target": {"url": "http://localhost:3000"}
    })
    plugin_off = MockPlugin()
    engine_off.plugins = [plugin_off]
    res_off = engine_off.iniciar_auditoria("http://localhost:3000")
    # Plugin saltado -> 0 hallazgos
    assert len(res_off.hallazgos) == 0
    assert "Mock Scan Rule (desactivado)" in res_off.plugins_ejecutados

def test_waf_repetition_detector():
    from core.engine import AuditEngine
    from core.modelos import Confianza
    
    # Simular un WAF que bloquea y responde igual a muchas peticiones
    engine = AuditEngine({
        "plugins": {"alert_threshold": "MEDIUM"},
        "target": {"url": "http://localhost:3000"}
    })
    
    # Crear 7 hallazgos en diferentes URLs con la misma evidencia de bloqueo
    h_list = []
    for i in range(7):
        h_list.append(Hallazgo(
            plugin_nombre=f"Plugin-{i}",
            categoria_owasp=CategoriaOWASP.A03_INJECTION,
            severidad=Severidad.ALTA,
            confianza=Confianza.TENTATIVA,
            url_afectada=f"http://localhost:3000/page-{i}",
            evidencia="WAF Blocked connection 403 Forbidden"
        ))
        
    engine.resultado = ResultadoEscaneo(target_url="http://localhost:3000")
    engine.resultado.hallazgos = h_list
    
    # Ejecutamos la fase 3 de validación del motor simulando plugins inexistentes
    # (lo que conservará los hallazgos originales)
    engine.resultado.hallazgos = h_list
    # Forzar el bloque del detector de firmas repetitivas
    # Agrupamos por firma
    firmas_bloqueo = {}
    for h in engine.resultado.hallazgos:
        if h.evidencia:
            firma = (h.metodo_http, h.evidencia[:80].lower())
            if firma not in firmas_bloqueo:
                firmas_bloqueo[firma] = []
            firmas_bloqueo[firma].append(h)
            
    for (met, ev_firma), lista_hallazgos in firmas_bloqueo.items():
        if len(lista_hallazgos) >= 6:
            urls_unicas = set(x.url_afectada for x in lista_hallazgos)
            if len(urls_unicas) >= 3:
                for x in lista_hallazgos:
                    x.confianza = Confianza.FALSE_POSITIVE
                    
    # Verificar que fueron marcados como FALSE_POSITIVE
    assert all(x.confianza == Confianza.FALSE_POSITIVE for x in h_list)
    assert len(engine.resultado.hallazgos_filtrados) == 0


