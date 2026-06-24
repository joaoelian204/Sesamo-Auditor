"""
tests/test_crawler.py — Pruebas unitarias para core/crawler.py
"""

import pytest
from bs4 import BeautifulSoup
from unittest.mock import MagicMock, patch
from core.crawler import Crawler, FormularioDescubierto, MetadataCrawl


def test_form_serialization():
    form = FormularioDescubierto(
        url_pagina="http://example.com",
        action="http://example.com/submit",
        method="POST",
        inputs=[{"name": "username", "type": "text"}]
    )
    d = form.to_dict()
    assert d["action"] == "http://example.com/submit"
    assert d["inputs"][0]["name"] == "username"


def test_metadata_crawl():
    m = MetadataCrawl()
    m.urls_descubiertas.add("http://example.com/a")
    m.archivos_js.append("http://example.com/main.js")
    m.robots_txt = "User-agent: *\nDisallow: /admin"
    
    d = m.to_dict()
    assert "http://example.com/a" in d["urls_descubiertas"]
    assert "http://example.com/main.js" in d["archivos_js"]
    assert d["robots_txt"] is not None
    assert "URLs:" in m.resumen()


def test_crawler_robots_txt():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "text/plain"}
    mock_response.text = "User-agent: *"
    mock_client.get.return_value = mock_response

    crawler = Crawler(mock_client)
    res = crawler._obtener_robots_txt("http://example.com")
    assert res == "User-agent: *"
    mock_client.get.assert_called_with("http://example.com/robots.txt")


def test_extraer_links():
    mock_client = MagicMock()
    crawler = Crawler(mock_client, {"respetar_scope": True})
    html = '<a href="/dashboard">Dashboard</a><a href="https://external.com">Out</a>'
    soup = BeautifulSoup(html, "html.parser")
    links = crawler._extraer_links(soup, "http://example.com/home", "example.com")
    assert len(links) == 1
    assert links[0] == "http://example.com/dashboard"


def test_extraer_formularios():
    mock_client = MagicMock()
    crawler = Crawler(mock_client)
    html = '''
    <form action="/login" method="post">
        <input name="user" type="text" />
        <textarea name="comment"></textarea>
    </form>
    '''
    soup = BeautifulSoup(html, "html.parser")
    forms = crawler._extraer_formularios(soup, "http://example.com")
    assert len(forms) == 1
    assert forms[0].action == "http://example.com/login"
    assert forms[0].method == "POST"
    assert len(forms[0].inputs) == 2
    assert forms[0].inputs[0]["name"] == "user"


def test_analizar_javascript():
    mock_client = MagicMock()
    crawler = Crawler(mock_client)
    js = 'const api = "/api/v1/users"; fetch(api);'
    endpoints = crawler._analizar_javascript(js, "http://example.com")
    assert "http://example.com/api/v1/users" in endpoints
