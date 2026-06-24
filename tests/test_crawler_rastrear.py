"""
tests/test_crawler_rastrear.py — Test para la lógica de rastreo BFS del crawler
"""

import pytest
from unittest.mock import MagicMock
from core.crawler import Crawler
from core.http_client import HttpClient


def test_crawler_rastrear_bfs():
    # Setup mocks
    mock_client = MagicMock(spec=HttpClient)
    
    # Mock first response: HTML with a link and a form
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 200
    mock_resp1.headers = {"Content-Type": "text/html"}
    mock_resp1.text = """
    <html>
        <body>
            <a href="/page2">Next</a>
            <form action="/submit" method="post">
                <input name="data" type="text" />
            </form>
        </body>
    </html>
    """
    
    # Mock second response: HTML with a link pointing back or to JS
    mock_resp2 = MagicMock()
    mock_resp2.status_code = 200
    mock_resp2.headers = {"Content-Type": "text/html"}
    mock_resp2.text = """
    <html>
        <head>
            <script src="/static/app.js"></script>
        </head>
        <body>
            <a href="/page2">Already visited link</a>
        </body>
    </html>
    """
    
    # Mock JS file response
    mock_resp_js = MagicMock()
    mock_resp_js.status_code = 200
    mock_resp_js.headers = {"Content-Type": "application/javascript"}
    mock_resp_js.text = 'fetch("/api/v1/data")'

    # Mock robots.txt response
    mock_resp_robots = MagicMock()
    mock_resp_robots.status_code = 200
    mock_resp_robots.headers = {"Content-Type": "text/plain"}
    mock_resp_robots.text = "User-agent: *\nDisallow: /private"

    def side_effect(url, **kwargs):
        if url.endswith("/robots.txt"):
            return mock_resp_robots
        elif url == "http://localhost:3000" or url == "http://localhost:3000/":
            return mock_resp1
        elif url == "http://localhost:3000/page2":
            return mock_resp2
        elif url == "http://localhost:3000/static/app.js":
            return mock_resp_js
        return None

    mock_client.get.side_effect = side_effect

    crawler = Crawler(mock_client, {"max_depth": 3, "max_urls": 10})
    metadata = crawler.rastrear("http://localhost:3000")

    # Verificaciones
    assert "http://localhost:3000" in metadata.urls_descubiertas
    assert "http://localhost:3000/page2" in metadata.urls_descubiertas
    assert len(metadata.formularios) == 1
    assert metadata.formularios[0].action == "http://localhost:3000/submit"
    assert "http://localhost:3000/static/app.js" in metadata.archivos_js
    assert "http://localhost:3000/api/v1/data" in metadata.endpoints_api
    assert "Disallow: /private" in metadata.robots_txt
