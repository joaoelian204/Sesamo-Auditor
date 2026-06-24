"""
tests/test_http_client.py — Pruebas unitarias para core/http_client.py
"""

import pytest
import time
import requests
from unittest.mock import MagicMock, patch
from core.http_client import HttpClient


def test_http_client_initialization():
    config = {
        "timeout_segundos": 5,
        "rate_limit_delay": 0.1,
        "max_reintentos": 2,
        "user_agent": "TestAgent/1.0",
        "proxy": "http://localhost:8080"
    }
    with patch("requests.Session") as mock_session_class:
        mock_session = mock_session_class.return_value
        mock_session.headers = {}
        mock_session.proxies = {}
        
        client = HttpClient(config)
        assert client.timeout == 5
        assert client.rate_limit_delay == 0.1
        assert client.session.headers["User-Agent"] == "TestAgent/1.0"
        assert client.session.proxies["http"] == "http://localhost:8080"
        assert client.session.proxies["https"] == "http://localhost:8080"
        assert client.session.verify is False


def test_rate_limiting():
    config = {
        "rate_limit_delay": 0.2,
        "max_reintentos": 1,
    }
    with patch("requests.Session") as mock_session_class:
        mock_session = mock_session_class.return_value
        mock_session.request.return_value = MagicMock(status_code=200, content=b"OK", elapsed=MagicMock(total_seconds=lambda: 0.1))
        
        client = HttpClient(config)
        start = time.time()
        client.get("http://example.com")
        client.get("http://example.com")
        duration = time.time() - start
        assert duration >= 0.2


def test_request_methods():
    client = HttpClient({"rate_limit_delay": 0})
    with patch.object(client.session, "request") as mock_request:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"OK"
        mock_resp.elapsed.total_seconds.return_value = 0.05
        mock_request.return_value = mock_resp

        resp = client.get("http://example.com/api", params={"q": "test"})
        assert resp is not None
        assert resp.status_code == 200
        mock_request.assert_called_with(
            method="GET",
            url="http://example.com/api",
            params={"q": "test"},
            data=None,
            json=None,
            headers=None,
            cookies=None,
            allow_redirects=True,
            timeout=10,
        )


def test_request_exception_handling():
    client = HttpClient({"rate_limit_delay": 0})
    with patch.object(client.session, "request") as mock_request:
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        resp = client.get("http://unreachable-target.com")
        assert resp is None
