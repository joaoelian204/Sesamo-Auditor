"""
core/variants.py — Modelos de Vectores de Inyección (Variants) para Sésamo Auditor

Inspirado en la clase Variant de OWASP ZAP, encapsula los diferentes tipos
de entrada y métodos de inyección de parámetros.
"""

from abc import ABC, abstractmethod
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class BaseVariant(ABC):
    """
    Abstracción base para un vector de inyección (Variant).
    Estructura la forma de inyectar un payload en un parámetro o ubicación específica.
    """

    def __init__(self, target_url: str, parametro: str, valor_original: str = ""):
        self.target_url = target_url
        self.parametro = parametro
        self.valor_original = valor_original

    @abstractmethod
    def inyectar(self, payload: str) -> dict:
        """
        Genera los argumentos para realizar la petición HTTP con el payload inyectado.

        Returns:
            Dict con las claves listas para inyectar en `HttpClient.request`:
            - 'url' (str)
            - 'method' (str)
            - 'params' (dict|None)
            - 'data' (dict|None)
            - 'json' (dict|None)
            - 'headers' (dict|None)
            - 'cookies' (dict|None)
        """
        pass


class VariantURLQuery(BaseVariant):
    """Variant para parámetros de query string (?param=value)."""

    def inyectar(self, payload: str) -> dict:
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Reemplazar el valor del parámetro objetivo
        params_actualizados = {k: v[0] for k, v in params.items()}
        params_actualizados[self.parametro] = payload

        # Reconstruir la URL sin la query string para pasar los params por separado
        url_base = urlunparse(parsed._replace(query=""))

        return {
            "method": "GET",
            "url": url_base,
            "params": params_actualizados,
            "data": None,
            "json": None,
            "headers": None,
            "cookies": None
        }


class VariantFormQuery(BaseVariant):
    """Variant para POST form-urlencoded data."""

    def __init__(self, target_url: str, parametro: str, valor_original: str = "", inputs_base: dict = None, metodo: str = "POST"):
        super().__init__(target_url, parametro, valor_original)
        self.inputs_base = inputs_base or {}
        self.metodo = metodo

    def inyectar(self, payload: str) -> dict:
        data = self.inputs_base.copy()
        data[self.parametro] = payload

        return {
            "method": self.metodo,
            "url": self.target_url,
            "params": None if self.metodo == "POST" else data,
            "data": data if self.metodo == "POST" else None,
            "json": None,
            "headers": None,
            "cookies": None
        }


class VariantJSONQuery(BaseVariant):
    """Variant para JSON bodies."""

    def __init__(self, target_url: str, parametro: str, json_base: dict, metodo: str = "POST"):
        super().__init__(target_url, parametro)
        self.json_base = json_base
        self.metodo = metodo

    def inyectar(self, payload: str) -> dict:
        body = json.loads(json.dumps(self.json_base)) # Deep copy simple
        
        # Soporte para claves anidadas simples o clave directa
        if isinstance(body, dict):
            body[self.parametro] = payload

        return {
            "method": self.metodo,
            "url": self.target_url,
            "params": None,
            "data": None,
            "json": body,
            "headers": {"Content-Type": "application/json"},
            "cookies": None
        }


class VariantHeader(BaseVariant):
    """Variant para HTTP Headers."""

    def inyectar(self, payload: str) -> dict:
        headers = {self.parametro: payload}
        return {
            "method": "GET",
            "url": self.target_url,
            "params": None,
            "data": None,
            "json": None,
            "headers": headers,
            "cookies": None
        }


class VariantCookie(BaseVariant):
    """Variant para cookies."""

    def inyectar(self, payload: str) -> dict:
        cookies = {self.parametro: payload}
        return {
            "method": "GET",
            "url": self.target_url,
            "params": None,
            "data": None,
            "json": None,
            "headers": None,
            "cookies": cookies
        }


class VariantURLPath(BaseVariant):
    """Variant para segmentos del path de la URL (ej. /users/{id}/profile)."""

    def __init__(self, target_url: str, segmento_idx: int, valor_original: str):
        # El parametro es el index del segmento a reemplazar
        super().__init__(target_url, str(segmento_idx), valor_original)
        self.segmento_idx = segmento_idx

    def inyectar(self, payload: str) -> dict:
        parsed = urlparse(self.target_url)
        path_parts = parsed.path.split("/")
        
        if 0 <= self.segmento_idx < len(path_parts):
            path_parts[self.segmento_idx] = payload
            
        nuevo_path = "/".join(path_parts)
        url_actualizada = urlunparse(parsed._replace(path=nuevo_path))

        return {
            "method": "GET",
            "url": url_actualizada,
            "params": None,
            "data": None,
            "json": None,
            "headers": None,
            "cookies": None
        }
