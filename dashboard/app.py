"""
dashboard/app.py — Servidor Flask del Dashboard Web

Servidor web que presenta los resultados de un escaneo de seguridad
en una interfaz visual interactiva con:
- Vista principal con KPIs y gráfico de severidades
- Lista filtrable de hallazgos
- Vista de detalle por hallazgo

Uso:
    from dashboard.app import crear_app
    app = crear_app(resultado_escaneo)
    app.run(host="127.0.0.1", port=5000)
"""

import json

from flask import Flask, render_template, jsonify, request

from core.modelos import ResultadoEscaneo, Severidad


def crear_app(resultado: ResultadoEscaneo) -> Flask:
    """
    Crea y configura la aplicación Flask con los datos del escaneo.

    Args:
        resultado: ResultadoEscaneo con todos los hallazgos.

    Returns:
        Aplicación Flask configurada y lista para ejecutar.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # Almacenar resultado en el contexto de la app
    app.config["RESULTADO"] = resultado

    # ─── Rutas de Vistas HTML ───

    @app.route("/")
    def index():
        """Dashboard principal con resumen y KPIs."""
        resumen = resultado.resumen()
        return render_template("index.html", resultado=resultado, resumen=resumen)

    @app.route("/hallazgos")
    def hallazgos():
        """Lista filtrable de hallazgos."""
        severidad_filtro = request.args.get("severidad", "")
        categoria_filtro = request.args.get("categoria", "")
        plugin_filtro = request.args.get("plugin", "")

        hallazgos_filtrados = resultado.hallazgos_filtrados

        if severidad_filtro:
            hallazgos_filtrados = [
                h for h in hallazgos_filtrados
                if h.severidad.etiqueta.lower() == severidad_filtro.lower()
            ]
        if categoria_filtro:
            hallazgos_filtrados = [
                h for h in hallazgos_filtrados
                if categoria_filtro.lower() in h.categoria_owasp.codigo.lower()
            ]
        if plugin_filtro:
            hallazgos_filtrados = [
                h for h in hallazgos_filtrados
                if plugin_filtro.lower() in h.plugin_nombre.lower()
            ]

        # Obtener opciones únicas para filtros
        severidades = sorted(set(h.severidad.etiqueta for h in resultado.hallazgos_filtrados))
        categorias = sorted(set(h.categoria_owasp.codigo for h in resultado.hallazgos_filtrados))
        plugins = sorted(set(h.plugin_nombre for h in resultado.hallazgos_filtrados))

        return render_template(
            "hallazgos.html",
            hallazgos=hallazgos_filtrados,
            severidades=severidades,
            categorias=categorias,
            plugins=plugins,
            filtro_severidad=severidad_filtro,
            filtro_categoria=categoria_filtro,
            filtro_plugin=plugin_filtro,
        )

    @app.route("/hallazgo/<int:idx>")
    def detalle(idx):
        """Detalle individual de un hallazgo."""
        if 0 <= idx < len(resultado.hallazgos_filtrados):
            hallazgo = resultado.hallazgos_filtrados[idx]
            return render_template("detalle.html", hallazgo=hallazgo, idx=idx)
        return "Hallazgo no encontrado", 404

    # ─── Rutas API (JSON) ───

    @app.route("/api/resumen")
    def api_resumen():
        """API: Resumen del escaneo."""
        return jsonify(resultado.resumen())

    @app.route("/api/hallazgos")
    def api_hallazgos():
        """API: Lista de hallazgos."""
        return jsonify([h.to_dict() for h in resultado.hallazgos_filtrados])

    @app.route("/api/hallazgo/<int:idx>")
    def api_hallazgo(idx):
        """API: Detalle de un hallazgo."""
        if 0 <= idx < len(resultado.hallazgos_filtrados):
            return jsonify(resultado.hallazgos_filtrados[idx].to_dict())
        return jsonify({"error": "No encontrado"}), 404

    @app.route("/api/estadisticas")
    def api_estadisticas():
        """API: Datos para gráficos."""
        por_severidad = {}
        for sev in Severidad:
            por_severidad[sev.etiqueta] = len(resultado.por_severidad(sev))

        por_categoria = {}
        for h in resultado.hallazgos_filtrados:
            cat = h.categoria_owasp.codigo
            por_categoria[cat] = por_categoria.get(cat, 0) + 1

        por_plugin = {}
        for h in resultado.hallazgos_filtrados:
            por_plugin[h.plugin_nombre] = por_plugin.get(h.plugin_nombre, 0) + 1

        return jsonify({
            "por_severidad": por_severidad,
            "por_categoria": por_categoria,
            "por_plugin": por_plugin,
        })

    return app
