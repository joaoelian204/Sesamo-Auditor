"""
reportes/pdf_exporter.py — Exportador de Reportes PDF Profesional
"""

from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)
from reportlab.pdfgen import canvas as canvas_module

from core.modelos import ResultadoEscaneo, Severidad

_SEV_COLORS = {
    Severidad.CRITICA: colors.HexColor("#DC2626"),
    Severidad.ALTA: colors.HexColor("#EA580C"),
    Severidad.MEDIA: colors.HexColor("#CA8A04"),
    Severidad.BAJA: colors.HexColor("#2563EB"),
    Severidad.INFO: colors.HexColor("#6B7280"),
}

_PRIMARY = colors.HexColor("#1E293B")
_ACCENT = colors.HexColor("#7C3AED")
_GRAY = colors.HexColor("#64748B")
_LIGHT = colors.HexColor("#F8FAFC")
_WHITE = colors.white
_BORDER = colors.HexColor("#E2E8F0")


class PDFExporter:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._configurar_estilos()

    def _configurar_estilos(self):
        self.styles.add(ParagraphStyle("PTitulo", fontName="Helvetica-Bold", fontSize=28,
            textColor=_ACCENT, alignment=TA_CENTER, spaceAfter=8))
        self.styles.add(ParagraphStyle("PSub", fontName="Helvetica", fontSize=14,
            textColor=_GRAY, alignment=TA_CENTER, spaceAfter=20))
        self.styles.add(ParagraphStyle("PInfo", fontName="Helvetica", fontSize=11,
            textColor=_PRIMARY, alignment=TA_CENTER, spaceAfter=3))
        self.styles.add(ParagraphStyle("ScoreNum", fontName="Helvetica-Bold", fontSize=48,
            alignment=TA_CENTER, spaceAfter=2))
        self.styles.add(ParagraphStyle("ScoreLbl", fontName="Helvetica", fontSize=10,
            textColor=_GRAY, alignment=TA_CENTER, spaceAfter=4))
        self.styles.add(ParagraphStyle("SecTit", fontName="Helvetica-Bold", fontSize=15,
            textColor=_PRIMARY, spaceAfter=8, spaceBefore=10))
        self.styles.add(ParagraphStyle("SubSec", fontName="Helvetica-Bold", fontSize=12,
            textColor=_ACCENT, spaceAfter=6, spaceBefore=8))
        self.styles.add(ParagraphStyle("Cuerpo", fontName="Helvetica", fontSize=9,
            textColor=_PRIMARY, spaceAfter=4, leading=13))
        self.styles.add(ParagraphStyle("Evidencia", fontName="Helvetica-Oblique", fontSize=8,
            textColor=_GRAY, spaceAfter=6, leading=11, leftIndent=10))
        self.styles.add(ParagraphStyle("Remed", fontName="Helvetica", fontSize=9,
            textColor=colors.HexColor("#065F46"), spaceAfter=8, leftIndent=10))
        self.styles.add(ParagraphStyle("Footer", fontName="Helvetica", fontSize=7,
            textColor=_GRAY, alignment=TA_CENTER))

    def _draw_portada(self, canvas: canvas_module.Canvas, doc):
        canvas.saveState()
        
        # 1. Left Blue Sidebar (HexColor "#2D70B3")
        canvas.setFillColor(colors.HexColor("#2D70B3"))
        canvas.rect(0, 0, 150, A4[1], fill=1, stroke=0)
        
        # 2. Logo in the Sidebar
        # Diamond shape
        path = canvas.beginPath()
        path.moveTo(50, 760)
        path.lineTo(65, 775)
        path.lineTo(50, 790)
        path.lineTo(35, 775)
        path.close()
        canvas.setFillColor(colors.white)
        canvas.drawPath(path, fill=1, stroke=0)
        
        # Inner smaller diamond (optional, matching image look)
        path_inner = canvas.beginPath()
        path_inner.moveTo(50, 765)
        path_inner.lineTo(60, 775)
        path_inner.lineTo(50, 785)
        path_inner.lineTo(40, 775)
        path_inner.close()
        canvas.setFillColor(colors.HexColor("#2D70B3"))
        canvas.drawPath(path_inner, fill=1, stroke=0)
        
        # Logo text
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.white)
        canvas.drawString(75, 770, "LOGO")
        
        # 3. Main white area content
        # Year (Top Right)
        anio_actual = datetime.now().strftime("%Y")
        canvas.setFont("Helvetica", 24)
        canvas.setFillColor(colors.HexColor("#2D70B3"))
        canvas.drawRightString(A4[0] - 2*cm, 765, anio_actual)
        
        # Title: "REPORTE" / "AUDITORÍA"
        canvas.setFont("Helvetica-Bold", 38)
        canvas.setFillColor(colors.HexColor("#0F172A")) # Sleek dark primary slate
        canvas.drawString(180, 600, "REPORTE")
        canvas.drawString(180, 550, "ANUAL")
        
        # Subtitle
        canvas.setFont("Helvetica", 20)
        canvas.setFillColor(colors.HexColor("#475569")) # Slate grey
        canvas.drawString(180, 500, "SEGURIDAD DE APIS")
        
        # Paragraph text
        canvas.setFont("Helvetica", 10)
        canvas.setFillColor(colors.HexColor("#64748B"))
        desc_lineas = [
            "Este documento contiene los resultados detallados de la auditoría",
            "de seguridad automatizada (DAST + SAST) realizada sobre el objetivo.",
            "Incluye vulnerabilidades identificadas, evidencias de explotación,",
            "análisis de riesgo consolidado y recomendaciones para su remediación."
        ]
        y_pos = 440
        for linea in desc_lineas:
            canvas.drawString(180, y_pos, linea)
            y_pos -= 15
            
        # 4. Light Grey Callout Box at bottom-middle
        canvas.setFillColor(colors.HexColor("#F8FAFC")) # Very light grey slate
        canvas.rect(180, 240, 360, 110, fill=1, stroke=0)
        
        # Text inside Callout Box
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(colors.HexColor("#334155"))
        canvas.drawString(200, 325, "DETALLES DEL ESCANEO")
        
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#475569"))
        target_str = self.temp_resultado.target_url
        if len(target_str) > 45:
            target_str = target_str[:42] + "..."
            
        canvas.drawString(200, 305, f"Objetivo: {target_str}")
        canvas.drawString(200, 290, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.drawString(200, 275, f"Vulnerabilidades: {len(self.temp_resultado.hallazgos_filtrados)} detectadas")
        canvas.drawString(200, 260, f"Score de Riesgo: {self.temp_res['score_riesgo']}/100")
        
        # 5. Decorative Dot Grid Matrix at the bottom right
        canvas.setFillColor(colors.HexColor("#CBD5E1")) # Light grey dots
        dot_start_x = 180
        dot_start_y = 100
        for row in range(5):
            for col in range(25):
                canvas.circle(dot_start_x + (col * 14), dot_start_y + (row * 10), 1.2, fill=1, stroke=0)
                
        canvas.restoreState()

    def _header_footer(self, canvas: canvas_module.Canvas, doc):
        if doc.page > 1:
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(_GRAY)
            canvas.drawString(2*cm, 1*cm, f"Sésamo Auditor v1.0 — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
            canvas.drawRightString(A4[0] - 2*cm, 1*cm, f"Pág. {doc.page}")
            canvas.restoreState()

    def generar_pdf(self, resultado: ResultadoEscaneo, ruta_salida: str):
        doc = SimpleDocTemplate(ruta_salida, pagesize=A4,
            topMargin=2*cm, bottomMargin=2.5*cm,
            leftMargin=2*cm, rightMargin=2*cm)
        e = []
        res = resultado.resumen()
        score = res["score_riesgo"]
        
        # Guardar variables temporales para el callback de la portada
        self.temp_resultado = resultado
        self.temp_res = res

        # ══════ PORTADA ══════
        e.append(PageBreak())

        # ══════ RESUMEN EJECUTIVO ══════
        e.append(Paragraph("1. Resumen Ejecutivo", self.styles["SecTit"]))
        e.append(self._tabla_simple(
            [["Métrica", "Valor"],
             ["URLs Escaneadas", str(res["urls_escaneadas"])],
             ["Plugins Ejecutados", str(res["plugins_ejecutados"])],
             ["Total Hallazgos", str(res["total_hallazgos"])],
             ["Score de Riesgo", f"{score}/100"],
             ["Duración", res["duracion"]]],
            [6*cm, 6*cm]))
        e.append(Spacer(1, 12))

        e.append(Paragraph("Distribución por Severidad", self.styles["SubSec"]))
        max_c = max((res["por_severidad"].get(s.etiqueta, 0) for s in Severidad), default=1)
        bar_rows = [["Severidad", "Cant.", "Barra"]]
        for s in reversed(list(Severidad)):
            c = res["por_severidad"].get(s.etiqueta, 0)
            if c > 0:
                bar = "█" * int((c / max_c) * 35) or "▏"
                bar_rows.append([f"{s.icono} {s.etiqueta}", str(c), bar])
        e.append(self._tabla_simple(bar_rows, [4.5*cm, 2*cm, 9.5*cm]))
        e.append(PageBreak())

        # ══════ HALLAZGOS ══════
        e.append(Paragraph("2. Hallazgos Detallados", self.styles["SecTit"]))
        if not resultado.hallazgos_filtrados:
            e.append(Paragraph("No se detectaron vulnerabilidades.", self.styles["Cuerpo"]))
        else:
            e.append(Paragraph(
                f"Se encontraron <b>{len(resultado.hallazgos_filtrados)}</b> hallazgo(s). "
                f"A continuación se detallan agrupados por severidad.",
                self.styles["Cuerpo"]))
            e.append(Spacer(1, 8))

            for sev in reversed(list(Severidad)):
                h_sev = resultado.por_severidad(sev)
                if not h_sev:
                    continue
                color = _SEV_COLORS.get(sev, _GRAY)

                bloque = []

                bloque.append(self._tabla_simple(
                    [[f"{sev.icono}  {sev.etiqueta.upper()}  —  {len(h_sev)} hallazgo(s)"]],
                    [16*cm], bg=color, tc=_WHITE, fs=11, p=8))

                bloque.append(Spacer(1, 6))

                for i, h in enumerate(h_sev, 1):
                    items = [
                        ["Plugin", h.plugin_nombre],
                        ["URL", h.url_afectada],
                        ["Método", h.metodo_http],
                        ["OWASP", str(h.categoria_owasp)],
                        ["CWE", h.cwe_id or "—"],
                        ["Confianza", h.confianza.etiqueta],
                    ]
                    if h.parametro:
                        items.append(["Parámetro", h.parametro])
                    if h.payload_usado:
                        p = h.payload_usado[:55] + ("..." if len(h.payload_usado) > 55 else "")
                        items.append(["Payload", p])

                    finding = []
                    finding.append(self._tabla_simple(items, [3.5*cm, 12.5*cm], fs=8))
                    if h.evidencia:
                        finding.append(Paragraph(f"<b>Evidencia:</b> {h.evidencia[:250]}", self.styles["Evidencia"]))
                    if h.remediacion:
                        finding.append(Paragraph(f"💡 <b>Solución:</b> {h.remediacion}", self.styles["Remed"]))
                    finding.append(Spacer(1, 8))
                    bloque.append(KeepTogether(finding))

                e.append(KeepTogether(bloque))
                e.append(Spacer(1, 8))

        e.append(Spacer(1, 15))
        e.append(Paragraph("— Fin del Reporte —", self.styles["Footer"]))
        doc.build(e, onFirstPage=self._draw_portada, onLaterPages=self._header_footer)

    def _tabla_simple(self, data, colWidths, bg=None, tc=None, fs=9, p=5):
        estilo = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), fs),
            ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), p),
            ("BOTTOMPADDING", (0, 0), (-1, -1), p),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        if bg:
            estilo.extend([
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("TEXTCOLOR", (0, 0), (-1, -1), tc or _WHITE),
            ])
        else:
            estilo.append(("BACKGROUND", (0, 0), (-1, 0), _PRIMARY))
            estilo.append(("TEXTCOLOR", (0, 0), (-1, 0), _WHITE))
            estilo.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _LIGHT]))
            estilo.append(("TEXTCOLOR", (0, 0), (-1, -1), _PRIMARY))
        t = Table(data, colWidths=colWidths, repeatRows=1)
        t.setStyle(TableStyle(estilo))
        return t

    def _caja_titulo(self, texto):
        c = _ACCENT
        t = Table([[texto]], colWidths=[10*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c),
            ("TEXTCOLOR", (0, 0), (-1, -1), _WHITE),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 22),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        return t
