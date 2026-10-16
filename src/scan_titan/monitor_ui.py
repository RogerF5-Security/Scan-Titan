"""Responsive CustomTkinter dashboard and dependency-free live canvas charts."""
from __future__ import annotations

import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import Any

import customtkinter as ctk
from PIL import Image, ImageDraw

from monitor_model import TelemetryHistory, number, timestamp


BG = "#0b101b"
PANEL = "#131c2c"
EDGE = "#233047"
TEXT = "#ecf2fc"
MUTED = "#8e9eb8"
CYAN = "#49d8cc"
BLUE = "#71a7ff"
ORANGE = "#ffb86b"
COLORS = ("#ff667e", "#ffad66", "#f2d073", "#71a7ff", "#8e9eb8")
SEVERITY_LABELS = ("Crítica", "Alta", "Media", "Baja", "Informativa")
SEVERITY_KEYS = ("Critical", "High", "Medium", "Low", "Info")


def icon(name: str, color: str = MUTED, size: int = 20) -> ctk.CTkImage:
    """Small antialiased line icons; no icon font, network, or emoji dependency."""
    image = Image.new("RGBA", (96, 96))
    draw = ImageDraw.Draw(image)
    def line(points: list[tuple[int, int]]) -> None:
        draw.line([(x * 4, y * 4) for x, y in points], fill=color, width=6, joint="curve")
    def box(rect: tuple[int, int, int, int], radius: int = 2) -> None:
        draw.rounded_rectangle(tuple(x * 4 for x in rect), radius=radius * 4, outline=color, width=6)
    if name == "shield":
        line([(12, 2), (21, 6), (20, 15), (16, 20), (12, 23), (8, 20), (4, 15), (3, 6), (12, 2)])
        line([(8, 12), (11, 15), (17, 9)])
    elif name == "grid":
        for x, y in ((3, 3), (14, 3), (3, 14), (14, 14)):
            box((x, y, x + 7, y + 7), 1)
    elif name == "pulse":
        line([(2, 12), (6, 12), (9, 5), (13, 19), (17, 9), (19, 12), (22, 12)])
    elif name == "folder":
        line([(3, 20), (3, 5), (10, 5), (12, 8), (21, 8), (21, 20), (3, 20)])
    elif name == "refresh":
        draw.arc((12, 12, 84, 84), 35, 315, fill=color, width=6)
        line([(18, 2), (18, 8), (12, 8)])
    elif name == "target":
        for pad in (4, 8):
            draw.ellipse((pad * 4, pad * 4, (24-pad) * 4, (24-pad) * 4), outline=color, width=6)
        line([(12, 1), (12, 5)]); line([(19, 12), (23, 12)])
    elif name == "clock":
        draw.ellipse((12, 12, 84, 84), outline=color, width=6)
        line([(12, 6), (12, 12), (16, 15)])
    elif name == "cpu":
        box((6, 6, 18, 18)); box((9, 9, 15, 15), 1)
        for pos in (8, 12, 16):
            line([(pos, 2), (pos, 5)]); line([(pos, 19), (pos, 22)])
            line([(2, pos), (5, pos)]); line([(19, pos), (22, pos)])
    elif name == "tools":
        line([(4, 20), (15, 9), (15, 4), (19, 2), (18, 7), (22, 6), (21, 11), (16, 12), (6, 22), (4, 20)])
    elif name == "list":
        for y in (6, 12, 18):
            line([(3, y), (4, y)]); line([(8, y), (21, y)])
    else:
        box((4, 3, 20, 21)); line([(8, 8), (16, 8)]); line([(8, 12), (16, 12)]); line([(8, 16), (13, 16)])
    return ctk.CTkImage(image, image, size=(size, size))


class LiveChart(tk.Canvas):
    """Time-proportional chart with explicit gaps and automatic axis scaling."""
    def __init__(self, parent: Any, color: str, unit: str, floor: float = 1) -> None:
        super().__init__(parent, background=PANEL, highlightthickness=0, height=round(150 * parent._get_widget_scaling()))
        self.color, self.unit, self.floor = color, unit, floor
        self.points: list[tuple[float, float | None]] = []
        self.message = "Esperando muestras de telemetría"
        self.bind("<Configure>", lambda _: self.draw())

    def set_data(self, points: Any, message: str = "") -> None:
        self.points = list(points)
        self.message = message or "Esperando muestras de telemetría"
        self.draw()

    def draw(self) -> None:
        self.delete("all")
        scale = self.master._get_widget_scaling()
        if int(self.cget("height")) != round(150 * scale):
            self.configure(height=round(150 * scale))
        width, height = self.winfo_width(), self.winfo_height()
        if width < 80 or height < 60:
            return
        left, right, top, bottom = 46 * scale, width - 14 * scale, 16 * scale, height - 28 * scale
        axis_font = ("Segoe UI", -round(10 * scale))
        values = [value for _, value in self.points if value is not None]
        ceiling = max(self.floor, max(values, default=0) * 1.2)
        for step in range(4):
            y = top + (bottom - top) * step / 3
            self.create_line(left, y, right, y, fill=EDGE, dash=(2, 5))
            value = ceiling * (1 - step / 3)
            self.create_text(left - 8 * scale, y, text=f"{value:,.0f}" if ceiling >= 10 else f"{value:.1f}", anchor="e", fill=MUTED, font=axis_font)
        if not values:
            self.create_text((left + right) / 2, (top + bottom) / 2, text=self.message, width=max(50, right-left-16), fill=MUTED, font=("Segoe UI", -round(12 * scale)), justify="center")
            return
        first, last = self.points[0][0], self.points[-1][0]
        span = max(10.0, last - first)
        def coords(stamp: float, value: float) -> tuple[float, float]:
            return left + (stamp - first) / span * (right-left), bottom - value / ceiling * (bottom-top)
        segment: list[float] = []
        segments: list[list[float]] = []
        previous = None
        for stamp, value in self.points:
            if value is None or (previous is not None and stamp - previous > 60):
                if segment:
                    segments.append(segment)
                segment = []
            if value is not None:
                segment.extend(coords(stamp, value))
            previous = stamp
        if segment:
            segments.append(segment)
        # A muted solid fill avoids expensive bitmap rendering on every tick.
        fill = "#183c40" if self.color == CYAN else "#1b2c49"
        for segment in segments:
            if len(segment) >= 4:
                self.create_polygon(segment[0], bottom, *segment, segment[-2], bottom, fill=fill, outline="")
                self.create_line(*segment, fill=self.color, width=2 * scale, joinstyle="round")
            x, y = segment[-2:]
            radius = 3 * scale
            self.create_oval(x-radius, y-radius, x+radius, y+radius, fill=self.color, outline=PANEL, width=1)
        self.create_text(left, height-10 * scale, anchor="w", text=datetime.fromtimestamp(first).strftime("%H:%M:%S"), fill=MUTED, font=axis_font)
        if last > first:
            self.create_text(right, height-10 * scale, anchor="e", text=datetime.fromtimestamp(last).strftime("%H:%M:%S"), fill=MUTED, font=axis_font)


class SeverityChart(tk.Canvas):
    def __init__(self, parent: Any) -> None:
        super().__init__(parent, background=PANEL, highlightthickness=0, height=round(156 * parent._get_widget_scaling()))
        self.counts: dict[str, Any] = {}
        self.bind("<Configure>", lambda _: self.draw())

    def set_counts(self, counts: dict[str, Any]) -> None:
        self.counts = counts
        self.draw()

    def draw(self) -> None:
        self.delete("all")
        scale = self.master._get_widget_scaling()
        if int(self.cget("height")) != round(156 * scale):
            self.configure(height=round(156 * scale))
        width = self.winfo_width()
        maximum = max(1, *(number(self.counts.get(key)) for key in SEVERITY_KEYS))
        for index, (key, label, color) in enumerate(zip(SEVERITY_KEYS, SEVERITY_LABELS, COLORS)):
            y = (14 + index * 30) * scale
            count = number(self.counts.get(key))
            self.create_oval(2 * scale, y-3 * scale, 8 * scale, y+3 * scale, fill=color, outline="")
            self.create_text(16 * scale, y, anchor="w", text=label, fill=MUTED, font=("Segoe UI", -round(11 * scale)))
            start, end = 100 * scale, max(104 * scale, width-34 * scale)
            self.create_line(start, y, end, y, fill=EDGE, width=5 * scale, capstyle="round")
            if count:
                self.create_line(start, y, start+(end-start)*count/maximum, y, fill=color, width=5 * scale, capstyle="round")
            self.create_text(width-4 * scale, y, anchor="e", text=f"{count:,.0f}", fill=TEXT, font=("Segoe UI", -round(12 * scale), "bold"))


class DashboardUI:
    """View mixin. File resolution and read-only runtime parsing stay in the app."""
    def _setup_style(self) -> None:
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=BG)
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("Titan.Treeview", background=PANEL, foreground=TEXT, fieldbackground=PANEL, borderwidth=0, bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL, relief="flat", rowheight=32, font=("Segoe UI", 10))
        self.style.configure("Titan.Treeview.Heading", background="#1b273b", foreground=MUTED, borderwidth=0, relief="flat", font=("Segoe UI", 9, "bold"), padding=(8, 10))
        self.style.map("Titan.Treeview", background=[("selected", "#234454")], foreground=[("selected", TEXT)])
        self.style.map("Titan.Treeview.Heading", background=[("active", EDGE)])
        self.style.configure("Titan.Horizontal.TScrollbar", background=EDGE, troughcolor=PANEL, borderwidth=0, arrowsize=12)
        self.style.configure("Titan.Vertical.TScrollbar", background=EDGE, troughcolor=PANEL, borderwidth=0, arrowsize=12)

    def _label(self, parent: Any, text: str = "", *, size: int = 12, color: str = TEXT, bold: bool = False, **kwargs: Any) -> ctk.CTkLabel:
        kwargs.setdefault("height", 0)
        return ctk.CTkLabel(parent, text=text, text_color=color, font=ctk.CTkFont(family="Segoe UI", size=size, weight="bold" if bold else "normal"), **kwargs)

    def _button(self, parent: Any, text: str, command: Any, symbol: str | None = None, *, primary: bool = False, width: int = 130) -> ctk.CTkButton:
        return ctk.CTkButton(parent, text=text, command=command, image=icon(symbol, BG if primary else MUTED) if symbol else None, compound="left", anchor="center", width=width, height=36, corner_radius=9, fg_color=CYAN if primary else "#1b283d", hover_color="#70e7dd" if primary else "#293a54", text_color=BG if primary else TEXT, font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold" if primary else "normal"))

    def _panel(self, parent: Any) -> ctk.CTkFrame:
        return ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=14, border_width=1, border_color=EDGE)

    def _build_ui(self) -> None:
        self.history = TelemetryHistory()
        self._layout_job: str | None = None
        self._layout_signature: tuple[Any, ...] | None = None
        self._rows_cache: dict[Any, Any] = {}
        self._resource_mode = "CPU"
        self.metric_vars = {key: tk.StringVar(value="—") for key in ("target", "phase", "module", "tests", "findings", "elapsed", "cpu", "ram", "processes", "requests", "targets")}
        self.detail_vars = {key: tk.StringVar(value="Esperando telemetría") for key in ("findings", "requests", "elapsed", "targets")}
        self.path_var = tk.StringVar(value=str(self.base_dir))
        self.footer_var = tk.StringVar(value="Esperando telemetría…")
        self.detail_var = tk.StringVar(value="El dashboard se actualizará automáticamente.")
        self.freshness_var = tk.StringVar(value="Actualización automática · 1,5 s")
        self.chart_hint_var = tk.StringVar(value="Historial de esta ventana · hasta 120 muestras reales")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.sidebar = ctk.CTkFrame(self, width=196, corner_radius=0, fg_color="#0e1625", border_width=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_propagate(False)
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(26, 0))
        self._label(brand, "", image=icon("shield", CYAN, 32), width=36).pack(side="left", padx=(0, 10))
        self._label(brand, "SCAN\nTITAN", size=18, bold=True, justify="left", anchor="w").pack(side="left")
        self._label(self.sidebar, "OPERATIONS MONITOR", size=10, color=MUTED).pack(anchor="w", padx=22, pady=(8, 38))
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        for text, symbol, tab in (("Vista general", "grid", ""), ("Módulos", "list", "Módulos"), ("Herramientas", "tools", "Herramientas"), ("Hallazgos", "shield", "Hallazgos"), ("Eventos", "pulse", "Eventos"), ("Procesos", "cpu", "Procesos")):
            button = self._button(self.sidebar, text, lambda tab=tab: self._navigate(tab), symbol, width=158)
            button.configure(anchor="w", fg_color="#183536" if not tab else "transparent", text_color=CYAN if not tab else MUTED)
            button.pack(fill="x", padx=14, pady=4)
            self.nav_buttons[tab] = button
        bottom = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=20, pady=22)
        self._label(bottom, "TU CENTRO DE CONTROL", size=10, color=MUTED).pack(anchor="w")
        self._label(bottom, "Telemetría de solo lectura", size=11, color=MUTED).pack(anchor="w", pady=(6, 0))
        self._label(bottom, "Scan Titan · Community", size=11, color="#526785").pack(anchor="w")

        self.scroll = ctk.CTkScrollableFrame(self, fg_color=BG, corner_radius=0, scrollbar_button_color=EDGE, scrollbar_button_hover_color="#38516f")
        self.scroll.grid(row=0, column=1, sticky="nsew", padx=(14, 8), pady=10)
        self.scroll.grid_columnconfigure(0, weight=1)
        self.header = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        self.header.grid_columnconfigure(0, weight=1)
        self._label(self.header, "WORKSPACE / LIVE OPERATIONS", size=10, color=MUTED).grid(row=0, column=0, sticky="w")
        self._label(self.header, "Centro de operaciones", size=28, bold=True).grid(row=1, column=0, sticky="w", pady=(0, 4))
        self.status_label = self._label(self.header, "ESPERANDO", size=11, color=MUTED, bold=True, fg_color="#1b283d", corner_radius=8, width=148, height=32)
        self.status_label.grid(row=1, column=1, sticky="e", padx=(10, 0))
        self.freshness_label = self._label(self.header, textvariable=self.freshness_var, size=11, color=MUTED)
        self.freshness_label.grid(row=2, column=0, columnspan=2, sticky="w")

        self.toolbar = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.toolbar.grid(row=1, column=0, sticky="ew", padx=10, pady=(6, 18))
        self.toolbar.grid_columnconfigure(0, weight=1)
        self.path_label = self._label(self.toolbar, textvariable=self.path_var, size=11, color=MUTED, anchor="w", justify="left", wraplength=650)
        self.path_label.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        controls = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        controls.grid(row=1, column=0, columnspan=3, sticky="w")
        self._button(controls, "Carpeta", self.choose_folder, "folder", width=104).pack(side="left", padx=(0, 8))
        self._button(controls, "Actualizar", self.refresh, "refresh", primary=True, width=116).pack(side="left", padx=(0, 8))
        self.open_menu = ctk.CTkOptionMenu(controls, values=["Reportes", "Dashboard HTML", "Recon Matrix", "Runtime JSON"], command=self._open_artifact, width=148, height=36, corner_radius=9, fg_color="#1b283d", button_color=EDGE, button_hover_color="#38516f", dropdown_fg_color=PANEL, dropdown_hover_color=EDGE, text_color=TEXT, font=ctk.CTkFont(family="Segoe UI", size=12))
        self.open_menu.set("Abrir archivo…")
        self.open_menu.pack(side="left")

        self.hero = self._panel(self.scroll)
        self.hero.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 14))
        self.hero.grid_columnconfigure(0, weight=1, uniform="hero")
        self.hero.grid_columnconfigure(1, weight=1, uniform="hero")
        self.context_panel = ctk.CTkFrame(self.hero, fg_color="transparent")
        self.context_panel.grid(row=0, column=0, sticky="nsew", padx=20, pady=18)
        self._label(self.context_panel, "OBJETIVO ACTUAL", size=10, color=CYAN, bold=True, image=icon("target", CYAN, 16), compound="left").pack(anchor="w")
        self.target_label = self._label(self.context_panel, textvariable=self.metric_vars["target"], size=21, bold=True, anchor="w", justify="left", wraplength=500)
        self.target_label.pack(fill="x", pady=(6, 4))
        self.context_label = self._label(self.context_panel, textvariable=self.metric_vars["phase"], size=12, color=MUTED, anchor="w", justify="left", wraplength=500)
        self.context_label.pack(fill="x")
        self.detail_label = self._label(self.context_panel, textvariable=self.detail_var, size=11, color=MUTED, anchor="w", justify="left", wraplength=500)
        self.detail_label.pack(fill="x", pady=(6, 0))
        self.progress_panel = ctk.CTkFrame(self.hero, fg_color="transparent")
        self.progress_panel.grid(row=0, column=1, sticky="nsew", padx=20, pady=18)
        self.progress_panel.grid_columnconfigure(0, weight=1)
        self._label(self.progress_panel, "Progreso global", size=12, bold=True).grid(row=0, column=0, sticky="w")
        self.global_text = self._label(self.progress_panel, "—", size=19, color=CYAN, bold=True)
        self.global_text.grid(row=0, column=1, sticky="e")
        self.global_bar = ctk.CTkProgressBar(self.progress_panel, height=8, fg_color=EDGE, progress_color=CYAN, corner_radius=4)
        self.global_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 15)); self.global_bar.set(0)
        self.module_caption = self._label(self.progress_panel, "Módulo actual", size=11, color=MUTED, anchor="w", wraplength=280)
        self.module_caption.grid(row=2, column=0, sticky="w")
        self.module_text = self._label(self.progress_panel, "—", size=12, color=BLUE, bold=True)
        self.module_text.grid(row=2, column=1, sticky="e")
        self.module_bar = ctk.CTkProgressBar(self.progress_panel, height=6, fg_color=EDGE, progress_color=BLUE, corner_radius=3)
        self.module_bar.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(7, 7)); self.module_bar.set(0)
        self._label(self.progress_panel, textvariable=self.metric_vars["tests"], size=10, color=MUTED, anchor="w").grid(row=4, column=0, columnspan=2, sticky="w")

        self.cards_frame = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.cards_frame.grid(row=3, column=0, sticky="ew", padx=4, pady=(0, 8))
        self.cards = []
        for key, label, symbol, color in (("findings", "Hallazgos únicos", "shield", ORANGE), ("requests", "Actividad HTTP interna", "pulse", CYAN), ("targets", "Objetivos completados", "target", BLUE), ("elapsed", "Tiempo transcurrido", "clock", "#c1adff")):
            card = self._panel(self.cards_frame)
            card.grid_columnconfigure(0, weight=1)
            self._label(card, label, size=11, color=MUTED, anchor="w").grid(row=0, column=0, sticky="w", padx=(16, 0), pady=(13, 0))
            self._label(card, "", image=icon(symbol, color), width=24).grid(row=0, column=1, padx=(4, 14), pady=(13, 0))
            value = self._label(card, textvariable=self.metric_vars[key], size=24, bold=True, anchor="w")
            value.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(3, 0))
            detail = self._label(card, textvariable=self.detail_vars[key], size=10, color=MUTED, anchor="w", justify="left", wraplength=230)
            detail.grid(row=2, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 13))
            self.cards.append((card, value, detail))

        charts_heading = ctk.CTkFrame(self.scroll, fg_color="transparent")
        charts_heading.grid(row=4, column=0, sticky="ew", padx=10, pady=(8, 8))
        self._label(charts_heading, "Pulso del escaneo", size=17, bold=True).pack(anchor="w")
        self._label(charts_heading, textvariable=self.chart_hint_var, size=11, color=MUTED).pack(anchor="w")
        self.charts_frame = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.charts_frame.grid(row=5, column=0, sticky="ew", padx=4)
        self.activity_panel = self._panel(self.charts_frame)
        self.resource_panel = self._panel(self.charts_frame)
        self.severity_panel = self._panel(self.charts_frame)
        for panel, title, subtitle in ((self.activity_panel, "Ritmo HTTP", "Respuestas internas por segundo"), (self.resource_panel, "Recursos del escaneo", "Proceso principal + procesos hijos"), (self.severity_panel, "Severidad", "Distribución reportada por el motor")):
            self._label(panel, title, size=13, bold=True).pack(anchor="w", padx=16, pady=(14, 0))
            self._label(panel, subtitle, size=10, color=MUTED).pack(anchor="w", padx=16, pady=(0, 2))
        rate_row = ctk.CTkFrame(self.activity_panel, fg_color="transparent", height=36)
        rate_row.pack(fill="x", padx=16)
        self.rate_label = self._label(rate_row, "— req/s", size=20, color=CYAN, bold=True)
        self.rate_label.pack(side="left")
        self.active_label = self._label(rate_row, "Sin muestra", size=10, color=MUTED)
        self.active_label.pack(side="right")
        self.activity_chart = LiveChart(self.activity_panel, CYAN, "req/s")
        self.activity_chart.pack(fill="x", padx=10, pady=(0, 2))
        self.activity_note = self._label(self.activity_panel, "No incluye tráfico de herramientas externas", size=10, color=MUTED, anchor="w")
        self.activity_note.pack(fill="x", padx=16, pady=(0, 12))
        resource_controls = ctk.CTkFrame(self.resource_panel, fg_color="transparent", height=36)
        resource_controls.pack(fill="x", padx=16, pady=(2, 0))
        self.resource_value = self._label(resource_controls, "—", size=20, color=BLUE, bold=True)
        self.resource_value.pack(side="left")
        self.resource_selector = ctk.CTkSegmentedButton(resource_controls, values=["CPU", "RAM"], command=self._select_resource, width=92, height=26, font=ctk.CTkFont(size=10), fg_color=EDGE, selected_color="#345986", selected_hover_color="#456fa2", unselected_color=EDGE, unselected_hover_color="#30435c", dynamic_resizing=False)
        self.resource_selector.pack(side="right"); self.resource_selector.set("CPU")
        self.resource_chart = LiveChart(self.resource_panel, BLUE, "%", floor=100)
        self.resource_chart.pack(fill="x", padx=10, pady=(0, 2))
        self.resource_note = self._label(self.resource_panel, "Esperando muestra de recursos", size=10, color=MUTED, anchor="w")
        self.resource_note.pack(fill="x", padx=16, pady=(0, 12))
        self.severity_chart = SeverityChart(self.severity_panel)
        self.severity_chart.pack(fill="x", padx=16, pady=(12, 12))
        self.severity_note = self._label(self.severity_panel, "Conteos del resumen de telemetría", size=10, color=MUTED, anchor="w", justify="left", wraplength=280)
        self.severity_note.pack(fill="x", padx=16, pady=(0, 14))

        self.details_heading = self._label(self.scroll, "Detalle de la operación", size=17, bold=True, anchor="w")
        self.details_heading.grid(row=6, column=0, sticky="ew", padx=10, pady=(18, 0))
        self.notebook = ctk.CTkTabview(self.scroll, height=354, fg_color=PANEL, corner_radius=14, border_width=1, border_color=EDGE, segmented_button_fg_color=BG, segmented_button_selected_color="#234849", segmented_button_selected_hover_color="#2d6260", segmented_button_unselected_color=BG, segmented_button_unselected_hover_color=EDGE, text_color=TEXT, segmented_button_font=ctk.CTkFont(family="Segoe UI", size=11), anchor="w", command=self._tab_changed)
        self.notebook.grid(row=7, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.modules_tree = self._tree("Módulos", ("target", "module", "status", "tested", "hits", "findings", "duration", "error"), ("Objetivo", "Módulo", "Estado", "Pruebas", "Hits", "Hallazgos", "Tiempo", "Detalle / error"))
        self.external_tree = self._tree("Herramientas", ("tool", "profile", "status", "rc", "findings", "duration", "timeout", "error"), ("Herramienta", "Perfil", "Estado", "RC", "Hallazgos", "Tiempo", "Timeout", "Detalle / error"))
        self.findings_tree = self._tree("Hallazgos", ("time", "severity", "target", "title", "source", "fingerprint"), ("Hora", "Severidad", "Objetivo", "Título", "Origen", "Fingerprint"))
        self.events_tree = self._tree("Eventos", ("time", "level", "message"), ("Hora", "Nivel", "Mensaje"))
        self.resources_tree = self._tree("Procesos", ("pid", "name", "cpu", "ram"), ("PID", "Proceso", "CPU %", "RAM MB"))
        for tree in (self.modules_tree, self.external_tree, self.findings_tree, self.events_tree, self.resources_tree):
            self._configure_columns(tree)
            tree.bind("<Double-1>", self._show_row_detail)
            tree.bind("<Return>", self._show_row_detail)
        self._label(self.scroll, "Doble clic en una fila para ver todos sus campos.", size=10, color=MUTED, anchor="w").grid(row=8, column=0, sticky="ew", padx=10)
        self.footer_label = self._label(self.scroll, textvariable=self.footer_var, size=10, color=MUTED, anchor="w", justify="left", wraplength=1000)
        self.footer_label.grid(row=9, column=0, sticky="ew", padx=10, pady=(10, 20))
        self.bind("<Configure>", self._queue_layout, add="+")
        self.after(100, self._apply_layout)

    def _queue_layout(self, event: Any) -> None:
        if event.widget not in (self, self.scroll):
            return
        if self._layout_job:
            self.after_cancel(self._layout_job)
        self._layout_job = self.after(80, self._apply_layout)

    def _apply_layout(self) -> None:
        self._layout_job = None
        width = self.winfo_width() / self._get_window_scaling()
        sidebar_visible = width >= 1360
        if sidebar_visible:
            self.sidebar.grid()
        else:
            self.sidebar.grid_remove()
        content = max(400, width - (196 if sidebar_visible else 0) - 70)
        card_columns = 4 if content >= 900 else 2
        chart_columns = 3 if content >= 1120 else (2 if content >= 740 else 1)
        hero_columns = 2 if content >= 860 else 1
        signature = (sidebar_visible, card_columns, chart_columns, hero_columns)
        if signature != self._layout_signature:
            self._layout_signature = signature
            for column in range(4):
                self.cards_frame.grid_columnconfigure(column, weight=int(column < card_columns), uniform="cards" if column < card_columns else "unused")
            for index, (card, _, _) in enumerate(self.cards):
                card.grid(row=index // card_columns, column=index % card_columns, sticky="nsew", padx=6, pady=6)
            for column in range(3):
                self.charts_frame.grid_columnconfigure(column, weight=(3 if column < 2 else 2) if column < chart_columns else 0, uniform="")
            for index, panel in enumerate((self.activity_panel, self.resource_panel, self.severity_panel)):
                panel.grid_forget()
                panel.grid(row=index // chart_columns, column=index % chart_columns, columnspan=2 if chart_columns == 2 and index == 2 else 1, sticky="nsew", padx=6, pady=6)
            self.hero.grid_columnconfigure(1, weight=int(hero_columns == 2), uniform="hero" if hero_columns == 2 else "unused")
            self.progress_panel.grid(row=0 if hero_columns == 2 else 1, column=1 if hero_columns == 2 else 0, sticky="nsew", padx=20, pady=(18, 18) if hero_columns == 2 else (0, 18))
        hero_wrap = max(300, int(content / hero_columns - 64))
        for label in (self.target_label, self.context_label, self.detail_label):
            label.configure(wraplength=hero_wrap)
        for _, value, detail in self.cards:
            value.configure(font=ctk.CTkFont(family="Segoe UI", size=23 if card_columns == 4 else 25, weight="bold"))
            detail.configure(wraplength=int(content / card_columns - 46))
        self.path_label.configure(wraplength=int(content-20))
        self.footer_label.configure(wraplength=int(content-20))
        self.module_caption.configure(wraplength=hero_wrap-70)

    def _navigate(self, tab: str) -> None:
        if tab:
            self.notebook.set(tab)
        self.update_idletasks()
        canvas = self.scroll._parent_canvas
        if not tab:
            canvas.yview_moveto(0)
        else:
            canvas.yview_moveto(max(0, (self.details_heading.winfo_y()-12) / max(1, self.scroll.winfo_height())))
        self._highlight_nav(tab)

    def _tab_changed(self) -> None:
        self._highlight_nav(self.notebook.get())

    def _highlight_nav(self, tab: str) -> None:
        for key, button in self.nav_buttons.items():
            button.configure(fg_color="#183536" if key == tab else "transparent", text_color=CYAN if key == tab else MUTED)

    def _open_artifact(self, value: str) -> None:
        # Importing here keeps the UI module independent of launcher setup.
        from ScanTitan_Monitor import open_path
        actions = {"Reportes": lambda: open_path(self.reports_dir), "Dashboard HTML": self.open_dashboard, "Recon Matrix": lambda: open_path(self.reports_dir / "Recon_Matrix.xlsx"), "Runtime JSON": lambda: open_path(self.runtime_file)}
        self.open_menu.set("Abrir archivo…")
        actions[value]()

    def _tree(self, tab_name: str, columns: tuple[str, ...], headings: tuple[str, ...]) -> ttk.Treeview:
        frame = self.notebook.add(tab_name)
        frame.grid_rowconfigure(0, weight=1); frame.grid_columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=columns, show="headings", style="Titan.Treeview", height=7, selectmode="browse")
        scroll_y = ctk.CTkScrollbar(frame, orientation="vertical", command=tree.yview, width=12, fg_color=PANEL, button_color=EDGE, button_hover_color="#38516f")
        scroll_x = ctk.CTkScrollbar(frame, orientation="horizontal", command=tree.xview, height=12, fg_color=PANEL, button_color=EDGE, button_hover_color="#38516f")
        tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        tree.grid(row=0, column=0, sticky="nsew"); scroll_y.grid(row=0, column=1, sticky="ns"); scroll_x.grid(row=1, column=0, sticky="ew")
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
        for severity, color in zip(SEVERITY_KEYS, COLORS):
            tree.tag_configure(severity, foreground=color)
        for status, color in (("failed", COLORS[0]), ("timeout", ORANGE), ("degraded", COLORS[2]), ("running", CYAN), ("finished", "#8bcbb9")):
            tree.tag_configure(status, foreground=color)
        tree.tag_configure("alternate", background="#162033")
        return tree

    def _configure_columns(self, tree: ttk.Treeview) -> None:
        widths = {"target": 170, "module": 150, "status": 100, "tested": 75, "hits": 60, "findings": 80, "duration": 90, "error": 330, "tool": 110, "profile": 180, "rc": 50, "timeout": 70, "time": 150, "severity": 90, "title": 350, "source": 130, "fingerprint": 140, "level": 70, "message": 700, "pid": 80, "name": 260, "cpu": 100, "ram": 110}
        for column in tree["columns"]:
            tree.column(column, width=widths.get(column, 120), minwidth=50, stretch=True)

    def _show_row_detail(self, event: Any) -> None:
        tree = event.widget
        if event.type == tk.EventType.ButtonPress:
            selected = tree.identify_row(event.y)
        else:
            selected = tree.focus()
        if not selected:
            return
        window = ctk.CTkToplevel(self)
        window.title("Detalle de telemetría"); window.geometry("760x460"); window.minsize(420, 280)
        window.transient(self)
        text = ctk.CTkTextbox(window, wrap="word", fg_color=PANEL, text_color=TEXT, font=ctk.CTkFont(family="Segoe UI", size=13))
        text.pack(fill="both", expand=True, padx=16, pady=16)
        for column, value in zip(tree["columns"], tree.item(selected, "values")):
            text.insert("end", f"{tree.heading(column, 'text')}\n{value or '—'}\n\n")
        text.configure(state="disabled")

    def _select_resource(self, value: str) -> None:
        self._resource_mode = value
        self._draw_resources()

    def _draw_resources(self) -> None:
        key = "cpu" if self._resource_mode == "CPU" else "ram"
        self.resource_chart.floor = 100 if key == "cpu" else 1
        self.resource_chart.unit = "%" if key == "cpu" else "MB"
        self.resource_chart.set_data(self.history.series[key])
        value = self.metric_vars[key].get().split("\n")[0]
        self.resource_value.configure(text=value)

    def _update_dashboard(self, data: dict[str, Any], *, stale: bool = False, fallback: bool = False) -> None:
        if fallback:
            self.history.clear()
        else:
            self.history.ingest(data, str(self.runtime_file), stale=stale)
        status = data.get("status", "")
        running = status in {"running", "finishing"} and not stale and not fallback
        counts = data.get("findings") if isinstance(data.get("findings"), dict) else {}
        unique = data.get("finding_unique")
        if unique is None:
            unique = sum(number(value) for value in counts.values())
        occurrences = data.get("finding_occurrences", unique)
        self.metric_vars["findings"].set(f"{number(unique):,.0f}")
        self.detail_vars["findings"].set(f"{number(occurrences):,.0f} ocurrencias reportadas")
        self.severity_chart.set_counts(counts)
        self.severity_note.configure(text="Resumen del motor; puede abarcar otro alcance que los únicos.")
        self.metric_vars["target"].set(str(data.get("current_target") or "Esperando objetivo"))
        phase, module = str(data.get("current_phase") or "Sin fase"), str(data.get("current_module") or "Sin módulo")
        self.metric_vars["phase"].set(f"{phase}  /  {module}")
        self.module_caption.configure(text=module)
        self.detail_var.set(str(data.get("current_detail") or ("Sin telemetría en vivo. Se muestran reportes anteriores." if fallback else "Esperando detalle del motor.")))
        self.metric_vars["tests"].set(f"{number(data.get('module_tested')):,.0f} / {number(data.get('module_total')):,.0f} pruebas · {number(data.get('module_hits')):,.0f} hits")
        total, done = number(data.get("target_total")), number(data.get("targets_completed"))
        self.metric_vars["targets"].set(f"{done:,.0f} / {total:,.0f}" if total else "—")
        self.detail_vars["targets"].set(f"Objetivo {number(data.get('target_index')):,.0f} en evaluación" if running else "Estado reportado por el motor")
        self.detail_vars["elapsed"].set("Desde el inicio del escaneo" if running else "Duración del último estado")
        activity = data.get("http_activity") if isinstance(data.get("http_activity"), dict) else {}
        self.metric_vars["requests"].set(f"{number(activity.get('completed')):,.0f}" if "completed" in activity and not fallback else "—")
        self.detail_vars["requests"].set("Respuestas del módulo actual" if activity else "Sin contador HTTP disponible")
        rate = self.history.rate
        self.rate_label.configure(text=f"{rate:.1f} req/s" if rate is not None and running else "— req/s")
        self.active_label.configure(text=f"{number(activity.get('active')):,.0f} activas · {number(activity.get('waiting')):,.0f} en cola" if running and activity else "Sin muestra en vivo")
        self.activity_chart.set_data(self.history.series["requests"], "Se necesitan dos muestras HTTP del mismo módulo")
        self._draw_resources()
        resources = data.get("resources") if isinstance(data.get("resources"), dict) else {}
        if resources.get("available"):
            self.resource_note.configure(text=f"CPU {number(resources.get('cpu_percent')):.1f}% · RAM {number(resources.get('ram_mb')):,.0f} MB · {number(resources.get('process_count')):,.0f} procesos")
        else:
            self.resource_note.configure(text="Sin muestra de recursos disponible")
        freshness = "Telemetría antigua · avance sin confirmar" if stale else ("Reportes anteriores · sin telemetría en vivo" if fallback else f"Actualización automática · 1,5 s · última muestra {str(data.get('updated_at') or '—')}")
        self.freshness_var.set(freshness)
        self.chart_hint_var.set("Historial detenido · última información recibida" if stale or fallback or not running else "Historial de esta ventana · hasta 120 muestras reales")
        if stale:
            self.detail_vars["elapsed"].set("Última duración recibida · dato antiguo")
        if fallback:
            self.global_bar.set(0); self.module_bar.set(0)
            self.global_text.configure(text="Sin datos"); self.module_text.configure(text="—")
        # Errors stay visible even while the user is looking at the overview.
        alert = data.get("last_error") or data.get("last_warning")
        if alert:
            self.detail_var.set(f"{'Último error' if data.get('last_error') else 'Aviso'}: {alert}")
            self.detail_label.configure(text_color=ORANGE)
        else:
            self.detail_label.configure(text_color=MUTED)
