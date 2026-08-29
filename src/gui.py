"""
EXE Unpacker GUI Application
Premium dark cybersecurity-themed interface for unpacking and analyzing executables
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import scrolledtext
import os
import threading
import json
import struct
import re
from pathlib import Path
from datetime import datetime

try:
    from tkinterdnd2 import TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

from src.dotnet_unpacker import DotNETUnpacker
from src.cpp_unpacker import CPPUnpacker
from src.decryptor import DecryptionManager, ProtectionDetector
from src.themida_unpacker import ThemidaUnpacker
from src.vmprotect_unpacker import VMProtectUnpacker
from src.license_patcher import LicensePatcher
from src.keyauth_patcher import KeyAuthPatcher


# ═══════════════════════════════════════════════════════════════════════════
# Color Palette & Theme Constants
# ═══════════════════════════════════════════════════════════════════════════

COLORS = {
    # Backgrounds
    "bg_darkest":       "#0d1117",
    "bg_dark":          "#161b22",
    "bg_card":          "#1c2128",
    "bg_card_hover":    "#242b35",
    "bg_input":         "#0d1117",
    "bg_sidebar":       "#111920",

    # Borders
    "border":           "#30363d",
    "border_light":     "#3d444d",
    "border_focus":     "#00d4ff",

    # Text
    "text_primary":     "#e6edf3",
    "text_secondary":   "#8b949e",
    "text_muted":       "#565e67",
    "text_bright":      "#ffffff",

    # Accent: Neon Cyan (Primary)
    "accent":           "#00d4ff",
    "accent_dim":       "#0a3d5c",
    "accent_hover":     "#33ddff",
    "accent_glow":      "#00d4ff",

    # Category Colors
    "cat_dotnet":       "#60a5fa",   # Blue
    "cat_cpp":          "#a78bfa",   # Purple
    "cat_scan":         "#34d399",   # Emerald
    "cat_protect":      "#fb923c",   # Orange
    "cat_patch":        "#f87171",   # Red

    # Status colors
    "success":          "#22c55e",
    "warning":          "#eab308",
    "error":            "#ef4444",
    "info":             "#00d4ff",

    # Special
    "drop_zone_bg":     "#0f1923",
    "drop_zone_active": "#0a2a1a",
    "drop_zone_border": "#1e3a5f",
    "one_click_bg":     "#1a1040",
    "one_click_hover":  "#2a1860",
    "scrollbar_bg":     "#161b22",
    "scrollbar_fg":     "#30363d",
}

FONTS = {
    "title":        ("Segoe UI", 16, "bold"),
    "subtitle":     ("Segoe UI", 11, "bold"),
    "heading":      ("Segoe UI", 10, "bold"),
    "body":         ("Segoe UI", 9),
    "body_bold":    ("Segoe UI", 9, "bold"),
    "small":        ("Segoe UI", 8),
    "mono":         ("Consolas", 9),
    "mono_small":   ("Consolas", 8),
    "mono_log":     ("Consolas", 9),
    "icon":         ("Segoe UI Emoji", 12),
    "icon_large":   ("Segoe UI Emoji", 22),
    "button":       ("Segoe UI", 9, "bold"),
    "category":     ("Segoe UI", 10, "bold"),
    "version":      ("Segoe UI", 8),
}


# ═══════════════════════════════════════════════════════════════════════════
# Tooltip Widget
# ═══════════════════════════════════════════════════════════════════════════

class ToolTip:
    """Hover tooltip for widgets."""
    def __init__(self, widget, text, delay=400):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tip_window = None
        self._after_id = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._cancel)

    def _schedule(self, event=None):
        self._cancel()
        self._after_id = self.widget.after(self.delay, self._show)

    def _cancel(self, event=None):
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None
        self._hide()

    def _show(self):
        if self.tip_window:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.attributes("-topmost", True)
        frame = tk.Frame(tw, bg=COLORS["bg_card"], bd=1, relief=tk.SOLID,
                         highlightbackground=COLORS["border"], highlightthickness=1)
        frame.pack()
        label = tk.Label(frame, text=self.text, bg=COLORS["bg_card"],
                         fg=COLORS["text_secondary"], font=FONTS["small"],
                         padx=8, pady=4, justify=tk.LEFT)
        label.pack()

    def _hide(self):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


# ═══════════════════════════════════════════════════════════════════════════
# Toast Notification
# ═══════════════════════════════════════════════════════════════════════════

class Toast:
    """Non-blocking toast notification."""
    def __init__(self, parent, message, level="info", duration=3000):
        self.parent = parent
        self.message = message
        self.level = level
        self.duration = duration
        self._show()

    def _show(self):
        self.win = tk.Toplevel(self.parent)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.configure(bg=COLORS["bg_card"])

        colors = {
            "info": COLORS["accent"],
            "success": COLORS["success"],
            "warning": COLORS["warning"],
            "error": COLORS["error"],
        }
        color = colors.get(self.level, COLORS["accent"])

        # Calculate position - bottom right of parent
        self.parent.update_idletasks()
        pw = self.parent.winfo_width()
        ph = self.parent.winfo_height()
        px = self.parent.winfo_rootx()
        py = self.parent.winfo_rooty()

        # Measure text
        temp = tk.Label(self.win, text=self.message, font=FONTS["body"])
        temp.pack()
        tw = temp.winfo_reqwidth() + 30
        th = temp.winfo_reqheight() + 16
        temp.destroy()

        x = px + pw - tw - 20
        y = py + ph - th - 60

        self.win.geometry(f"{tw}x{th}+{x}+{y}")

        # Border
        border = tk.Frame(self.win, bg=color, height=3)
        border.pack(fill=tk.X)

        tk.Label(self.win, text=self.message, font=FONTS["body"],
                 bg=COLORS["bg_card"], fg=COLORS["text_primary"],
                 padx=12, pady=8, anchor=tk.W).pack(fill=tk.BOTH, expand=True)

        # Auto dismiss
        self.win.after(self.duration, self._dismiss)

    def _dismiss(self):
        try:
            self.win.destroy()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# Styled Button Widget
# ═══════════════════════════════════════════════════════════════════════════

class StyledButton(tk.Canvas):
    """A custom flat button with hover glow effects."""
    def __init__(self, parent, text, command=None, color=None, width=None,
                 tooltip=None, icon=None, large=False, disabled=False):
        self._color = color or COLORS["accent"]
        self._text = text
        self._command = command
        self._icon = icon
        self._large = large
        self._disabled = disabled

        h = 36 if large else 30
        w = width or (self._calc_width(text, icon, large))

        super().__init__(parent, width=w, height=h,
                         bg=COLORS["bg_card"], highlightthickness=0,
                         cursor="hand2" if not disabled else "arrow")

        self._btn_w = w
        self._btn_h = h
        self._hovered = False

        self.after_idle(self._draw)

        if not disabled:
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)
            self.bind("<ButtonPress-1>", self._on_press)
            self.bind("<ButtonRelease-1>", self._on_release)

        if tooltip:
            ToolTip(self, tooltip)

    def set_disabled(self, state):
        self._disabled = state
        self.config(cursor="arrow" if state else "hand2")
        self._draw()

    def _calc_width(self, text, icon, large):
        base = len(text) * (8 if large else 7) + 24
        if icon:
            base += 20
        return max(base, 90)

    def _draw(self):
        self.delete("all")
        w, h = self._btn_w, self._btn_h
        r = 6

        if self._disabled:
            bg = COLORS["bg_dark"]
            border = COLORS["border"]
            text_col = COLORS["text_muted"]
        elif self._hovered:
            bg = self._blend(COLORS["bg_card_hover"], self._color, 0.15)
            border = self._color
            text_col = COLORS["text_bright"]
        else:
            bg = COLORS["bg_card"]
            border = COLORS["border"]
            text_col = COLORS["text_primary"]

        # Rounded rectangle
        self._round_rect(1, 1, w - 1, h - 1, r, fill=bg, outline=border)

        # Text
        display = self._text
        if self._icon:
            display = f"{self._icon}  {self._text}"
        font = FONTS["button"] if not self._large else FONTS["heading"]
        self.create_text(w // 2, h // 2, text=display, fill=text_col, font=font)

        # Bottom accent line on hover
        if self._hovered and not self._disabled:
            self.create_line(r + 2, h - 2, w - r - 2, h - 2, fill=self._color, width=2)

    def _round_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        self.create_polygon(points, smooth=True, **kwargs)

    def _blend(self, hex1, hex2, factor):
        r1, g1, b1 = int(hex1[1:3], 16), int(hex1[3:5], 16), int(hex1[5:7], 16)
        r2, g2, b2 = int(hex2[1:3], 16), int(hex2[3:5], 16), int(hex2[5:7], 16)
        r = int(r1 + (r2 - r1) * factor)
        g = int(g1 + (g2 - g1) * factor)
        b = int(b1 + (b2 - b1) * factor)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _on_enter(self, e):
        self._hovered = True
        self._draw()

    def _on_leave(self, e):
        self._hovered = False
        self._draw()

    def _on_press(self, e):
        self.config(bg=self._blend(COLORS["bg_darkest"], self._color, 0.1))

    def _on_release(self, e):
        self.config(bg=COLORS["bg_card"])
        if self._command:
            self._command()


# ═══════════════════════════════════════════════════════════════════════════
# Sidebar Category Tab
# ═══════════════════════════════════════════════════════════════════════════

class CategoryTab(tk.Canvas):
    """Sidebar navigation tab."""
    def __init__(self, parent, text, icon, color, command=None, **kwargs):
        super().__init__(parent, height=48, highlightthickness=0,
                         bg=COLORS["bg_sidebar"], cursor="hand2", **kwargs)
        self._text = text
        self._icon = icon
        self._color = color
        self._command = command
        self._active = False
        self._hovered = False

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonRelease-1>", self._on_click)
        self.bind("<Configure>", lambda e: self._draw())

    def set_active(self, active):
        self._active = active
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 2:
            return

        if self._active:
            bg = "#0d1a2a"
            text_col = self._color
            self.create_rectangle(0, 0, 3, h, fill=self._color, outline="")
        elif self._hovered:
            bg = COLORS["bg_card"]
            text_col = COLORS["text_primary"]
        else:
            bg = COLORS["bg_sidebar"]
            text_col = COLORS["text_secondary"]

        self.create_rectangle(0, 0, w, h, fill=bg, outline="")
        if self._active:
            self.create_rectangle(0, 0, 3, h, fill=self._color, outline="")

        self.create_text(22, h // 2, text=self._icon, font=FONTS["icon"], fill=text_col, anchor=tk.W)
        self.create_text(46, h // 2, text=self._text, font=FONTS["category"],
                         fill=text_col, anchor=tk.W)

    def _on_enter(self, e):
        self._hovered = True
        self._draw()

    def _on_leave(self, e):
        self._hovered = False
        self._draw()

    def _on_click(self, e):
        if self._command:
            self._command()


# ═══════════════════════════════════════════════════════════════════════════
# Main GUI Class
# ═══════════════════════════════════════════════════════════════════════════

class UnpackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EXE Unpacker — All-in-One Analysis Tool")
        self.root.geometry("1150x820")
        self.root.resizable(True, True)
        self.root.minsize(950, 700)
        self.root.configure(bg=COLORS["bg_darkest"])

        # Remove default window decorations styling
        try:
            self.root.tk.call("tk", "scaling", 1.25)
        except Exception:
            pass

        # Initialize unpackers
        self.dotnet_unpacker = DotNETUnpacker()
        self.cpp_unpacker = CPPUnpacker()
        self.license_patcher = LicensePatcher()
        self.keyauth_patcher = KeyAuthPatcher()
        self.decryption_manager = DecryptionManager()

        self.selected_file = None
        self.current_output_dir = None
        self._operation_active = False
        self._current_category = "dotnet"
        self._recent_files = self._load_recent_files()

        self._categories = {
            "dotnet":  {"label": ".NET",        "icon": "🔷", "color": COLORS["cat_dotnet"]},
            "cpp":     {"label": "C++ / Native","icon": "⚙️", "color": COLORS["cat_cpp"]},
            "scan":    {"label": "Deep Scan",   "icon": "🔍", "color": COLORS["cat_scan"]},
            "protect": {"label": "Protection",  "icon": "🛡️", "color": COLORS["cat_protect"]},
            "patch":   {"label": "Patching",    "icon": "🩹", "color": COLORS["cat_patch"]},
        }

        self._setup_styles()
        self._build_ui()
        self.setup_drag_drop()
        self._setup_keyboard_shortcuts()
        self._switch_category("dotnet")
        self.add_log("Application started — ready to analyze executables", "info")
        self.add_log("  Keyboard: Ctrl+O browse | Ctrl+L clear log | Ctrl+F search log | Ctrl+C copy info", "normal")
        self._animate_drop_zone()

    # ── Keyboard Shortcuts ─────────────────────────────────────────────────

    def _setup_keyboard_shortcuts(self):
        self.root.bind("<Control-o>", lambda e: self.browse_file())
        self.root.bind("<Control-O>", lambda e: self.browse_file())
        self.root.bind("<Control-l>", lambda e: self.clear_log())
        self.root.bind("<Control-L>", lambda e: self.clear_log())
        self.root.bind("<Control-f>", lambda e: self._focus_log_search())
        self.root.bind("<Control-F>", lambda e: self._focus_log_search())
        self.root.bind("<Control-c>", lambda e: self._copy_info_panel())
        self.root.bind("<Control-C>", lambda e: self._copy_info_panel())
        self.root.bind("<Escape>", lambda e: self._cancel_operation())

    def _focus_log_search(self):
        if hasattr(self, 'log_search_entry'):
            self.log_search_entry.focus_set()

    def _copy_info_panel(self):
        try:
            content = self.info_text.get(1.0, tk.END).strip()
            if content:
                self.root.clipboard_clear()
                self.root.clipboard_append(content)
                Toast(self.root, "Info panel copied to clipboard", "success")
        except Exception:
            pass

    def _cancel_operation(self):
        if self._operation_active:
            self._operation_active = False
            self.progress.stop()
            self.set_status("Cancelled")
            self.add_log("Operation cancelled by user", "warning")

    # ── Theme & Style Setup ──────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        # General
        style.configure(".", background=COLORS["bg_darkest"], foreground=COLORS["text_primary"],
                         font=FONTS["body"])
        style.configure("TFrame", background=COLORS["bg_darkest"])
        style.configure("TLabel", background=COLORS["bg_darkest"], foreground=COLORS["text_primary"])
        style.configure("Card.TFrame", background=COLORS["bg_card"])
        style.configure("Card.TLabel", background=COLORS["bg_card"], foreground=COLORS["text_primary"])

        # Progressbar
        style.configure("Accent.Horizontal.TProgressbar",
                         troughcolor=COLORS["bg_dark"],
                         background=COLORS["accent"],
                         bordercolor=COLORS["border"],
                         lightcolor=COLORS["accent"],
                         darkcolor=COLORS["accent_dim"])

        # Scrollbar
        style.configure("Dark.Vertical.TScrollbar",
                         background=COLORS["scrollbar_fg"],
                         troughcolor=COLORS["scrollbar_bg"],
                         bordercolor=COLORS["bg_darkest"],
                         arrowcolor=COLORS["text_muted"])

    # ── Build Main UI ────────────────────────────────────────────────────

    def _build_ui(self):
        # Root grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        # ── Header ──
        self._build_header()

        # ── Body (sidebar + content) ──
        body = tk.Frame(self.root, bg=COLORS["bg_darkest"])
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_sidebar(body)
        self._build_content(body)

        # ── Status Bar ──
        self._build_status_bar()

    # ── Header ───────────────────────────────────────────────────────────

    def _build_header(self):
        header = tk.Frame(self.root, bg=COLORS["bg_dark"], height=56)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.columnconfigure(1, weight=1)

        # Logo + Title
        logo_frame = tk.Frame(header, bg=COLORS["bg_dark"])
        logo_frame.grid(row=0, column=0, sticky="w", padx=(16, 0), pady=8)

        tk.Label(logo_frame, text="📦", font=FONTS["icon_large"],
                 bg=COLORS["bg_dark"], fg=COLORS["accent"]).pack(side=tk.LEFT, padx=(0, 8))

        title_col = tk.Frame(logo_frame, bg=COLORS["bg_dark"])
        title_col.pack(side=tk.LEFT)

        tk.Label(title_col, text="EXE UNPACKER", font=FONTS["title"],
                 bg=COLORS["bg_dark"], fg=COLORS["text_bright"]).pack(side=tk.LEFT)

        tk.Label(title_col, text="  v2.0", font=FONTS["version"],
                 bg=COLORS["bg_dark"], fg=COLORS["text_muted"]).pack(side=tk.LEFT, pady=(4, 0))

        # Accent line at bottom
        accent_line = tk.Canvas(header, height=2, bg=COLORS["bg_dark"], highlightthickness=0)
        accent_line.grid(row=1, column=0, columnspan=3, sticky="ew")
        accent_line.bind("<Configure>", lambda e: self._draw_gradient_line(accent_line))

        # File info in header
        file_frame = tk.Frame(header, bg=COLORS["bg_dark"])
        file_frame.grid(row=0, column=1, sticky="ew", padx=20, pady=8)

        browse_frame = tk.Frame(file_frame, bg=COLORS["bg_dark"])
        browse_frame.pack(fill=tk.X)

        tk.Label(browse_frame, text="TARGET:", font=FONTS["body_bold"],
                 bg=COLORS["bg_dark"], fg=COLORS["text_muted"]).pack(side=tk.LEFT)

        self.file_label = tk.Label(browse_frame, text="  No file selected",
                                   font=FONTS["mono"], bg=COLORS["bg_dark"],
                                   fg=COLORS["text_secondary"], anchor=tk.W)
        self.file_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))

        # Browse button
        browse_btn = tk.Canvas(header, width=90, height=30, bg=COLORS["bg_dark"],
                               highlightthickness=0, cursor="hand2")
        browse_btn.grid(row=0, column=2, padx=(0, 8), pady=12)
        self._draw_browse_btn(browse_btn, False)
        browse_btn.bind("<Enter>", lambda e: self._draw_browse_btn(browse_btn, True))
        browse_btn.bind("<Leave>", lambda e: self._draw_browse_btn(browse_btn, False))
        browse_btn.bind("<ButtonRelease-1>", lambda e: self.browse_file())
        ToolTip(browse_btn, "Browse for an executable file")

        # Recent files button
        recent_btn = tk.Canvas(header, width=28, height=30, bg=COLORS["bg_dark"],
                               highlightthickness=0, cursor="hand2")
        recent_btn.grid(row=0, column=3, padx=(0, 16), pady=12)
        self._draw_recent_btn(recent_btn, False)
        recent_btn.bind("<Enter>", lambda e: self._draw_recent_btn(recent_btn, True))
        recent_btn.bind("<Leave>", lambda e: self._draw_recent_btn(recent_btn, False))
        recent_btn.bind("<ButtonRelease-1>", lambda e: self._show_recent_files_menu())
        ToolTip(recent_btn, "Recent files")

    def _draw_gradient_line(self, canvas):
        canvas.delete("all")
        w = canvas.winfo_width()
        if w < 2:
            return
        steps = min(w, 200)
        for i in range(steps):
            r = int(0 + (168 - 0) * i / steps)
            g = int(212 + (85 - 212) * i / steps)
            b = int(255 + (247 - 255) * i / steps)
            color = f"#{r:02x}{g:02x}{b:02x}"
            x = int(i * w / steps)
            x2 = int((i + 1) * w / steps)
            canvas.create_rectangle(x, 0, x2, 2, fill=color, outline="")

    def _draw_browse_btn(self, canvas, hovered):
        canvas.delete("all")
        w, h = 90, 30
        bg = COLORS["accent_dim"] if hovered else COLORS["bg_card"]
        border = COLORS["accent"] if hovered else COLORS["border"]
        fg = COLORS["accent"] if hovered else COLORS["text_secondary"]
        # Rounded rect
        r = 5
        points = [r, 0, w - r, 0, w, 0, w, r, w, h - r, w, h, w - r, h,
                  r, h, 0, h, 0, h - r, 0, r, 0, 0]
        canvas.create_polygon(points, smooth=True, fill=bg, outline=border)
        canvas.create_text(w // 2, h // 2, text="Browse…", font=FONTS["button"], fill=fg)

    def _draw_recent_btn(self, canvas, hovered):
        canvas.delete("all")
        w, h = 28, 30
        bg = COLORS["bg_card_hover"] if hovered else COLORS["bg_card"]
        border = COLORS["accent"] if hovered else COLORS["border"]
        fg = COLORS["accent"] if hovered else COLORS["text_muted"]
        r = 5
        points = [r, 0, w - r, 0, w, 0, w, r, w, h - r, w, h, w - r, h,
                  r, h, 0, h, 0, h - r, 0, r, 0, 0]
        canvas.create_polygon(points, smooth=True, fill=bg, outline=border)
        # Clock icon
        cx, cy = w // 2, h // 2
        canvas.create_oval(cx - 8, cy - 8, cx + 8, cy + 8, outline=fg, width=1.5)
        canvas.create_line(cx, cy, cx, cy - 5, fill=fg, width=1.5)
        canvas.create_line(cx, cy, cx + 4, cy, fill=fg, width=1.5)

    # ── Sidebar ──────────────────────────────────────────────────────────

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=COLORS["bg_sidebar"], width=180)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        # Section label
        tk.Label(sidebar, text="CATEGORIES", font=FONTS["small"],
                 bg=COLORS["bg_sidebar"], fg=COLORS["text_muted"],
                 anchor=tk.W).pack(fill=tk.X, padx=16, pady=(14, 6))

        sep = tk.Frame(sidebar, bg=COLORS["border"], height=1)
        sep.pack(fill=tk.X, padx=12, pady=(0, 6))

        # Category tabs with tooltips
        self._tabs = {}
        tab_tips = {
            "dotnet": "Analyze .NET assemblies, extract metadata and decompile",
            "cpp": "Analyze native C++ binaries, disassemble and extract strings",
            "scan": "Deep scan for entropy, network indicators, embedded files",
            "protect": "Detect and unpack Themida, VMProtect and other packers",
            "patch": "Patch KeyAuth license checks and HWID protections",
        }
        for key, cat in self._categories.items():
            tab = CategoryTab(sidebar, cat["label"], cat["icon"], cat["color"],
                              command=lambda k=key: self._switch_category(k))
            tab.pack(fill=tk.X, padx=4, pady=1)
            self._tabs[key] = tab
            if key in tab_tips:
                ToolTip(tab, tab_tips[key])

        # Spacer
        tk.Frame(sidebar, bg=COLORS["bg_sidebar"]).pack(fill=tk.BOTH, expand=True)

        # Bottom sidebar buttons
        sep2 = tk.Frame(sidebar, bg=COLORS["border"], height=1)
        sep2.pack(fill=tk.X, padx=12, pady=(6, 6))

        bottom_btns = tk.Frame(sidebar, bg=COLORS["bg_sidebar"])
        bottom_btns.pack(fill=tk.X, padx=8, pady=(0, 8))

        for text, cmd, tip in [
            ("📂 Open Output", self.open_output_folder, "Open output folder in explorer"),
            ("🗑️ Clear Log", self.clear_log, "Clear the activity log"),
            ("❌ Exit", self.root.quit, "Exit application"),
        ]:
            btn = tk.Label(bottom_btns, text=text, font=FONTS["small"],
                           bg=COLORS["bg_sidebar"], fg=COLORS["text_muted"],
                           cursor="hand2", anchor=tk.W, padx=12, pady=6)
            btn.pack(fill=tk.X, pady=1)
            btn.bind("<Enter>", lambda e, b=btn: b.config(
                bg=COLORS["bg_card"], fg=COLORS["text_primary"]))
            btn.bind("<Leave>", lambda e, b=btn: b.config(
                bg=COLORS["bg_sidebar"], fg=COLORS["text_muted"]))
            btn.bind("<ButtonRelease-1>", lambda e, c=cmd: c())
            ToolTip(btn, tip)

    def _switch_category(self, key):
        self._current_category = key
        for k, tab in self._tabs.items():
            tab.set_active(k == key)
        self._populate_actions(key)

    # ── Content Area ─────────────────────────────────────────────────────

    def _build_content(self, parent):
        content = tk.Frame(parent, bg=COLORS["bg_darkest"])
        content.grid(row=0, column=1, sticky="nsew", padx=(0, 0))
        content.columnconfigure(0, weight=1)
        content.rowconfigure(2, weight=1)  # Log gets remaining space

        # Subtle top separator line
        top_sep = tk.Canvas(content, height=1, bg=COLORS["bg_darkest"], highlightthickness=0)
        top_sep.grid(row=0, column=0, sticky="ew", pady=(0, 0))
        top_sep.bind("<Configure>", lambda e: self._draw_content_separator(top_sep))

        # ── Drop Zone ──
        self._build_drop_zone(content)

        # ── Actions Panel ──
        self._build_actions_panel(content)

        # ── Info + Log (bottom half) ──
        bottom = tk.Frame(content, bg=COLORS["bg_darkest"])
        bottom.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 8))
        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(1, weight=1)

        # Binary Info
        self._build_info_panel(bottom)

        # Activity Log
        self._build_log_panel(bottom)

    def _draw_content_separator(self, canvas):
        canvas.delete("all")
        w = canvas.winfo_width()
        if w < 2:
            return
        # Gradient line from accent to transparent
        steps = min(w, 300)
        for i in range(steps):
            alpha = int(0.3 * (1 - i / steps) * 255)
            r, g, b = 0, 212, 255
            color = f"#{r:02x}{g:02x}{b:02x}"
            x = int(i * w / steps)
            x2 = int((i + 1) * w / steps)
            canvas.create_rectangle(x, 0, x2, 1, fill=color, outline="")

    # ── Drop Zone ────────────────────────────────────────────────────────

    def _build_drop_zone(self, parent):
        self._drop_glow_phase = 0
        self._drop_active = False

        self._drop_container = tk.Frame(parent, bg=COLORS["bg_darkest"])
        self._drop_container.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))

        self.drop_zone = tk.Canvas(self._drop_container, height=70,
                                   bg=COLORS["drop_zone_bg"], highlightthickness=0,
                                   cursor="hand2")
        self.drop_zone.pack(fill=tk.X)
        self.drop_zone.bind("<Configure>", lambda e: self._draw_drop_zone())
        self.drop_zone.bind("<ButtonRelease-1>", lambda e: self.browse_file())

        self._drop_glow_phase = 0
        self._drop_active = False

    def _blend(self, hex1, hex2, factor):
        r1, g1, b1 = int(hex1[1:3], 16), int(hex1[3:5], 16), int(hex1[5:7], 16)
        r2, g2, b2 = int(hex2[1:3], 16), int(hex2[3:5], 16), int(hex2[5:7], 16)
        r = int(r1 + (r2 - r1) * factor)
        g = int(g1 + (g2 - g1) * factor)
        b = int(b1 + (b2 - b1) * factor)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _draw_drop_zone(self, active=False):
        if not hasattr(self, "drop_zone"):
            return
        c = self.drop_zone
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 2:
            return

        bg = COLORS["drop_zone_active"] if active else COLORS["drop_zone_bg"]
        c.create_rectangle(0, 0, w, h, fill=bg, outline="")

        # Dashed border with optional pulse
        if active:
            border_color = COLORS["accent"]
        elif self._drop_glow_phase < 30 and not self.selected_file:
            # Pulse: slightly brighter border
            border_color = self._blend(COLORS["drop_zone_border"], COLORS["accent"], 0.3)
        else:
            border_color = COLORS["drop_zone_border"]

        dash_len = 10
        gap = 6
        for x in range(4, w - 4, dash_len + gap):
            c.create_line(x, 3, min(x + dash_len, w - 4), 3, fill=border_color, width=1)
            c.create_line(x, h - 3, min(x + dash_len, w - 4), h - 3, fill=border_color, width=1)
        for y in range(4, h - 4, dash_len + gap):
            c.create_line(3, y, 3, min(y + dash_len, h - 4), fill=border_color, width=1)
            c.create_line(w - 3, y, w - 3, min(y + dash_len, h - 4), fill=border_color, width=1)

        # Icon + Text
        if active:
            icon_color = COLORS["accent"]
            text_color = COLORS["text_bright"]
            icon = "⬇️"
            text = "Release to load file"
        elif self.selected_file:
            icon_color = COLORS["success"]
            text_color = COLORS["text_primary"]
            icon = "✅"
            fname = os.path.basename(self.selected_file)
            fsize = os.path.getsize(self.selected_file)
            text = f"{fname}  ({fsize:,} bytes)"
        else:
            icon_color = COLORS["accent"] if self._drop_glow_phase < 30 else COLORS["text_muted"]
            text_color = COLORS["text_secondary"]
            icon = "📁"
            hint = "Drop executable here or click to browse" if HAS_DND else "Click to browse for executable"
            text = hint

        c.create_text(w // 2 - 10, h // 2, text=icon, font=("Segoe UI Emoji", 16),
                       fill=icon_color, anchor=tk.E)
        c.create_text(w // 2 + 10, h // 2, text=text, font=FONTS["body"],
                       fill=text_color, anchor=tk.W)

    def _animate_drop_zone(self):
        """Subtle idle animation on the drop zone border."""
        if not self.selected_file and not self._drop_active:
            self._drop_glow_phase = (self._drop_glow_phase + 1) % 60
            # Pulse the border color slightly
            if hasattr(self, 'drop_zone'):
                self._draw_drop_zone(False)
        self.root.after(200, self._animate_drop_zone)

    # ── Actions Panel ────────────────────────────────────────────────────

    def _build_actions_panel(self, parent):
        self._actions_outer = tk.Frame(parent, bg=COLORS["bg_darkest"])
        self._actions_outer.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 6))

        # Header row with subtle background
        header = tk.Frame(self._actions_outer, bg=COLORS["bg_dark"],
                          highlightbackground=COLORS["border"], highlightthickness=1)
        header.pack(fill=tk.X, pady=(0, 6))

        inner_header = tk.Frame(header, bg=COLORS["bg_dark"])
        inner_header.pack(fill=tk.X, padx=10, pady=8)

        self._actions_title = tk.Label(inner_header, text="", font=FONTS["subtitle"],
                                        bg=COLORS["bg_dark"], fg=COLORS["text_primary"])
        self._actions_title.pack(side=tk.LEFT)

        # One-click button in the header
        self._one_click_btn = StyledButton(
            inner_header, text="⚡ ONE-CLICK FULL ANALYSIS", command=self.one_click_all,
            color="#a855f7", width=260, large=True,
            tooltip="Run all analysis tools in sequence")
        self._one_click_btn.pack(side=tk.RIGHT)

        # Actions container
        self._actions_frame = tk.Frame(self._actions_outer, bg=COLORS["bg_dark"],
                                        highlightbackground=COLORS["border"],
                                        highlightthickness=1)
        self._actions_frame.pack(fill=tk.X)

    def _populate_actions(self, category):
        # Clear existing buttons
        for child in self._actions_frame.winfo_children():
            child.destroy()

        cat = self._categories[category]
        self._actions_title.config(text=f"{cat['icon']}  {cat['label']} Tools")
        color = cat["color"]

        inner = tk.Frame(self._actions_frame, bg=COLORS["bg_dark"])
        inner.pack(fill=tk.X, padx=12, pady=12)

        buttons = self._get_category_buttons(category)

        # Layout buttons in rows of 4 with better spacing
        row_frame = None
        for i, (text, cmd, tip) in enumerate(buttons):
            if i % 4 == 0:
                row_frame = tk.Frame(inner, bg=COLORS["bg_dark"])
                row_frame.pack(fill=tk.X, pady=3)

            btn = StyledButton(row_frame, text=text, command=cmd, color=color,
                               width=200, tooltip=tip)
            btn.pack(side=tk.LEFT, padx=4, pady=3)

    def _get_category_buttons(self, category):
        if category == "dotnet":
            return [
                ("Analyze Assembly", self.analyze_dotnet,
                 "Analyze .NET assembly structure, references, and types"),
                ("Extract Metadata", self.extract_dotnet_metadata,
                 "Extract .NET metadata tables and type definitions"),
                ("Extract Resources", self.extract_dotnet_resources,
                 "Extract embedded .NET resources to files"),
                ("Decompile to C#", self.decompile_dotnet,
                 "Decompile .NET assembly back to C# source code"),
            ]
        elif category == "cpp":
            return [
                ("Binary Info", self.get_cpp_info,
                 "Get PE header info, sections, imports, exports"),
                ("Extract Strings", self.extract_cpp_strings,
                 "Extract all ASCII and Unicode strings from binary"),
                ("Analysis Report", self.create_cpp_report,
                 "Generate comprehensive analysis report"),
                ("Disassemble", self.disassemble_cpp,
                 "Disassemble to x86/x64 assembly using radare2 or objdump"),
                ("Pseudocode", self.generate_pseudocode_gui,
                 "Generate C-like pseudocode from static analysis"),
            ]
        elif category == "scan":
            return [
                ("Deep Scan", self.deep_scan_binary,
                 "Section entropy analysis, string extraction, import scan"),
                ("Extract Links", self.extract_links,
                 "Find URLs, domains, IPs, API paths embedded in binary"),
                ("Dump Sections", self.dump_sections,
                 "Dump all PE sections to individual .bin files"),
                ("Extract Embedded", self.extract_embedded,
                 "Find embedded PEs, images, ZIP archives inside binary"),
                ("XOR Brute-Force", self.xor_bruteforce,
                 "Try all single-byte XOR keys on high-entropy sections"),
                ("Try Decrypt", self.decrypt_executable,
                 "Attempt automatic decryption/unpacking"),
            ]
        elif category == "protect":
            return [
                ("Detect Protections", self.detect_protections,
                 "Identify protection schemes (Themida, VMProtect, etc.)"),
                ("Themida Unpack", self.unpack_themida,
                 "Analyze and attempt Themida/WinLicense unpacking"),
                ("VMProtect Unpack", self.unpack_vmprotect,
                 "Analyze and attempt VMProtect unpacking"),
                ("Full Analysis", self.full_decryption_analysis,
                 "Complete decryption analysis with all methods"),
            ]
        elif category == "patch":
            return [
                ("License Patch", self.keyauth_patch_gui,
                 "Detect and patch KeyAuth license checks, panels, HWID"),
            ]
        return []

    # ── Info Panel ───────────────────────────────────────────────────────

    def _build_info_panel(self, parent):
        info_header = tk.Frame(parent, bg=COLORS["bg_darkest"])
        info_header.grid(row=0, column=0, sticky="ew", pady=(0, 4))

        header_left = tk.Frame(info_header, bg=COLORS["bg_darkest"])
        header_left.pack(side=tk.LEFT)

        tk.Label(header_left, text="📋  Binary Information", font=FONTS["heading"],
                 bg=COLORS["bg_darkest"], fg=COLORS["text_primary"]).pack(side=tk.LEFT)

        # Copy button
        copy_btn = tk.Canvas(info_header, width=28, height=28, bg=COLORS["bg_darkest"],
                             highlightthickness=0, cursor="hand2")
        copy_btn.pack(side=tk.RIGHT, padx=(0, 8))
        self._draw_copy_btn(copy_btn, False)
        copy_btn.bind("<Enter>", lambda e: self._draw_copy_btn(copy_btn, True))
        copy_btn.bind("<Leave>", lambda e: self._draw_copy_btn(copy_btn, False))
        copy_btn.bind("<ButtonRelease-1>", lambda e: self._copy_info_panel())
        ToolTip(copy_btn, "Copy info (Ctrl+C)")

        info_border = tk.Frame(parent, bg=COLORS["border"], highlightthickness=0)
        info_border.grid(row=0, column=0, sticky="ew", pady=(22, 4))

        self.info_text = tk.Text(info_border, height=4, wrap=tk.WORD,
                                  bg=COLORS["bg_input"], fg=COLORS["accent"],
                                  font=FONTS["mono"], insertbackground=COLORS["accent"],
                                  selectbackground=COLORS["accent_dim"],
                                  selectforeground=COLORS["text_bright"],
                                  relief=tk.FLAT, bd=0, padx=10, pady=6,
                                  state=tk.DISABLED)
        self.info_text.pack(fill=tk.X, padx=1, pady=1)

        # Double-click to copy
        self.info_text.bind("<Double-Button-1>", lambda e: self._copy_info_panel())

    def _draw_copy_btn(self, canvas, hovered):
        canvas.delete("all")
        w, h = 28, 28
        bg = COLORS["bg_card"] if not hovered else COLORS["bg_card_hover"]
        border = COLORS["border"] if not hovered else COLORS["accent"]
        fg = COLORS["text_muted"] if not hovered else COLORS["accent"]
        r = 4
        points = [r, 0, w - r, 0, w, 0, w, r, w, h - r, w, h, w - r, h,
                  r, h, 0, h, 0, h - r, 0, r, 0, 0]
        canvas.create_polygon(points, smooth=True, fill=bg, outline=border)
        # Copy icon
        cx, cy = w // 2, h // 2
        canvas.create_rectangle(cx - 7, cy - 5, cx + 5, cy + 7, outline=fg, width=1.5)
        canvas.create_line(cx - 5, cy - 7, cx + 3, cy - 7, fill=fg, width=1.5)
        canvas.create_line(cx - 5, cy - 7, cx - 5, cy + 1, fill=fg, width=1.5)

    # ── Log Panel ────────────────────────────────────────────────────────

    def _build_log_panel(self, parent):
        log_header = tk.Frame(parent, bg=COLORS["bg_darkest"])
        log_header.grid(row=1, column=0, sticky="new", pady=(8, 4))

        header_left = tk.Frame(log_header, bg=COLORS["bg_darkest"])
        header_left.pack(side=tk.LEFT)

        tk.Label(header_left, text="🖥️  Activity Log", font=FONTS["heading"],
                 bg=COLORS["bg_darkest"], fg=COLORS["text_primary"]).pack(side=tk.LEFT)

        # Search bar
        search_frame = tk.Frame(log_header, bg=COLORS["bg_darkest"])
        search_frame.pack(side=tk.RIGHT)

        self._log_search_var = tk.StringVar()
        self._log_search_var.trace("w", lambda *args: self._filter_log())

        self.log_search_entry = tk.Entry(search_frame, textvariable=self._log_search_var,
                                          bg=COLORS["bg_input"], fg=COLORS["text_primary"],
                                          font=FONTS["small"], relief=tk.FLAT, bd=0,
                                          insertbackground=COLORS["accent"], width=22)
        self.log_search_entry.pack(side=tk.LEFT, padx=(0, 4))

        # Search icon canvas
        search_icon = tk.Canvas(search_frame, width=22, height=22, bg=COLORS["bg_input"],
                                highlightthickness=0)
        search_icon.pack(side=tk.LEFT)
        self._draw_search_icon(search_icon)
        self.log_search_entry.bind("<Escape>", lambda e: self._clear_log_search())

        # Placeholder for search
        def on_focus_in(e):
            if self.log_search_entry.cget("fg") == COLORS["text_muted"]:
                self.log_search_entry.config(fg=COLORS["text_primary"])

        def on_focus_out(e):
            if not self.log_search_entry.get():
                self.log_search_entry.config(fg=COLORS["text_muted"])

        self.log_search_entry.insert(0, "🔍 Search log...")
        self.log_search_entry.config(fg=COLORS["text_muted"])
        self.log_search_entry.bind("<FocusIn>", on_focus_in)
        self.log_search_entry.bind("<FocusOut>", on_focus_out)
        self.log_search_entry.bind("<Key>", lambda e: None)  # Clear placeholder on key

        log_border = tk.Frame(parent, bg=COLORS["border"])
        log_border.grid(row=1, column=0, sticky="nsew", pady=(28, 0))

        self.log_text = tk.Text(log_border, wrap=tk.WORD,
                                 bg=COLORS["bg_input"], fg=COLORS["text_secondary"],
                                 font=FONTS["mono_log"], insertbackground=COLORS["accent"],
                                 selectbackground=COLORS["accent_dim"],
                                 selectforeground=COLORS["text_bright"],
                                 relief=tk.FLAT, bd=0, padx=10, pady=6,
                                 state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        # Configure colored tags
        self.log_text.tag_configure("timestamp", foreground=COLORS["text_muted"])
        self.log_text.tag_configure("info", foreground=COLORS["info"])
        self.log_text.tag_configure("success", foreground=COLORS["success"])
        self.log_text.tag_configure("warning", foreground=COLORS["warning"])
        self.log_text.tag_configure("error", foreground=COLORS["error"])
        self.log_text.tag_configure("normal", foreground=COLORS["text_secondary"])
        self.log_text.tag_configure("header", foreground=COLORS["accent"], font=FONTS["mono"])
        self.log_text.tag_configure("separator", foreground=COLORS["text_muted"])
        self.log_text.tag_configure("highlight", background=COLORS["accent_dim"], foreground=COLORS["text_bright"])

        # Scrollbar
        scrollbar = tk.Scrollbar(self.log_text, orient=tk.VERTICAL,
                                  command=self.log_text.yview,
                                  bg=COLORS["scrollbar_fg"],
                                  troughcolor=COLORS["scrollbar_bg"],
                                  activebackground=COLORS["accent_dim"],
                                  highlightthickness=0, bd=0, width=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

        # Right-click context menu
        self._log_context_menu = tk.Menu(self.log_text, tearoff=0, bg=COLORS["bg_card"],
                                          fg=COLORS["text_primary"],
                                          activebackground=COLORS["accent_dim"],
                                          activeforeground=COLORS["text_bright"],
                                          font=FONTS["small"], relief=tk.SOLID,
                                          bd=1)
        self._log_context_menu.add_command(label="Copy selected",
                                            command=self._copy_log_selection)
        self._log_context_menu.add_command(label="Copy all",
                                            command=self._copy_log_all)
        self._log_context_menu.add_separator()
        self._log_context_menu.add_command(label="Clear log",
                                            command=self.clear_log)
        self.log_text.bind("<Button-3>", self._show_log_context_menu)

        # Store all log entries for filtering
        self._log_entries = []
        self._log_filtered = False

    def _draw_search_icon(self, canvas):
        canvas.delete("all")
        w, h = 22, 22
        cx, cy = w // 2, h // 2
        color = COLORS["text_muted"]
        # Magnifying glass
        canvas.create_oval(cx - 6, cy - 6, cx + 2, cy + 2, outline=color, width=1.5)
        canvas.create_line(cx + 2, cy + 2, cx + 7, cy + 7, fill=color, width=1.5)

    def _show_log_context_menu(self, event):
        try:
            self._log_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._log_context_menu.grab_release()

    def _copy_log_selection(self):
        try:
            sel = self.log_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            if sel:
                self.root.clipboard_clear()
                self.root.clipboard_append(sel)
                Toast(self.root, "Selection copied", "success", 1500)
        except tk.TclError:
            pass

    def _copy_log_all(self):
        content = self.log_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        Toast(self.root, "Full log copied", "success", 1500)

    def _clear_log_search(self):
        self._log_search_var.set("")
        self.log_search_entry.delete(0, tk.END)
        self.log_search_entry.insert(0, "🔍 Search log...")
        self.log_search_entry.config(fg=COLORS["text_muted"])
        self._filter_log()

    def _filter_log(self):
        if not hasattr(self, "log_text") or not hasattr(self, "_log_entries"):
            return
        query = self._log_search_var.get().strip()
        if not query or query == "🔍 Search log...":
            # Show all
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            for entry in self._log_entries:
                self.log_text.insert(tk.END, entry["full_text"])
            self.log_text.config(state=tk.DISABLED)
            self._log_filtered = False
            return

        self._log_filtered = True
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        query_lower = query.lower()

        for entry in self._log_entries:
            if query_lower in entry["raw_text"].lower():
                self.log_text.insert(tk.END, entry["full_text"])
                # Highlight matching text
                self._highlight_search(self.log_text, query)

        self.log_text.config(state=tk.DISABLED)

    def _highlight_search(self, text_widget, query):
        text_widget.tag_remove("highlight", "1.0", tk.END)
        query_lower = query.lower()
        content = text_widget.get("1.0", tk.END).lower()
        start = "1.0"
        while True:
            idx = content.find(query_lower, text_widget.index(start))
            if idx == -1:
                break
            pos = text_widget.index(f"1.0 + {idx} chars")
            end_pos = text_widget.index(f"{pos} + {len(query)} chars")
            text_widget.tag_add("highlight", pos, end_pos)
            start = end_pos
            if text_widget.compare(start, ">=", tk.END):
                break

    # ── Status Bar ───────────────────────────────────────────────────────

    def _build_status_bar(self):
        status_bar = tk.Frame(self.root, bg=COLORS["bg_dark"], height=32)
        status_bar.grid(row=2, column=0, sticky="ew")
        status_bar.grid_propagate(False)
        status_bar.columnconfigure(1, weight=1)

        # Progress bar
        self.progress = ttk.Progressbar(status_bar, mode='indeterminate', length=120,
                                         style="Accent.Horizontal.TProgressbar")
        self.progress.grid(row=0, column=0, padx=(12, 8), pady=6)

        # Status text
        self.status_label = tk.Label(status_bar, text="● Ready", font=FONTS["small"],
                                      bg=COLORS["bg_dark"], fg=COLORS["success"],
                                      anchor=tk.W)
        self.status_label.grid(row=0, column=1, sticky=tk.W)

        # Right side info
        self._file_type_label = tk.Label(status_bar, text="", font=FONTS["small"],
                                          bg=COLORS["bg_dark"], fg=COLORS["text_muted"],
                                          anchor=tk.E)
        self._file_type_label.grid(row=0, column=2, sticky=tk.E, padx=(0, 16))

    # ── Drag & Drop ──────────────────────────────────────────────────────

    def setup_drag_drop(self):
        if HAS_DND:
            for widget in (self.root, self.drop_zone):
                widget.drop_target_register('*')
                widget.dnd_bind('<<Drop>>', self.on_drop)
                widget.dnd_bind('<<DragEnter>>', self.on_drag_enter)
                widget.dnd_bind('<<DragLeave>>', self.on_drag_leave)

    def _set_drop_zone(self, active):
        self._drop_active = active
        self._draw_drop_zone(active)

    def on_drag_enter(self, event):
        self._set_drop_zone(True)

    def on_drag_leave(self, event):
        self._set_drop_zone(False)

    def on_drop(self, event):
        self._set_drop_zone(False)
        raw = event.data.strip().strip('{}').strip('"')
        if os.path.isfile(raw):
            self.load_file(raw)
        else:
            messagebox.showwarning("Invalid File", "Please drop a valid executable file.")

    # ── File Loading ─────────────────────────────────────────────────────

    def load_file(self, file_path):
        self.selected_file = os.path.normpath(file_path)
        filename = os.path.basename(file_path)
        fsize = os.path.getsize(file_path)

        self.file_label.config(text=f"  {filename}  ({fsize:,} bytes)",
                               fg=COLORS["accent"])
        self.add_log(f"Selected: {file_path}", "info")

        self._add_recent_file(file_path)

        output_name = Path(file_path).stem
        self.current_output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", output_name)
        os.makedirs(self.current_output_dir, exist_ok=True)

        self.display_info({"file": filename, "size": f"{fsize:,} bytes", "path": file_path})
        self.auto_detect_file_type(file_path)
        self._draw_drop_zone(False)

    def auto_detect_file_type(self, file_path):
        def detect():
            try:
                self.set_status("Detecting file type…")
                analysis = self.dotnet_unpacker.analyze_assembly(file_path)
                if analysis.get("assembly_info", {}).get("name"):
                    self.add_log("  ╰→ Type: .NET executable", "success")
                    self._update_file_type_label(".NET Assembly")
                    self._update_file_badge("🔷 .NET", COLORS["cat_dotnet"])
                else:
                    info = self.cpp_unpacker.get_binary_info(file_path)
                    arch = info.get("architecture", "Unknown")
                    if arch != "Unknown":
                        self.add_log(f"  ╰→ Type: C++ executable ({arch})", "success")
                        self._update_file_type_label(f"C++ ({arch})")
                        self._update_file_badge("⚙️ Native", COLORS["cat_cpp"])
                    else:
                        self.add_log("  ╰→ Type: Unknown executable", "warning")
                        self._update_file_type_label("Unknown")
                        self._update_file_badge("❓ Unknown", COLORS["warning"])
            except Exception as e:
                self.add_log(f"  ╰→ Detection note: {str(e)}", "warning")
            finally:
                self.set_status("Ready")
        threading.Thread(target=detect, daemon=True).start()

    def _update_file_type_label(self, text):
        def update():
            self._file_type_label.config(text=f"Type: {text}")
        self.root.after(0, update)

    def _update_file_badge(self, badge_text, color):
        """Show a colored badge next to file type."""
        def update():
            if hasattr(self, '_file_badge_label'):
                self._file_badge_label.config(text=badge_text, fg=color)
            else:
                self._file_badge_label = tk.Label(
                    self._file_type_label.master, text=badge_text, font=FONTS["small"],
                    bg=COLORS["bg_dark"], fg=color, anchor=tk.E, padx=8, pady=2)
                self._file_badge_label.grid(row=0, column=3, sticky=tk.E, padx=(8, 16))
        self.root.after(0, update)

    # ── Recent Files ─────────────────────────────────────────────────────

    def _load_recent_files(self):
        """Load recent files from JSON."""
        try:
            path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "recent_files.json")
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _save_recent_files(self):
        """Save recent files to JSON."""
        try:
            path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "recent_files.json")
            with open(path, 'w') as f:
                json.dump(self._recent_files[:10], f, indent=2)
        except Exception:
            pass

    def _add_recent_file(self, file_path):
        """Add file to recent files list."""
        entry = {
            "path": file_path,
            "name": os.path.basename(file_path),
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._recent_files = [f for f in self._recent_files if f["path"] != file_path]
        self._recent_files.insert(0, entry)
        self._save_recent_files()

    def _show_recent_files_menu(self):
        """Show recent files in a popup menu."""
        if not self._recent_files:
            Toast(self.root, "No recent files", "info", 1500)
            return

        menu = tk.Menu(self.root, tearoff=0, bg=COLORS["bg_card"],
                       fg=COLORS["text_primary"],
                       activebackground=COLORS["accent_dim"],
                       activeforeground=COLORS["text_bright"],
                       font=FONTS["small"], relief=tk.SOLID, bd=1)

        for entry in self._recent_files[:10]:
            label = f"{entry['name']}  ({entry['time']})"
            path = entry["path"]
            menu.add_command(label=label, command=lambda p=path: self.load_file(p))

        menu.add_separator()
        menu.add_command(label="Clear recent files",
                         command=self._clear_recent_files)

        menu.tk_popup(self.root.winfo_rootx() + 200, self.root.winfo_rooty() + 60)

    def _clear_recent_files(self):
        self._recent_files.clear()
        self._save_recent_files()
        Toast(self.root, "Recent files cleared", "success", 1500)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select an executable",
            filetypes=[("Executables", "*.exe *.dll"), ("PE files", "*.exe *.dll *.scr *.cpl"), ("All files", "*.*")]
        )
        if file_path:
            self.load_file(file_path)

    # ── Async Runner ─────────────────────────────────────────────────────

    def _require_file(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a file first")
            return False
        return True

    def _run_async(self, label, target, success_msg=None):
        if not self._require_file():
            return
        self._operation_active = True
        def wrapper():
            try:
                self.set_status(label)
                self.progress.start()
                result = target()
                if success_msg:
                    self.add_log(success_msg, "success")
                    Toast(self.root, success_msg, "success", 2500)
                return result
            except Exception as e:
                self.add_log(f"Error: {str(e)}", "error")
                Toast(self.root, f"Error: {str(e)}", "error", 3500)
            finally:
                self.progress.stop()
                self._operation_active = False
                self.set_status("Ready")
        threading.Thread(target=wrapper, daemon=True).start()

    # ── .NET Actions ─────────────────────────────────────────────────────

    def analyze_dotnet(self):
        def run():
            self.add_log("Analyzing .NET assembly…", "info")
            analysis = self.dotnet_unpacker.analyze_assembly(self.selected_file)
            self.display_info(analysis)
            with open(os.path.join(self.current_output_dir, "dotnet_analysis.json"), 'w') as f:
                json.dump(analysis, f, indent=2)
            self.add_log("Analysis saved", "success")
            return "Analysis complete"
        self._run_async("Analyzing .NET…", run, "✓ Analysis complete!")

    def extract_dotnet_metadata(self):
        def run():
            self.add_log("Extracting .NET metadata…", "info")
            metadata = self.dotnet_unpacker.extract_metadata(self.selected_file)
            self.display_info(metadata)
            with open(os.path.join(self.current_output_dir, "dotnet_metadata.json"), 'w') as f:
                json.dump(metadata, f, indent=2)
            return "Metadata extraction complete"
        self._run_async("Extracting metadata…", run, "✓ Metadata extraction complete!")

    def extract_dotnet_resources(self):
        def run():
            self.add_log("Extracting .NET resources…", "info")
            resources_dir = os.path.join(self.current_output_dir, "resources")
            extracted = self.dotnet_unpacker.extract_resources(self.selected_file, resources_dir)
            self.add_log(f"Extracted {len(extracted)} resources", "success")
            for r in extracted:
                self.add_log(f"  ├─ {os.path.basename(r)}")
            return f"Extracted {len(extracted)} resources"
        self._run_async("Extracting resources…", run, "✓ Resource extraction complete!")

    def decompile_dotnet(self):
        def run():
            self.add_log("Decompiling .NET assembly to C#…", "info")
            decompiled_dir = os.path.join(self.current_output_dir, "decompiled_csharp")
            os.makedirs(decompiled_dir, exist_ok=True)
            success = self.dotnet_unpacker.decompile_to_csharp_ilspy(self.selected_file, decompiled_dir)
            if success:
                self.add_log(f"Output: {decompiled_dir}", "success")
                return "C# decompilation successful"
            else:
                return "Source structure extracted via reflection"
        self._run_async("Decompiling…", run)

    # ── C++ Actions ──────────────────────────────────────────────────────

    def get_cpp_info(self):
        def run():
            self.add_log("Analyzing C++ binary…", "info")
            info = self.cpp_unpacker.get_binary_info(self.selected_file)
            self.display_info(info)
            with open(os.path.join(self.current_output_dir, "cpp_binary_info.json"), 'w') as f:
                json.dump(info, f, indent=2)
            return "Binary analysis complete"
        self._run_async("Analyzing C++…", run, "✓ Binary analysis complete!")

    def extract_cpp_strings(self):
        def run():
            self.add_log("Extracting strings from binary…", "info")
            strings_file = os.path.join(self.current_output_dir, "cpp_strings.txt")
            strings = self.cpp_unpacker.extract_strings(self.selected_file, strings_file)
            self.add_log(f"Extracted {len(strings)} strings → {strings_file}", "success")
            return f"Extracted {len(strings)} strings"
        self._run_async("Extracting strings…", run, "✓ String extraction complete!")

    def create_cpp_report(self):
        def run():
            self.add_log("Creating C++ analysis report…", "info")
            report_path = self.cpp_unpacker.create_analysis_report(self.selected_file, self.current_output_dir)
            self.add_log(f"Report: {report_path}", "success")
            return "Report created"
        self._run_async("Creating report…", run, "✓ Analysis report created!")

    def disassemble_cpp(self):
        def run():
            self.add_log("Disassembling C++ executable…", "info")
            disasm_dir = os.path.join(self.current_output_dir, "disassembly")
            os.makedirs(disasm_dir, exist_ok=True)
            success = False
            try:
                success = self.cpp_unpacker.disassemble_with_radare2(self.selected_file, disasm_dir)
            except Exception:
                pass
            if not success:
                success = self.cpp_unpacker.disassemble_with_objdump(self.selected_file, disasm_dir)
            if success:
                self.add_log(f"Assembly saved to: {disasm_dir}", "success")
                return "Disassembly complete"
            else:
                self.cpp_unpacker.generate_pseudocode(self.selected_file, disasm_dir)
                return "Pseudocode generated (install radare2 or objdump for full disassembly)"
        self._run_async("Disassembling…", run)

    def generate_pseudocode_gui(self):
        def run():
            self.add_log("Generating pseudocode from static analysis…", "info")
            disasm_dir = os.path.join(self.current_output_dir, "disassembly")
            os.makedirs(disasm_dir, exist_ok=True)
            if self.cpp_unpacker.generate_pseudocode(self.selected_file, disasm_dir):
                self.add_log(f"Pseudocode saved to: {disasm_dir}\\pseudocode.c", "success")
                return "Pseudocode generated"
            else:
                return "Pseudocode generation failed"
        self._run_async("Generating pseudocode…", run)

    # ── Deep Scan ────────────────────────────────────────────────────────

    def deep_scan_binary(self):
        def run():
            self.add_log("Deep static analysis…", "info")
            deep_dir = os.path.join(self.current_output_dir, "deep_scan")
            results = self.cpp_unpacker.deep_scan(self.selected_file, deep_dir)
            secs = results.get("section_entropy", [])
            self.add_log(f"Sections: {len(secs)}")
            for s in secs:
                flag = " ⚠ HIGH ENTROPY" if s['entropy'] > 7.0 else ""
                level = "warning" if s['entropy'] > 7.0 else "normal"
                self.add_log(f"  {s['name']:12s} {s['size']:>8,} B  entropy={s['entropy']:.2f}{flag}", level)
            strs = results.get("strings", {})
            self.add_log(f"Strings: {strs.get('ascii_count', 0):,} ASCII, {strs.get('unicode_count', 0):,} Unicode")
            imps = results.get("imports", {})
            self.add_log(f"Imports: {len(imps)} DLLs")
            net = results.get("network", {})
            for key, label in [("urls", "URLs"), ("domains", "Domains"), ("ip_addresses", "IPs")]:
                items = net.get(key, [])
                if items:
                    self.add_log(f"  {label}: {len(items)}", "info")
                    for item in items[:5]:
                        self.add_log(f"    ├─ {item[:120]}")
            crypto = results.get("crypto_constants", [])
            if crypto:
                self.add_log(f"Crypto: {', '.join(crypto)}", "warning")
            return "Deep scan complete"
        self._run_async("Deep scanning…", run, "✓ Deep scan complete!")

    # ── Link Extraction ─────────────────────────────────────────────────

    def extract_links(self):
        def run():
            self.add_log("Scanning for network indicators…", "info")
            with open(self.selected_file, 'rb') as f:
                data = f.read()
            net = self.cpp_unpacker._scan_network_indicators(data)
            total = sum(len(v) for v in net.values())
            self.add_log(f"Found {total} network indicators", "success")
            out_dir = os.path.join(self.current_output_dir, "links_extracted")
            os.makedirs(out_dir, exist_ok=True)
            rpath = os.path.join(out_dir, "network_indicators.txt")
            with open(rpath, 'w', encoding='utf-8') as f:
                f.write(f"Network Indicators: {os.path.basename(self.selected_file)}\nTotal: {total}\n" + "=" * 60 + "\n\n")
                for key, label in [("urls", "URLs"), ("domains", "Domains"), ("ip_addresses", "IPs"),
                                   ("ip_ports", "IP:Port"), ("api_paths", "API Paths"),
                                   ("hex_urls", "Hex URLs"), ("b64_urls", "Base64 URLs")]:
                    items = net.get(key, [])
                    f.write(f"--- {label} ({len(items)}) ---\n")
                    for item in items:
                        f.write(f"  {item}\n")
                    f.write("\n")
            for key, label in [("urls", "URLs"), ("domains", "Domains"), ("ip_addresses", "IPs")]:
                items = net.get(key, [])
                if items:
                    self.add_log(f"  {label}: {len(items)}", "info")
                    for item in items[:5]:
                        self.add_log(f"    ├─ {item[:130]}")
            self.display_info({"total_indicators": total, "urls": len(net.get("urls", [])),
                               "domains": len(net.get("domains", [])), "ip_addresses": len(net.get("ip_addresses", []))})
            return f"Found {total} network indicators"
        self._run_async("Extracting links…", run, "✓ Link extraction complete!")

    # ── Dump Sections ───────────────────────────────────────────────────

    def dump_sections(self):
        def run():
            self.add_log("Dumping all sections…", "info")
            with open(self.selected_file, 'rb') as f:
                data = f.read()
            pe_off = struct.unpack('<I', data[60:64])[0]
            num_sects = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
            opt_hdr_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
            sect_start = pe_off + 24 + opt_hdr_size
            out_dir = os.path.join(self.current_output_dir, "dumped_sections")
            os.makedirs(out_dir, exist_ok=True)
            count = 0
            for i in range(num_sects):
                off = sect_start + i * 40
                name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                rsize = struct.unpack('<I', data[off+16:off+20])[0]
                rptr = struct.unpack('<I', data[off+20:off+24])[0]
                if rptr > 0 and rsize > 0:
                    fpath = os.path.join(out_dir, f"section_{name}.bin")
                    with open(fpath, 'wb') as fh:
                        fh.write(data[rptr:rptr+rsize])
                    self.add_log(f"  ├─ {name}: {rsize:,} B → {fpath}")
                    count += 1
            self.add_log(f"Dumped {count} sections to {out_dir}", "success")
            return f"Dumped {count} sections"
        self._run_async("Dumping sections…", run, "✓ Sections dumped!")

    # ── Extract Embedded ────────────────────────────────────────────────

    def extract_embedded(self):
        def run():
            self.add_log("Scanning for embedded files (PEs, images, ZIPs)…", "info")
            with open(self.selected_file, 'rb') as f:
                data = f.read()
            out_dir = os.path.join(self.current_output_dir, "extracted_embedded")
            os.makedirs(out_dir, exist_ok=True)

            found = []

            # Embedded PEs
            idx = 0
            pe_count = 0
            while idx < len(data) - 64:
                pos = data.find(b'MZ', idx)
                if pos == -1 or pos > len(data) - 64:
                    break
                if pos + 64 > len(data):
                    break
                pe_off_val = struct.unpack('<I', data[pos+60:pos+64])[0]
                sig_off = pos + pe_off_val
                if sig_off + 4 <= len(data) and data[sig_off:sig_off+4] == b'PE\x00\x00':
                    fpath = os.path.join(out_dir, f"embedded_pe_{pe_count}.exe")
                    try:
                        img_size = struct.unpack('<I', data[sig_off+80:sig_off+84])[0]
                    except:
                        img_size = 0
                    end = min(pos + max(img_size, 4096), len(data))
                    with open(fpath, 'wb') as fh:
                        fh.write(data[pos:end])
                    found.append(f"PE #{pe_count} @ 0x{pos:x}")
                    pe_count += 1
                    idx = pos + 4
                else:
                    idx = pos + 2
            if pe_count:
                self.add_log(f"  Embedded PEs: {pe_count}", "info")

            # Images (PNG, JPEG, GIF)
            for sig, ext in [(b'\x89PNG', 'png'), (b'\xff\xd8\xff', 'jpg'), (b'GIF8', 'gif')]:
                idx = 0
                img_count = 0
                while True:
                    pos = data.find(sig, idx)
                    if pos == -1:
                        break
                    fpath = os.path.join(out_dir, f"image_{img_count}.{ext}")
                    with open(fpath, 'wb') as fh:
                        fh.write(data[pos:pos+min(1024*1024, len(data)-pos)])
                    img_count += 1
                    idx = pos + 4
                if img_count:
                    self.add_log(f"  Images (.{ext}): {img_count}", "info")
                    found.append(f"Images: {img_count} .{ext}")

            # ZIPs
            idx = 0
            zip_count = 0
            while True:
                pos = data.find(b'PK\x03\x04', idx)
                if pos == -1:
                    break
                fpath = os.path.join(out_dir, f"archive_{zip_count}.zip")
                with open(fpath, 'wb') as fh:
                    fh.write(data[pos:pos+min(10*1024*1024, len(data)-pos)])
                zip_count += 1
                idx = pos + 4
            if zip_count:
                self.add_log(f"  ZIP archives: {zip_count}", "info")

            if not found:
                self.add_log("  No embedded files found", "warning")
            else:
                self.add_log(f"All extracted to: {out_dir}", "success")
            return f"Found {len(found)} embedded items"
        self._run_async("Extracting embedded…", run, "✓ Embedded extraction complete!")

    # ── XOR Brute-Force ─────────────────────────────────────────────────

    def xor_bruteforce(self):
        def run():
            self.add_log("XOR brute-force on high-entropy sections…", "info")
            with open(self.selected_file, 'rb') as f:
                data = f.read()
            pe_off = struct.unpack('<I', data[60:64])[0]
            num_sects = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
            opt_hdr_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
            sect_start = pe_off + 24 + opt_hdr_size
            out_dir = os.path.join(self.current_output_dir, "xor_bruteforce")
            os.makedirs(out_dir, exist_ok=True)

            high_secs = []
            for i in range(num_sects):
                off = sect_start + i * 40
                name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                rsize = struct.unpack('<I', data[off+16:off+20])[0]
                rptr = struct.unpack('<I', data[off+20:off+24])[0]
                if rptr > 0 and rsize > 0:
                    chunk = data[rptr:rptr+min(rsize, 256*1024)]
                    import math
                    ent = 0.0
                    for c in range(256):
                        fq = chunk.count(bytes([c])) / len(chunk)
                        if fq > 0:
                            ent -= fq * math.log2(fq)
                    if ent > 7.5:
                        high_secs.append((name, rptr, rsize))

            if not high_secs:
                self.add_log("  No high-entropy sections found (nothing to brute-force)", "warning")
                return "No high-entropy sections"

            total_keys = 0
            for sec_name, rptr, rsize in high_secs:
                sec_data = data[rptr:rptr+min(rsize, 256*1024)]
                sec_out = os.path.join(out_dir, sec_name)
                os.makedirs(sec_out, exist_ok=True)
                found = 0
                for key in range(256):
                    dec = bytes(b ^ key for b in sec_data)
                    printable_pct = sum(1 for b in dec if 32 <= b <= 126) / len(dec) * 100
                    has_url = b'http' in dec or b'://' in dec
                    if printable_pct > 70 or (printable_pct > 40 and has_url):
                        fpath = os.path.join(sec_out, f"xor_0x{key:02x}.bin")
                        with open(fpath, 'wb') as fh:
                            fh.write(dec)
                        found += 1
                if found:
                    self.add_log(f"  {sec_name}: {found} promising XOR keys → {sec_out}", "success")
                total_keys += found

            if total_keys:
                self.add_log(f"Saved {total_keys} XOR-decrypted candidates to {out_dir}", "success")
            else:
                self.add_log("  No simple XOR key found (encryption is stronger than single-byte XOR)", "warning")
            return f"Tested {256 * len(high_secs)} keys, found {total_keys} candidates"
        self._run_async("XOR brute-force…", run, "✓ XOR brute-force complete!")

    # ── Protection / Decryption ─────────────────────────────────────────

    def detect_protections(self):
        def run():
            self.add_log("Scanning for protections…", "info")
            detector = ProtectionDetector(self.selected_file)
            protections = detector.detect_protections()
            if not protections:
                self.add_log("  No protections detected", "success")
                self.display_info({"status": "No protections detected"})
            else:
                self.add_log(f"  Found {len(protections)} protection(s):", "warning")
                for name, info in protections.items():
                    conf = info.get('confidence', 'N/A')
                    ent = info.get('entropy', '')
                    extra = f" (entropy: {ent})" if ent else ""
                    self.add_log(f"    ├─ {name} (confidence: {conf}%){extra}", "warning")
                self.display_info(protections)
                with open(os.path.join(self.current_output_dir, "protections_detected.json"), 'w') as f:
                    json.dump(protections, f, indent=2)
            return "Protection scan complete"
        self._run_async("Scanning protections…", run, "✓ Protection scan complete!")

    def decrypt_executable(self):
        def run():
            self.add_log("Attempting decryption/unpack…", "info")
            output_path = os.path.join(self.current_output_dir, "decrypted.exe")
            success, message = self.decryption_manager.decryptor.decrypt_executable(
                self.selected_file, output_path, method="auto")
            if success:
                self.add_log(f"  Decrypted: {output_path}", "success")
            self.add_log(f"  Result: {message}", "success" if success else "warning")
            return message
        self._run_async("Decrypting…", run)

    def full_decryption_analysis(self):
        def run():
            self.add_log("Full decryption analysis…", "info")
            decrypt_dir = os.path.join(self.current_output_dir, "decryption_analysis")
            os.makedirs(decrypt_dir, exist_ok=True)
            results = self.decryption_manager.analyze_and_decrypt(self.selected_file, decrypt_dir)
            if results.get("protections"):
                self.add_log("  Protections:", "warning")
                for p in results["protections"]:
                    self.add_log(f"    ├─ {p}", "warning")
            if results.get("recommendations"):
                self.add_log("  Recommendations:", "info")
                for r in results["recommendations"]:
                    self.add_log(f"    ├─ {r}")
            self.display_info(results)
            return "Full analysis complete"
        self._run_async("Full analysis…", run, "✓ Full analysis complete!")

    def unpack_themida(self):
        def run():
            self.add_log("Themida analysis…", "info")
            tu = ThemidaUnpacker()
            themida_dir = os.path.join(self.current_output_dir, "themida_unpack")
            os.makedirs(themida_dir, exist_ok=True)
            report = tu.generate_analysis_report(self.selected_file, themida_dir)
            self.add_log(f"  Confidence: {report['detection']['confidence']}%", "info")
            self.add_log(f"  Difficulty: {report['difficulty_level']}", "warning")
            self.display_info(report)
            return "Themida analysis complete"
        self._run_async("Themida analysis…", run, "✓ Themida analysis complete!")

    def unpack_vmprotect(self):
        def run():
            self.add_log("VMProtect unpacking…", "info")
            vu = VMProtectUnpacker()
            vmp_dir = os.path.join(self.current_output_dir, "vmprotect_unpack")
            os.makedirs(vmp_dir, exist_ok=True)
            success, message = vu.unpack_executable(self.selected_file, vmp_dir)
            self.add_log(f"  Result: {message}", "success" if success else "warning")
            if success:
                report = vu.generate_analysis_report(self.selected_file, vmp_dir)
                self.display_info(report)
            return message
        self._run_async("VMProtect unpacking…", run, "✓ VMProtect unpack complete!")

    def keyauth_patch_gui(self):
        if not self._require_file():
            return
        self.add_log("Scanning for KeyAuth license panels…", "info")
        results = self.keyauth_patcher.scan(self.selected_file)
        self.add_log(f"  License URL: {results.get('license_url', 'N/A')}")
        self.add_log(f"  Owner ID: {results.get('owner_id', 'N/A')}")
        self.add_log(f"  App Name: {results.get('app_name', 'N/A')}")
        self.add_log(f"  Discord Webhooks: {len(results.get('discord_webhooks', []))}")
        self.add_log(f"  HWID checks: {len(results.get('hwid_strings', []))}")
        self.add_log(f"  Login strings: {len(results.get('login_strings', []))}")

        if not results.get('owner_id'):
            self.add_log("  No KeyAuth panels detected", "warning")
            return

        patch_dir = os.path.join(self.current_output_dir, "keyauth_patch")
        os.makedirs(patch_dir, exist_ok=True)

        owner_id = results['owner_id']
        msg = (f"KeyAuth detected!\n"
               f"Owner: {owner_id}\n"
               f"Webhooks: {len(results.get('discord_webhooks',[]))}\n"
               f"HWID: {len(results.get('hwid_strings',[]))}\n\n"
               f"Apply: direct login + panel removal + HWID bypass?")
        apply = messagebox.askyesno("KeyAuth Patcher", msg)
        if not apply:
            self.add_log("  Patch cancelled", "warning")
            return

        def run():
            self.set_status("Patching KeyAuth…")
            self.progress.start()
            try:
                output_path = os.path.join(patch_dir, os.path.basename(self.selected_file))
                patch_results = self.keyauth_patcher.patch(
                    self.selected_file, output_path=output_path,
                    remove_panels=True, direct_login=True, dry_run=False
                )
                count = patch_results['patch_count']
                self.add_log(f"  Applied {count} patches!", "success")
                self.add_log(f"  Output: {output_path}", "success")
                for p in patch_results['patches'][:15]:
                    self.add_log(f"    ├─ {p}")
                if len(patch_results['patches']) > 15:
                    self.add_log(f"    ╰─ +{len(patch_results['patches'])-15} more")
                self.keyauth_patcher.save_report(patch_results, patch_dir)
                self.add_log(f"  Report: {patch_dir}\\keyauth_patch_report.txt", "info")
                self.add_log(f"  Backup: {self.selected_file}.bak", "info")
            except Exception as e:
                self.add_log(f"  Error: {e}", "error")
            finally:
                self.progress.stop()
                self.set_status("Ready")
        threading.Thread(target=run, daemon=True).start()

    # ── One-Click Everything ────────────────────────────────────────────

    def one_click_all(self):
        if not self._require_file():
            return
        def run():
            self.add_log("═" * 55, "separator")
            self.add_log("⚡  ONE-CLICK FULL ANALYSIS STARTED", "header")
            self.add_log("═" * 55, "separator")

            self.progress.start()
            self._operation_active = True
            steps = [
                ("Detecting protections", lambda: self._run_detect_protections_sync()),
                ("Getting binary info", lambda: self._run_binary_info_sync()),
                ("Deep scanning", lambda: self._run_deep_scan_sync()),
                ("Extracting links", lambda: self._run_links_sync()),
                ("Dumping sections", lambda: self._run_dump_sections_sync()),
                ("Extracting embedded", lambda: self._run_embedded_sync()),
                ("XOR brute-force", lambda: self._run_xor_sync()),
            ]

            total = len(steps)
            for i, (name, fn) in enumerate(steps):
                if not self._operation_active:
                    break
                pct = int((i / total) * 100)
                self.add_log(f"\n▸ {name}… [{pct}%]", "info")
                self.set_status(f"{name} ({pct}%)")
                try:
                    fn()
                    self.add_log(f"  ✓ {name} done", "success")
                except Exception as e:
                    self.add_log(f"  ✗ {name} FAILED: {e}", "error")

            self.progress.stop()
            self._operation_active = False
            self.add_log("")
            self.add_log("═" * 55, "separator")
            self.add_log("✓  ONE-CLICK FULL ANALYSIS COMPLETE", "header")
            self.add_log(f"   All output saved to: {self.current_output_dir}", "success")
            self.add_log("═" * 55, "separator")
            self.set_status("Ready")
            Toast(self.root, "Full analysis complete!", "success", 3000)
            messagebox.showinfo("Complete", "Full analysis complete! Check output folder.")

        threading.Thread(target=run, daemon=True).start()

    # Synchronous helpers for one-click
    def _run_detect_protections_sync(self):
        detector = ProtectionDetector(self.selected_file)
        prot = detector.detect_protections()
        self.add_log(f"  {len(prot)} protection(s) found")
        for name, info in prot.items():
            self.add_log(f"    ├─ {name} ({info.get('confidence', 'N/A')}%)")
        with open(os.path.join(self.current_output_dir, "protections_detected.json"), 'w') as f:
            json.dump(prot, f, indent=2)

    def _run_binary_info_sync(self):
        info = self.cpp_unpacker.get_binary_info(self.selected_file)
        self.add_log(f"  Arch: {info['architecture']}, Sections: {len(info['sections'])}")
        with open(os.path.join(self.current_output_dir, "cpp_binary_info.json"), 'w') as f:
            json.dump(info, f, indent=2)

    def _run_deep_scan_sync(self):
        results = self.cpp_unpacker.deep_scan(self.selected_file, os.path.join(self.current_output_dir, "deep_scan"))
        secs = results.get("section_entropy", [])
        for s in secs:
            flag = " ⚠ HIGH" if s['entropy'] > 7.0 else ""
            self.add_log(f"  {s['name']:12s} {s['size']:>8,} B  entropy={s['entropy']:.2f}{flag}")

    def _run_links_sync(self):
        with open(self.selected_file, 'rb') as f:
            data = f.read()
        net = self.cpp_unpacker._scan_network_indicators(data)
        total = sum(len(v) for v in net.values())
        self.add_log(f"  {total} network indicators")
        for key, label in [("urls", "URLs"), ("domains", "Domains"), ("ip_addresses", "IPs")]:
            items = net.get(key, [])
            if items:
                self.add_log(f"    {label}: {len(items)}")

    def _run_dump_sections_sync(self):
        with open(self.selected_file, 'rb') as f:
            data = f.read()
        pe_off = struct.unpack('<I', data[60:64])[0]
        num_sects = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
        opt_hdr_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
        sect_start = pe_off + 24 + opt_hdr_size
        out_dir = os.path.join(self.current_output_dir, "dumped_sections")
        os.makedirs(out_dir, exist_ok=True)
        count = 0
        for i in range(num_sects):
            off = sect_start + i * 40
            name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            rsize = struct.unpack('<I', data[off+16:off+20])[0]
            rptr = struct.unpack('<I', data[off+20:off+24])[0]
            if rptr > 0 and rsize > 0:
                with open(os.path.join(out_dir, f"section_{name}.bin"), 'wb') as fh:
                    fh.write(data[rptr:rptr+rsize])
                count += 1
        self.add_log(f"  Dumped {count} sections")

    def _run_embedded_sync(self):
        with open(self.selected_file, 'rb') as f:
            data = f.read()
        out_dir = os.path.join(self.current_output_dir, "extracted_embedded")
        os.makedirs(out_dir, exist_ok=True)
        pe_count = 0
        idx = 0
        while idx < len(data) - 64:
            pos = data.find(b'MZ', idx)
            if pos == -1 or pos > len(data) - 64:
                break
            if pos + 64 > len(data):
                break
            val = struct.unpack('<I', data[pos+60:pos+64])[0]
            sig_off = pos + val
            if sig_off + 4 <= len(data) and data[sig_off:sig_off+4] == b'PE\x00\x00':
                try:
                    img_size = struct.unpack('<I', data[sig_off+80:sig_off+84])[0]
                except:
                    img_size = 0
                end = min(pos + max(img_size, 4096), len(data))
                with open(os.path.join(out_dir, f"embedded_pe_{pe_count}.exe"), 'wb') as fh:
                    fh.write(data[pos:end])
                pe_count += 1
                idx = pos + 4
            else:
                idx = pos + 2
        self.add_log(f"  Embedded PEs: {pe_count}")

    def _run_xor_sync(self):
        with open(self.selected_file, 'rb') as f:
            data = f.read()
        pe_off = struct.unpack('<I', data[60:64])[0]
        num_sects = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
        opt_hdr_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
        sect_start = pe_off + 24 + opt_hdr_size
        import math
        high = []
        for i in range(num_sects):
            off = sect_start + i * 40
            rsize = struct.unpack('<I', data[off+16:off+20])[0]
            rptr = struct.unpack('<I', data[off+20:off+24])[0]
            if rptr > 0 and rsize > 0:
                chunk = data[rptr:rptr+min(rsize, 256*1024)]
                ent = 0.0
                for c in range(256):
                    fq = chunk.count(bytes([c])) / len(chunk)
                    if fq > 0:
                        ent -= fq * math.log2(fq)
                if ent > 7.5:
                    high.append((i, rptr, rsize))
        if not high:
            self.add_log("  No high-entropy sections")
            return
        out_dir = os.path.join(self.current_output_dir, "xor_bruteforce")
        os.makedirs(out_dir, exist_ok=True)
        total = 0
        for si, rptr, rsize in high:
            name = struct.unpack_from('8s', data, sect_start + si * 40)[0].rstrip(b'\x00').decode('ascii', errors='ignore')
            sec_data = data[rptr:rptr+min(rsize, 256*1024)]
            sec_out = os.path.join(out_dir, name)
            os.makedirs(sec_out, exist_ok=True)
            found = 0
            for key in range(256):
                dec = bytes(b ^ key for b in sec_data)
                pct = sum(1 for b in dec if 32 <= b <= 126) / len(dec) * 100
                if pct > 70 or (pct > 40 and b'http' in dec):
                    with open(os.path.join(sec_out, f"xor_0x{key:02x}.bin"), 'wb') as fh:
                        fh.write(dec)
                    found += 1
            if found:
                self.add_log(f"    {name}: {found} candidates")
                total += found
        if total:
            self.add_log(f"  XOR: {total} candidates saved")
        else:
            self.add_log("  XOR: No simple keys found")

    # ── UI Helpers ───────────────────────────────────────────────────────

    def _format_info_value(self, value, indent=0):
        """Recursively format a value for display."""
        prefix = "  " * indent
        lines = []
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{prefix}{k}:")
                    lines.extend(self._format_info_value(v, indent + 1))
                else:
                    lines.append(f"{prefix}{k}: {v}")
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}[{i}]:")
                    lines.extend(self._format_info_value(item, indent + 1))
                else:
                    lines.append(f"{prefix}[{i}]: {item}")
        else:
            lines.append(f"{prefix}{value}")
        return lines

    def display_info(self, info_dict):
        def update():
            self.info_text.config(state=tk.NORMAL)
            self.info_text.delete(1.0, tk.END)

            if isinstance(info_dict, dict):
                lines = self._format_info_value(info_dict)
                formatted = "\n".join(lines)
            else:
                formatted = str(info_dict)

            self.info_text.insert(tk.END, formatted)
            self.info_text.config(state=tk.DISABLED)
        self.root.after(0, update)

    def add_log(self, message, level="normal"):
        def update():
            self.log_text.config(state=tk.NORMAL)
            ts = datetime.now().strftime("%H:%M:%S")

            # Timestamp
            self.log_text.insert(tk.END, f"[{ts}] ", "timestamp")

            # Level prefix
            prefixes = {
                "info":    ("ℹ ", "info"),
                "success": ("✓ ", "success"),
                "warning": ("⚠ ", "warning"),
                "error":   ("✗ ", "error"),
                "header":  ("", "header"),
                "separator": ("", "separator"),
            }

            prefix, tag = prefixes.get(level, ("", "normal"))
            if prefix:
                self.log_text.insert(tk.END, prefix, tag)
            self.log_text.insert(tk.END, f"{message}\n", tag)

            # Store for filtering
            raw = f"[{ts}] {prefix}{message}" if prefix else f"[{ts}] {message}"
            full = f"[{ts}] {prefix}{message}\n" if prefix else f"[{ts}] {message}\n"
            self._log_entries.append({
                "raw_text": raw,
                "full_text": full,
                "level": level,
            })

            # If filtered, re-filter
            if self._log_filtered:
                query = self._log_search_var.get().strip()
                if query and query != "🔍 Search log...":
                    # Rebuild filtered view
                    self.log_text.delete(1.0, tk.END)
                    query_lower = query.lower()
                    for entry in self._log_entries:
                        if query_lower in entry["raw_text"].lower():
                            self.log_text.insert(tk.END, entry["full_text"])
                    self._highlight_search(self.log_text, query)
                else:
                    self.log_text.delete(1.0, tk.END)
                    for entry in self._log_entries:
                        self.log_text.insert(tk.END, entry["full_text"])

            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        self.root.after(0, update)

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self._log_entries.clear()
        self._log_filtered = False
        self.set_status("Ready")

    def set_status(self, text):
        def update():
            if text == "Ready":
                self.status_label.config(text="● Ready", fg=COLORS["success"])
            elif text == "Cancelled":
                self.status_label.config(text="◍ Cancelled", fg=COLORS["warning"])
            else:
                self.status_label.config(text=f"◉ {text}", fg=COLORS["accent"])
        self.root.after(0, update)

    def open_output_folder(self):
        if self.current_output_dir and os.path.exists(self.current_output_dir):
            os.startfile(self.current_output_dir)
        else:
            messagebox.showinfo("Info", "Output folder not yet created. Process a file first.")


def main():
    if HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    # Set dark title bar on Windows 10/11
    try:
        from ctypes import windll, byref, sizeof, c_int
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        hwnd = windll.user32.GetParent(root.winfo_id())
        value = c_int(1)
        windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                                             byref(value), sizeof(value))
    except Exception:
        pass

    # Set window icon color / taskbar
    try:
        root.iconbitmap(default="")
    except Exception:
        pass

    app = UnpackerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
