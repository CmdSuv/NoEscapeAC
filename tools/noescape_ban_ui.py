#!/usr/bin/env python3
"""
NoEscape Anti-Cheat - Minimalist Crimson Ban Screen
Designed for KDE Plasma on Wayland / X11 (Qt6 / PySide6)
"""

import sys
import os
import argparse

# Ensure display environment variables are set if running from detached daemon
uid = os.getuid() if hasattr(os, "getuid") else 1000
run_dir = f"/run/user/{uid}"
if not os.environ.get("WAYLAND_DISPLAY"):
    if os.path.exists(f"{run_dir}/wayland-1"):
        os.environ["WAYLAND_DISPLAY"] = "wayland-1"
    elif os.path.exists(f"{run_dir}/wayland-0"):
        os.environ["WAYLAND_DISPLAY"] = "wayland-0"
if not os.environ.get("XDG_RUNTIME_DIR") and os.path.exists(run_dir):
    os.environ["XDG_RUNTIME_DIR"] = run_dir
if not os.environ.get("DISPLAY"):
    os.environ["DISPLAY"] = ":0"
os.environ.setdefault("QT_QPA_PLATFORM", "wayland;xcb")

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QGraphicsDropShadowEffect
)
from PySide6.QtCore import Qt, QPointF, QTimer
from PySide6.QtGui import (
    QColor, QFont, QLinearGradient, QRadialGradient, QBrush, QPen,
    QPainter, QPainterPath
)

class NoEscapeLogo(QWidget):
    """Custom high-precision vector emblem for NoEscape Anti-Cheat."""
    def __init__(self, size=220, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.SmoothPixmapTransform)

        w = self.width()
        h = self.height()
        cx = w / 2.0
        cy = h / 2.0
        scale = w / 220.0

        # 1. Radiant Ambient Halo Flare
        glow = QRadialGradient(cx, cy, 105 * scale)
        glow.setColorAt(0.0, QColor(255, 255, 255, 95))
        glow.setColorAt(0.25, QColor(255, 45, 60, 85))
        glow.setColorAt(0.7, QColor(160, 0, 15, 30))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(glow))
        p.drawEllipse(QPointF(cx, cy), 105 * scale, 105 * scale)

        # 2. Outer Shield Geometry (Aerodynamic Cyber Shield)
        outer_path = QPainterPath()
        outer_path.moveTo(cx, cy - 88 * scale)
        outer_path.lineTo(cx + 74 * scale, cy - 74 * scale)
        outer_path.lineTo(cx + 74 * scale, cy + 8 * scale)
        outer_path.cubicTo(
            cx + 74 * scale, cy + 50 * scale,
            cx + 28 * scale, cy + 80 * scale,
            cx, cy + 94 * scale
        )
        outer_path.cubicTo(
            cx - 28 * scale, cy + 80 * scale,
            cx - 74 * scale, cy + 50 * scale,
            cx - 74 * scale, cy + 8 * scale
        )
        outer_path.lineTo(cx - 74 * scale, cy - 74 * scale)
        outer_path.closeSubpath()

        # Shield Fill: Deep obsidian-crimson gradient
        shield_grad = QLinearGradient(cx, cy - 88 * scale, cx, cy + 94 * scale)
        shield_grad.setColorAt(0.0, QColor(50, 2, 8))
        shield_grad.setColorAt(0.5, QColor(28, 1, 4))
        shield_grad.setColorAt(1.0, QColor(12, 0, 2))
        p.setBrush(QBrush(shield_grad))

        # Shield Edge: Beveled Silver/Chrome with Crimson Reflection
        border_pen = QPen()
        border_pen.setWidthF(4.0 * scale)
        border_grad = QLinearGradient(cx - 74 * scale, cy - 88 * scale, cx + 74 * scale, cy + 94 * scale)
        border_grad.setColorAt(0.0, QColor(255, 255, 255, 250))
        border_grad.setColorAt(0.35, QColor(255, 90, 90, 255))
        border_grad.setColorAt(0.7, QColor(180, 15, 25, 240))
        border_grad.setColorAt(1.0, QColor(255, 240, 240, 255))
        border_pen.setBrush(QBrush(border_grad))
        p.setPen(border_pen)
        p.drawPath(outer_path)

        # 3. Inner Decorative Crest Accent Line
        inner_path = QPainterPath()
        inner_path.moveTo(cx, cy - 76 * scale)
        inner_path.lineTo(cx + 60 * scale, cy - 65 * scale)
        inner_path.lineTo(cx + 60 * scale, cy + 6 * scale)
        inner_path.cubicTo(
            cx + 60 * scale, cy + 40 * scale,
            cx + 22 * scale, cy + 68 * scale,
            cx, cy + 80 * scale
        )
        inner_path.cubicTo(
            cx - 22 * scale, cy + 68 * scale,
            cx - 60 * scale, cy + 40 * scale,
            cx - 60 * scale, cy + 6 * scale
        )
        inner_path.lineTo(cx - 60 * scale, cy - 65 * scale)
        inner_path.closeSubpath()

        p.setPen(QPen(QColor(255, 60, 75, 110), 1.6 * scale))
        p.setBrush(Qt.NoBrush)
        p.drawPath(inner_path)

        # 4. Heavy Steel Security Shackle
        shackle_path = QPainterPath()
        shackle_path.moveTo(cx - 24 * scale, cy - 8 * scale)
        shackle_path.lineTo(cx - 24 * scale, cy - 36 * scale)
        shackle_path.arcTo(cx - 24 * scale, cy - 60 * scale, 48 * scale, 48 * scale, 180, -180)
        shackle_path.lineTo(cx + 24 * scale, cy - 8 * scale)

        shackle_pen = QPen(QColor(250, 250, 255), 7.5 * scale, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(shackle_pen)
        p.drawPath(shackle_path)

        # 5. Crimson Vault Padlock Body
        body_path = QPainterPath()
        body_path.addRoundedRect(cx - 34 * scale, cy - 10 * scale, 68 * scale, 52 * scale, 8 * scale, 8 * scale)

        body_grad = QLinearGradient(cx, cy - 10 * scale, cx, cy + 42 * scale)
        body_grad.setColorAt(0.0, QColor(240, 25, 40))
        body_grad.setColorAt(0.6, QColor(170, 10, 22))
        body_grad.setColorAt(1.0, QColor(95, 4, 10))
        p.setBrush(QBrush(body_grad))

        body_pen = QPen(QColor(255, 255, 255, 230), 2.2 * scale)
        p.setPen(body_pen)
        p.drawPath(body_path)

        # 6. Laser Core Keyhole Aperture
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(QColor(255, 255, 255, 255)))
        p.drawEllipse(QPointF(cx, cy + 9 * scale), 6.5 * scale, 6.5 * scale)

        slit = QPainterPath()
        slit.moveTo(cx - 3.5 * scale, cy + 10 * scale)
        slit.lineTo(cx + 3.5 * scale, cy + 10 * scale)
        slit.lineTo(cx + 5.5 * scale, cy + 27 * scale)
        slit.lineTo(cx - 5.5 * scale, cy + 27 * scale)
        slit.closeSubpath()
        p.drawPath(slit)

        p.end()

class MinimalistBanWindow(QWidget):
    def __init__(self, is_fullscreen=True):
        super().__init__()
        self.setWindowTitle("NOESCAPE // SECURITY ENFORCEMENT")
        self.setWindowFlags(Qt.Window | Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, False)

        # Size: Full Screen or commanding 1200x750
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            if is_fullscreen:
                self.resize(geo.width(), geo.height())
                self.move(geo.x(), geo.y())
            else:
                w = min(1200, int(geo.width() * 0.8))
                h = min(750, int(geo.height() * 0.8))
                self.resize(w, h)
                self.move(geo.x() + (geo.width() - w) // 2, geo.y() + (geo.height() - h) // 2)
        else:
            self.resize(1280, 720)

        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addStretch(1)

        # Center Content Container
        center_layout = QVBoxLayout()
        center_layout.setAlignment(Qt.AlignCenter)
        center_layout.setSpacing(32)

        # 1. Custom Designed Logo
        self.logo = NoEscapeLogo(size=240)
        center_layout.addWidget(self.logo, 0, Qt.AlignCenter)

        # 2. Main Title: "YOU HAVE BEEN BANNED"
        self.text_label = QLabel("YOU HAVE BEEN BANNED")
        self.text_label.setAlignment(Qt.AlignCenter)

        # Prefer modern high-impact fonts with crisp letter-spacing
        font = QFont("Cantarell", 46, QFont.Bold)
        font.setLetterSpacing(QFont.AbsoluteSpacing, 9.5)
        self.text_label.setFont(font)
        self.text_label.setStyleSheet("""
            QLabel {
                color: #FFFFFF;
                background: transparent;
            }
        """)

        # Glow / Shadow for Impact
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(36)
        shadow.setColor(QColor(0, 0, 0, 230))
        shadow.setOffset(0, 6)
        self.text_label.setGraphicsEffect(shadow)
        center_layout.addWidget(self.text_label, 0, Qt.AlignCenter)

        # 3. Minimalist Subtitle Pill
        self.sub_label = QLabel("NOESCAPE ANTI-CHEAT")
        self.sub_label.setAlignment(Qt.AlignCenter)
        sub_font = QFont("Liberation Sans", 13, QFont.Bold)
        sub_font.setLetterSpacing(QFont.AbsoluteSpacing, 6.0)
        self.sub_label.setFont(sub_font)
        self.sub_label.setStyleSheet("""
            QLabel {
                color: rgba(255, 255, 255, 0.75);
                background: rgba(0, 0, 0, 0.25);
                padding: 7px 22px;
                border-radius: 14px;
                border: 1px solid rgba(255, 255, 255, 0.18);
            }
        """)
        center_layout.addWidget(self.sub_label, 0, Qt.AlignCenter)

        main_layout.addLayout(center_layout)
        main_layout.addStretch(1)

    def mousePressEvent(self, event):
        self.close()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Escape, Qt.Key_Q, Qt.Key_Space, Qt.Key_Return):
            self.close()
        else:
            super().keyPressEvent(event)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # Full Red Radial Gradient with Vignette
        w = self.width()
        h = self.height()
        cx = w / 2.0
        cy = h / 2.0
        radius = max(w, h) * 0.75

        grad = QRadialGradient(cx, cy, radius)
        grad.setColorAt(0.0, QColor(200, 16, 28))   # Rich vibrant crimson red in center
        grad.setColorAt(0.55, QColor(140, 6, 14))  # Deep blood red
        grad.setColorAt(1.0, QColor(60, 2, 6))     # Dark dramatic vignette edge

        p.fillRect(0, 0, w, h, QBrush(grad))
        p.end()

def main():
    parser = argparse.ArgumentParser(description="NoEscape Anti-Cheat Ban UI")
    parser.add_argument("--hwid", type=str, default="")
    parser.add_argument("--score", type=int, default=100)
    parser.add_argument("--reason", type=str, default="")
    parser.add_argument("--component", type=str, default="")
    parser.add_argument("--type", type=str, default="")
    parser.add_argument("--timestamp", type=str, default="")
    parser.add_argument("--fullscreen", action="store_true", default=True)
    parser.add_argument("--windowed", action="store_true", default=False)
    parser.add_argument("--screenshot", type=str, default="")
    parser.add_argument("--auto-close", type=int, default=0)
    args = parser.parse_args()

    app = QApplication(sys.argv)
    is_fs = not args.windowed
    window = MinimalistBanWindow(is_fullscreen=is_fs)
    if is_fs:
        window.showFullScreen()
    else:
        window.show()
    window.raise_()
    window.activateWindow()

    if args.screenshot:
        def capture():
            pix = window.grab()
            pix.save(args.screenshot, "PNG")
            print(f"Screenshot saved to: {args.screenshot}")
        QTimer.singleShot(500, capture)

    if args.auto_close > 0:
        QTimer.singleShot(args.auto_close * 1000, window.close)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
