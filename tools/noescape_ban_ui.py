#!/usr/bin/env python3
"""
NoEscape Anti-Cheat - Standalone Crimson Ban Warning Screen
Designed for KDE Plasma on Wayland / X11 (Qt6 / PySide6)
"""

import sys
import os
import argparse
import datetime

# Ensure display environment variables are set if running from detached daemon
uid = os.getuid() if hasattr(os, "getuid") else 1000
run_dir = f"/run/user/{uid}"
if not os.environ.get("WAYLAND_DISPLAY") and os.path.exists(f"{run_dir}/wayland-0"):
    os.environ["WAYLAND_DISPLAY"] = "wayland-0"
if not os.environ.get("XDG_RUNTIME_DIR") and os.path.exists(run_dir):
    os.environ["XDG_RUNTIME_DIR"] = run_dir
if not os.environ.get("DISPLAY"):
    os.environ["DISPLAY"] = ":0"
os.environ.setdefault("QT_QPA_PLATFORM", "wayland;xcb")

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QGraphicsDropShadowEffect
)
from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QColor, QFont, QPalette, QLinearGradient, QBrush, QPainter, QPainterPath

class BanWindow(QWidget):
    def __init__(self, hwid, score, reason, component, violation_type, timestamp_str):
        super().__init__()
        self.hwid = hwid or "UNKNOWN-HWID-DEVICE"
        self.score = str(score) if score is not None else "100"
        self.reason = reason or "Critical security policy violation detected"
        self.component = component or "AntiCheatEngine::Enforcement"
        self.violation_type = violation_type or "FATAL_BAN"
        self.timestamp_str = timestamp_str or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        self.setWindowTitle("NOESCAPE ANTI-CHEAT // SECURITY VIOLATION")

        # Determine prominent, commanding screen size ("kocaman")
        screen = QApplication.primaryScreen()
        if screen:
            screen_geo = screen.availableGeometry()
            target_w = min(1280, max(1000, int(screen_geo.width() * 0.72)))
            target_h = min(820, max(680, int(screen_geo.height() * 0.72)))
            self.resize(target_w, target_h)
            self.setMinimumSize(880, 620)
            self.move(
                screen_geo.x() + (screen_geo.width() - self.width()) // 2,
                screen_geo.y() + (screen_geo.height() - self.height()) // 2
            )
        else:
            self.resize(1100, 720)
            self.setMinimumSize(880, 620)

        # Keep on top so user cannot miss it
        self.setWindowFlags(Qt.Window | Qt.WindowStaysOnTopHint | Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.init_ui()

    def init_ui(self):
        # Master dark crimson / red aesthetic
        self.setStyleSheet("""
            QWidget#MainBackground {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a0306, stop:0.35 #0f0203, stop:0.7 #170305, stop:1 #080102);
            }
            QLabel {
                color: #e0e0e0;
                font-family: 'Segoe UI', 'Ubuntu', 'Liberation Sans', sans-serif;
            }
            QFrame#HeaderCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #42080e, stop:0.5 #2b0509, stop:1 #1c0305);
                border: 2px solid #ff4655;
                border-radius: 8px;
            }
            QFrame#InfoCard {
                background: #140608;
                border: 1px solid #380e13;
                border-radius: 8px;
            }
            QFrame#FieldBox {
                background: #1e090c;
                border: 1px solid #4a131a;
                border-radius: 6px;
            }
            QPushButton#AcknowledgeBtn {
                background-color: #ff4655;
                color: #ffffff;
                font-weight: bold;
                font-size: 15px;
                letter-spacing: 1.5px;
                border: 1px solid #ff6e7b;
                border-radius: 6px;
                padding: 14px 40px;
            }
            QPushButton#AcknowledgeBtn:hover {
                background-color: #ff5e6c;
                border: 1px solid #ffffff;
            }
            QPushButton#AcknowledgeBtn:pressed {
                background-color: #d92d3c;
            }
        """)

        self.setObjectName("MainBackground")
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(36, 32, 36, 32)
        main_layout.setSpacing(20)

        # ---------------- HEADER CARD ----------------
        header_card = QFrame()
        header_card.setObjectName("HeaderCard")
        header_layout = QHBoxLayout(header_card)
        header_layout.setContentsMargins(24, 20, 24, 20)
        header_layout.setSpacing(20)

        # Security Symbol / Shield Icon
        icon_label = QLabel("⛔")
        icon_label.setStyleSheet("font-size: 48px; color: #ff4655; background: transparent;")
        icon_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(icon_label, 0)

        title_vbox = QVBoxLayout()
        title_vbox.setSpacing(4)

        top_tag = QLabel("NOESCAPE ANTI-CHEAT // RING-3 SECURITY ENFORCEMENT")
        top_tag.setStyleSheet("color: #ff8c96; font-size: 12px; font-weight: 800; letter-spacing: 2px;")
        title_vbox.addWidget(top_tag)

        main_title = QLabel("SECURITY VIOLATION DETECTED")
        main_title.setStyleSheet("color: #ffffff; font-size: 26px; font-weight: 900; letter-spacing: 1px;")
        title_vbox.addWidget(main_title)

        sub_title = QLabel("HARDWARE-LEVEL SECURITY ENFORCEMENT // ACCESS REVOKED")
        sub_title.setStyleSheet("color: #ff4655; font-size: 13px; font-weight: 700; letter-spacing: 1.2px;")
        title_vbox.addWidget(sub_title)

        header_layout.addLayout(title_vbox, 1)

        # Status badge on right
        badge_frame = QFrame()
        badge_frame.setStyleSheet("""
            background: #ff1744;
            border-radius: 4px;
            padding: 8px 16px;
        """)
        badge_layout = QVBoxLayout(badge_frame)
        badge_layout.setContentsMargins(12, 6, 12, 6)
        b_label1 = QLabel("STATUS")
        b_label1.setStyleSheet("color: #ffffff; font-size: 10px; font-weight: 900; letter-spacing: 1px;")
        b_label1.setAlignment(Qt.AlignCenter)
        b_label2 = QLabel("BANNED")
        b_label2.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: 900;")
        b_label2.setAlignment(Qt.AlignCenter)
        badge_layout.addWidget(b_label1)
        badge_layout.addWidget(b_label2)
        header_layout.addWidget(badge_frame, 0)

        main_layout.addWidget(header_card)

        # ---------------- CONTENT CARD ----------------
        info_card = QFrame()
        info_card.setObjectName("InfoCard")
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(24, 20, 24, 20)
        info_layout.setSpacing(14)

        desc_label = QLabel(
            "The NoEscape Anti-Cheat subsystem identified an unauthorized memory anomaly, debugger, "
            "or integrity violation during execution. The active game session has been terminated to "
            "protect game integrity. Below are the forensic enforcement parameters:"
        )
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #c4b5b7; font-size: 13px; line-height: 1.4;")
        info_layout.addWidget(desc_label)

        def make_field(label_text, val_text, is_mono=False, is_highlight=False):
            fbox = QFrame()
            fbox.setObjectName("FieldBox")
            flayout = QVBoxLayout(fbox)
            flayout.setContentsMargins(14, 8, 14, 8)
            flayout.setSpacing(2)

            lbl = QLabel(label_text)
            lbl.setStyleSheet("color: #ff949f; font-size: 11px; font-weight: 700; letter-spacing: 1px;")
            flayout.addWidget(lbl)

            val = QLabel(val_text)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            val.setWordWrap(True)
            if is_mono:
                val.setStyleSheet("color: #ffffff; font-family: 'Consolas', 'DejaVu Sans Mono', monospace; font-size: 12px; font-weight: bold;")
            elif is_highlight:
                val.setStyleSheet("color: #ff4655; font-size: 14px; font-weight: 800;")
            else:
                val.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: 600;")
            flayout.addWidget(val)
            return fbox

        # Fields row 1: HWID (full width)
        info_layout.addWidget(make_field("DEVICE HARDWARE IDENTIFIER (HWID)", self.hwid, is_mono=True))

        # Fields row 2: Violation Reason & Component
        r2_layout = QHBoxLayout()
        r2_layout.setSpacing(12)
        r2_layout.addWidget(make_field("DETECTED VIOLATION", self.reason, is_highlight=True), 3)
        r2_layout.addWidget(make_field("COMPONENT", self.component, is_mono=True), 2)
        info_layout.addLayout(r2_layout)

        # Fields row 3: Threat Score, Type, Action, Timestamp
        r3_layout = QHBoxLayout()
        r3_layout.setSpacing(12)
        r3_layout.addWidget(make_field("THREAT SCORE", f"{self.score} / 100 [CRITICAL]", is_highlight=True), 1)
        r3_layout.addWidget(make_field("VIOLATION TYPE", self.violation_type), 1)
        r3_layout.addWidget(make_field("ENFORCEMENT ACTION", "SESSION TERMINATED", is_highlight=True), 1)
        r3_layout.addWidget(make_field("TIMESTAMP", self.timestamp_str), 1)
        info_layout.addLayout(r3_layout)

        main_layout.addWidget(info_card)

        # ---------------- BOTTOM ACTION BAR ----------------
        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(8, 6, 8, 6)

        footer_warning = QLabel("WARNING: Tampering with game memory or running illicit tools is strictly prohibited.")
        footer_warning.setStyleSheet("color: #8c5d63; font-size: 11px; font-style: italic;")
        bottom_layout.addWidget(footer_warning, 1)

        ack_btn = QPushButton("ACKNOWLEDGE && CLOSE")
        ack_btn.setObjectName("AcknowledgeBtn")
        ack_btn.setCursor(Qt.PointingHandCursor)
        ack_btn.clicked.connect(self.close)
        bottom_layout.addWidget(ack_btn, 0)

        main_layout.addLayout(bottom_layout)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Escape, Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
            self.close()
        else:
            super().keyPressEvent(event)

def main():
    parser = argparse.ArgumentParser(description="NoEscape Crimson Ban Screen")
    parser.add_argument("--hwid", type=str, default="", help="Device HWID fingerprint")
    parser.add_argument("--score", type=int, default=100, help="Threat score")
    parser.add_argument("--reason", type=str, default="Critical security violation detected", help="Violation details")
    parser.add_argument("--component", type=str, default="AntiCheatEngine::Enforcement", help="Violating module")
    parser.add_argument("--type", type=str, default="FATAL_BAN", help="Detection type name")
    parser.add_argument("--timestamp", type=str, default="", help="Detection timestamp string")
    parser.add_argument("--fullscreen", action="store_true", help="Launch in fullscreen mode")
    parser.add_argument("--auto-close", type=int, default=0, help="Auto-close after N seconds (for testing)")
    parser.add_argument("--screenshot", type=str, default="", help="Save rendered window screenshot to file path")

    args = parser.parse_args()

    # Fallback to local HWID if not supplied
    hwid = args.hwid
    if not hwid:
        try:
            with open("/etc/machine-id", "r") as f:
                import hashlib
                hwid = hashlib.sha256(f.read().strip().encode()).hexdigest()
        except Exception:
            hwid = "2d70541832a1cb00855e97f183c6a5053a7b666bc5043648970f977710c3fb80"

    app = QApplication(sys.argv)
    window = BanWindow(
        hwid=hwid,
        score=args.score,
        reason=args.reason,
        component=args.component,
        violation_type=args.type,
        timestamp_str=args.timestamp
    )
    if args.fullscreen:
        window.showFullScreen()
    else:
        window.show()
    window.raise_()
    window.activateWindow()

    if args.screenshot:
        from PySide6.QtCore import QTimer
        def capture():
            pix = window.grab()
            pix.save(args.screenshot, "PNG")
            print(f"Screenshot saved to: {args.screenshot}")
        QTimer.singleShot(600, capture)

    if args.auto_close > 0:
        from PySide6.QtCore import QTimer
        QTimer.singleShot(args.auto_close * 1000, window.close)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
