#!/usr/bin/env bash
# ==============================================================================
# NoEscape Anti-Cheat Wrapper for Prism Launcher Minecraft
# Architects: Omar Yiğitcan Mengü (@CmdSuv) & OnlyCosmos (@OnlyCosmos)
# ==============================================================================

# Dynamic Library Preload for Minecraft Java Process
AC_LIB="/home/COSMOS/NoEscapeAC/build/libnoescape.so"
BAN_UI="/home/COSMOS/NoEscapeAC/tools/noescape_ban_ui.py"

if [[ -f "${AC_LIB}" ]]; then
    export LD_PRELOAD="${AC_LIB}${LD_PRELOAD:+:$LD_PRELOAD}"
fi

export NOESCAPE_BAN_UI_PATH="${BAN_UI}"
export WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-1}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/1000}"
export DISPLAY="${DISPLAY:-:0}"

echo "[NoEscapeAC] ======================================================"
echo "[NoEscapeAC] Launching Minecraft with NoEscape Anti-Cheat Protection"
echo "[NoEscapeAC] Pure Ring-3 C++20 Integrity Monitoring Active"
echo "[NoEscapeAC] ======================================================"

exec "$@"
