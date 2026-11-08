#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build_win"

echo "=== NoEscapeAC Windows Build & Live Wine Test Runner ==="

# Check requirements
if ! command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
    echo "[-] Error: MinGW-w64 compiler (x86_64-w64-mingw32-g++) not found."
    exit 1
fi

if ! command -v wine >/dev/null 2>&1; then
    echo "[-] Error: Wine not found in PATH."
    exit 1
fi

echo "[+] MinGW: $(x86_64-w64-mingw32-g++ --version | head -n1)"
echo "[+] Wine:  $(wine --version)"

# Configure
cmake -B "${BUILD_DIR}" -S "${ROOT_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${ROOT_DIR}/cmake/toolchain-mingw64.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNOESCAPE_BUILD_TESTS=ON \
    -DNOESCAPE_SECURE_BUILD=OFF

# Build
cmake --build "${BUILD_DIR}" -j"$(nproc)"

echo "[+] Executing Windows Test Suite under Wine..."
NOESCAPE_TEST_MODE=1 WINEDEBUG=-all wine "${BUILD_DIR}/noescape_tests.exe"
echo "[+] Windows Test Suite PASSED successfully!"
