#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

echo "=== NoEscapeAC Linux Native Build & Test Runner ==="

# Configure
cmake -B "${BUILD_DIR}" -S "${ROOT_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DNOESCAPE_BUILD_TESTS=ON \
    -DNOESCAPE_SECURE_BUILD=OFF

# Build
cmake --build "${BUILD_DIR}" -j"$(nproc)"

echo "[+] Executing Linux Native Test Suite..."
ctest --test-dir "${BUILD_DIR}" --output-on-failure
echo "[+] Linux Test Suite PASSED successfully!"
