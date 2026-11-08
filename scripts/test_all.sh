#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo " Starting Full Cross-Platform Validation (Linux + Windows)"
echo "=========================================================="

"${SCRIPT_DIR}/test_linux.sh"
echo ""
"${SCRIPT_DIR}/test_windows.sh"

echo ""
echo "=========================================================="
echo " ALL TESTS (Linux + Windows) COMPLETED WITH 100% SUCCESS! "
echo "=========================================================="
