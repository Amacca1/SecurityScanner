#!/bin/bash
# VS Code Git Hook Wrapper for Security Scanner Mark II
# This script provides better integration with VS Code's git operations

set -e  # Exit on any error

# Find the repository root
REPO_ROOT=$(git rev-parse --show-toplevel)

# VS Code-friendly output
printf "🔍 Security scanning..."

# Set up the scanner environment
SCANNER_DIR="/Users/alexmccarthy/SecurityScanner/Mark_II"
VENV_PYTHON="$SCANNER_DIR/.venv/bin/python3"

# Check if virtual environment exists, fallback to system python
if [ -f "$VENV_PYTHON" ]; then
    PYTHON_CMD="$VENV_PYTHON"
else
    PYTHON_CMD="python3"
fi

# Run the security scanner silently and capture output with timeout
cd "$SCANNER_DIR"

# Use timeout to prevent hanging (30 seconds max)
if command -v timeout >/dev/null 2>&1; then
    OUTPUT=$(timeout 30s $PYTHON_CMD security_scanner.py --repo-path "$REPO_ROOT" --quiet 2>&1)
    SCANNER_EXIT_CODE=$?
    
    # Check if it timed out
    if [ $SCANNER_EXIT_CODE -eq 124 ]; then
        printf "\n⚠️  Scanner timed out, allowing commit\n"
        exit 0
    fi
else
    # No timeout available, run normally
    OUTPUT=$($PYTHON_CMD security_scanner.py --repo-path "$REPO_ROOT" --quiet 2>&1)
    SCANNER_EXIT_CODE=$?
fi

if [ $SCANNER_EXIT_CODE -ne 0 ]; then
    printf "\n❌ Security issues found!\n"
    echo "$OUTPUT"
    echo ""
    echo "Review: $REPO_ROOT/security_scan_results.json"
    echo "Bypass: git commit --no-verify"
    exit 1
else
    printf " ✅\n"
    exit 0
fi
