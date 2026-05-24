#!/bin/sh
# Setup script to configure local Git hooks.

set -e

# ANSI escape codes for coloring
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=== Setting up local Git hooks ==="

# Get the repository root directory
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$REPO_ROOT" ]; then
    echo "${RED}❌ Error: Not in a git repository.${NC}"
    exit 1
fi

cd "$REPO_ROOT"

# Ensure hooks directory exists
if [ ! -d ".githooks" ]; then
    echo "${RED}❌ Error: .githooks directory not found at repository root.${NC}"
    exit 1
fi

# Make hooks executable
echo "Making hooks executable..."
chmod +x .githooks/pre-commit
chmod +x .githooks/pre-push

# Set core.hooksPath to .githooks
echo "Configuring Git core.hooksPath..."
git config core.hooksPath .githooks

echo "=== ${GREEN}Local Git hooks successfully installed and activated!${NC} ==="
echo "  - pre-commit: runs 'gofmt', 'go vet', and verifies code compiles"
echo "  - pre-push: runs the unit test suite and platform-specific smoke tests"
echo ""
echo "If you ever need to bypass a check, you can use the '--no-verify' option (e.g., 'git commit -m \"msg\" --no-verify')."
