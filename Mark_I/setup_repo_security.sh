#!/bin/bash
# Quick setup script for adding security scanner to an existing repository

REPO_PATH="$1"
SCANNER_PATH="/Users/alexmccarthy/SecurityScanner/scanner.py"

if [ -z "$REPO_PATH" ]; then
    echo "Usage: $0 <path-to-repository>"
    echo "Example: $0 /path/to/your/other/repo"
    exit 1
fi

if [ ! -d "$REPO_PATH/.git" ]; then
    echo "❌ Error: $REPO_PATH is not a git repository"
    exit 1
fi

if [ ! -f "$SCANNER_PATH" ]; then
    echo "❌ Error: Scanner not found at $SCANNER_PATH"
    exit 1
fi

echo "🔧 Setting up security scanner for repository: $REPO_PATH"

# Create hooks directory if it doesn't exist
mkdir -p "$REPO_PATH/.git/hooks"

# Copy scanner to the repository
cp "$SCANNER_PATH" "$REPO_PATH/.git/hooks/"
chmod +x "$REPO_PATH/.git/hooks/scanner.py"

# Create pre-commit hook
cat > "$REPO_PATH/.git/hooks/pre-commit" << 'EOF'
#!/bin/zsh
# Pre-commit security scanner

SCRIPT_DIR="$(dirname "$0")"
SCANNER="$SCRIPT_DIR/scanner.py"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "${YELLOW}🔍 Running security scan...${NC}"

# Check if scanner exists
if [ ! -f "$SCANNER" ]; then
    echo "${RED}❌ Security scanner not found${NC}"
    exit 1
fi

# Run security scan on staged files
python3 "$SCANNER" --staged --format json > /tmp/scan_results.json

if [ $? -eq 0 ]; then
    echo "${GREEN}✅ No critical/high vulnerabilities found${NC}"
    rm -f /tmp/scan_results.json
    exit 0
else
    echo "${RED}🚨 SECURITY VULNERABILITIES FOUND!${NC}"
    echo "${RED}❌ Commit blocked to prevent security issues${NC}"
    
    # Show summary
    if [ -f /tmp/scan_results.json ]; then
        critical=$(python3 -c "import json; data=json.load(open('/tmp/scan_results.json')); print(data.get('summary', {}).get('critical', 0))")
        high=$(python3 -c "import json; data=json.load(open('/tmp/scan_results.json')); print(data.get('summary', {}).get('high', 0))")
        echo "${RED}Critical: $critical, High: $high vulnerabilities${NC}"
    fi
    
    # Send Mac notification
    osascript -e 'display notification "Critical/High vulnerabilities found! Commit blocked." with title "Security Alert"' 2>/dev/null
    
    # Send email notification (if configured)
    # mail -s "Security Alert - Commit Blocked" alexcomp2@outlook.com < /tmp/scan_results.json 2>/dev/null
    
    # Log incident
    echo "$(date -Iseconds): Commit blocked due to security vulnerabilities in $(pwd)" >> ~/.security_incidents.log
    
    rm -f /tmp/scan_results.json
    exit 1
fi
EOF

chmod +x "$REPO_PATH/.git/hooks/pre-commit"

echo "✅ Security scanner installed successfully!"
echo "🔒 The repository is now protected with pre-commit security scanning"
echo ""
echo "To test, try committing a file with vulnerabilities and it will be blocked."
