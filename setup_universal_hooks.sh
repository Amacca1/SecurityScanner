#!/bin/bash
# Universal Git Hook Setup Script
# This sets up security scanning for all new git repositories

# Create git template directory
mkdir -p ~/.git-template/hooks

# Copy our security scanner to a global location
cp scanner.py ~/.git-template/hooks/
chmod +x ~/.git-template/hooks/scanner.py

# Create universal pre-commit hook
cat > ~/.git-template/hooks/pre-commit << 'EOF'
#!/bin/zsh
# Universal pre-commit security scanner

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
    echo "${RED}❌ Security scanner not found at $SCANNER${NC}"
    echo "${YELLOW}💡 Run the setup script to install the scanner${NC}"
    exit 1
fi

# Run the scanner on staged files
if python3 "$SCANNER" --staged --format json > /tmp/scan_results.json 2>/dev/null; then
    critical=$(jq '.summary.critical // 0' /tmp/scan_results.json 2>/dev/null || echo 0)
    high=$(jq '.summary.high // 0' /tmp/scan_results.json 2>/dev/null || echo 0)
    
    if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ]; then
        echo "${RED}🚨 SECURITY VULNERABILITIES FOUND!${NC}"
        echo "${RED}Critical: $critical, High: $high${NC}"
        echo "${YELLOW}💡 Fix vulnerabilities before committing${NC}"
        
        # Send notification (macOS)
        osascript -e 'display notification "Security vulnerabilities found!" with title "Git Security Alert"' 2>/dev/null
        
        # Log incident
        echo "$(date): Security vulnerabilities found in $(pwd)" >> ~/.security_incidents.log
        cat /tmp/scan_results.json >> ~/.security_incidents.log
        
        exit 1
    else
        echo "${GREEN}✅ Security scan passed${NC}"
    fi
else
    echo "${YELLOW}⚠️  Scanner failed to run, allowing commit${NC}"
fi

exit 0
EOF

chmod +x ~/.git-template/hooks/pre-commit

# Configure git to use this template for all new repositories
git config --global init.templateDir ~/.git-template

echo "✅ Universal git hook setup complete!"
echo "📝 All new git repositories will automatically have security scanning"
echo "🔧 To apply to existing repositories, run: git init in each repo directory"
