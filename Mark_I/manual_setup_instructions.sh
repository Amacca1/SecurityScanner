#!/bin/bash
# Manual setup commands for adding security to any repository

echo "🔧 Manual Setup Instructions:"
echo ""
echo "1. Navigate to your repository:"
echo "   cd /path/to/your/other/repo"
echo ""
echo "2. Copy the scanner:"
echo "   cp /Users/alexmccarthy/SecurityScanner/scanner.py .git/hooks/"
echo "   chmod +x .git/hooks/scanner.py"
echo ""
echo "3. Copy the pre-commit hook:"
echo "   cp /Users/alexmccarthy/SecurityScanner/.git/hooks/pre-commit .git/hooks/"
echo "   chmod +x .git/hooks/pre-commit"
echo ""
echo "4. Test it by trying to commit a vulnerable file!"
echo ""
echo "✅ Your repository will now be protected!"
