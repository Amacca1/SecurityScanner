#!/bin/bash
# Find all git repositories on the system

echo "🔍 Searching for git repositories..."
echo ""

find ~ -type d -name ".git" 2>/dev/null | while read git_dir; do
    repo_dir=$(dirname "$git_dir")
    echo "📁 Repository found: $repo_dir"
    
    # Check if it has security scanner
    if [ -f "$git_dir/hooks/pre-commit" ]; then
        if grep -q "security scan" "$git_dir/hooks/pre-commit" 2>/dev/null; then
            echo "   ✅ Protected (has security scanner)"
        else
            echo "   ⚠️  Has pre-commit hook (but not security scanner)"
        fi
    else
        echo "   ❌ Unprotected (no pre-commit hook)"
    fi
    echo ""
done

echo "💡 To protect unprotected repositories, run:"
echo "   ./setup_repo_security.sh <repository-path>"
