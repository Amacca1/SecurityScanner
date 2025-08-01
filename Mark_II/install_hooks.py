#!/bin/bash
"""
Git Hook Installation Script for Security Scanner Mark II
This script sets up pre-commit hooks to automatically scan files for security vulnerabilities
"""

import os
import sys
import subprocess
from pathlib import Path

def find_git_repo():
    """Find the git repository root"""
    current_dir = Path.cwd()
    
    while current_dir != current_dir.parent:
        if (current_dir / '.git').exists():
            return current_dir
        current_dir = current_dir.parent
    
    print("Error: Not in a git repository")
    sys.exit(1)

def install_pre_commit_hook(repo_root, scanner_path):
    """Install the pre-commit hook"""
    hooks_dir = repo_root / '.git' / 'hooks'
    pre_commit_hook = hooks_dir / 'pre-commit'
    
    # Create hooks directory if it doesn't exist
    hooks_dir.mkdir(exist_ok=True)
    
    # Pre-commit hook content
    hook_content = f'''#!/bin/bash
# Security Scanner Pre-commit Hook
# Automatically scans staged files for security vulnerabilities

echo "🔍 Running security scan on staged files..."

# Run the security scanner
python3 "{scanner_path}" --repo-path "{repo_root}"

# Get the exit code
SCANNER_EXIT_CODE=$?

if [ $SCANNER_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Security scan failed! High-severity vulnerabilities found."
    echo "   Please review the security report and fix the issues before committing."
    echo "   Report saved to: security_scan_results.json"
    echo ""
    echo "To bypass this check (NOT RECOMMENDED), use: git commit --no-verify"
    exit 1
else
    echo "✅ Security scan passed!"
fi

exit 0
'''
    
    # Write the hook
    with open(pre_commit_hook, 'w') as f:
        f.write(hook_content)
    
    # Make it executable
    os.chmod(pre_commit_hook, 0o755)
    
    print(f"✅ Pre-commit hook installed at: {pre_commit_hook}")

def install_commit_msg_hook(repo_root, scanner_path):
    """Install commit-msg hook for additional security checks"""
    hooks_dir = repo_root / '.git' / 'hooks'
    commit_msg_hook = hooks_dir / 'commit-msg'
    
    hook_content = f'''#!/bin/bash
# Security Scanner Commit Message Hook
# Adds security scan results to commit message if vulnerabilities were found

COMMIT_MSG_FILE=$1

# Check if security scan results exist
if [ -f "security_scan_results.json" ]; then
    # Check if there were any vulnerabilities
    VULN_COUNT=$(python3 -c "
import json
try:
    with open('security_scan_results.json') as f:
        data = json.load(f)
    summary = data.get('summary', {{}})
    total = sum([
        summary.get('critical_issues', 0),
        summary.get('high_issues', 0),
        summary.get('medium_issues', 0),
        summary.get('low_issues', 0)
    ])
    print(total)
except:
    print(0)
")
    
    if [ "$VULN_COUNT" -gt 0 ]; then
        echo "" >> "$COMMIT_MSG_FILE"
        echo "🔍 Security Scan: $VULN_COUNT vulnerabilities found and addressed" >> "$COMMIT_MSG_FILE"
    fi
fi
'''
    
    with open(commit_msg_hook, 'w') as f:
        f.write(hook_content)
    
    os.chmod(commit_msg_hook, 0o755)
    
    print(f"✅ Commit-msg hook installed at: {commit_msg_hook}")

def setup_global_hooks():
    """Setup global git hooks for all repositories"""
    home_dir = Path.home()
    global_hooks_dir = home_dir / '.git-hooks'
    global_hooks_dir.mkdir(exist_ok=True)
    
    # Get current script directory to find the scanner
    current_dir = Path(__file__).parent.absolute()
    scanner_path = current_dir / 'security_scanner.py'
    
    # Global pre-commit hook
    global_pre_commit = global_hooks_dir / 'pre-commit'
    hook_content = f'''#!/bin/bash
# Global Security Scanner Pre-commit Hook

# Find the repository root
REPO_ROOT=$(git rev-parse --show-toplevel)

echo "🔍 Running global security scan on staged files..."

# Run the security scanner
python3 "{scanner_path}" --repo-path "$REPO_ROOT"

SCANNER_EXIT_CODE=$?

if [ $SCANNER_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Security scan failed! High-severity vulnerabilities found."
    echo "   Please review the security report and fix the issues before committing."
    echo "   Report saved to: $REPO_ROOT/security_scan_results.json"
    echo ""
    echo "To bypass this check (NOT RECOMMENDED), use: git commit --no-verify"
    exit 1
else
    echo "✅ Security scan passed!"
fi

exit 0
'''
    
    with open(global_pre_commit, 'w') as f:
        f.write(hook_content)
    
    os.chmod(global_pre_commit, 0o755)
    
    # Configure git to use global hooks
    subprocess.run(['git', 'config', '--global', 'core.hooksPath', str(global_hooks_dir)])
    
    print(f"✅ Global hooks configured at: {global_hooks_dir}")
    print("✅ Git configured to use global hooks for all repositories")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Install Security Scanner Git Hooks')
    parser.add_argument('--global', dest='global_hooks', action='store_true',
                       help='Install hooks globally for all repositories')
    parser.add_argument('--local', dest='local_hooks', action='store_true',
                       help='Install hooks for current repository only')
    
    args = parser.parse_args()
    
    current_dir = Path(__file__).parent.absolute()
    scanner_path = current_dir / 'security_scanner.py'
    
    if not scanner_path.exists():
        print(f"Error: Scanner not found at {scanner_path}")
        sys.exit(1)
    
    if args.global_hooks:
        setup_global_hooks()
    elif args.local_hooks:
        repo_root = find_git_repo()
        install_pre_commit_hook(repo_root, scanner_path)
        install_commit_msg_hook(repo_root, scanner_path)
    else:
        print("Please specify --global or --local")
        print("  --global: Install hooks for all repositories")
        print("  --local:  Install hooks for current repository only")
        sys.exit(1)

if __name__ == "__main__":
    main()
