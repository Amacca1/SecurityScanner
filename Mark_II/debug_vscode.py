#!/usr/bin/env python3
"""
VS Code Git Hook Troubleshooting Script
"""

import os
import sys
import subprocess
from pathlib import Path

def test_vscode_integration():
    """Test VS Code git integration"""
    print("🔧 Testing VS Code Git Hook Integration")
    print("=" * 50)
    
    # Test 1: Check hook file exists and is executable
    hook_path = Path("/Users/alexmccarthy/.git-hooks/pre-commit")
    if hook_path.exists():
        print("✅ Global pre-commit hook exists")
        if os.access(hook_path, os.X_OK):
            print("✅ Hook is executable")
        else:
            print("❌ Hook is not executable")
            return False
    else:
        print("❌ Global pre-commit hook not found")
        return False
    
    # Test 2: Check git configuration
    try:
        result = subprocess.run(['git', 'config', '--global', 'core.hooksPath'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            hooks_path = result.stdout.strip()
            print(f"✅ Git hooks path configured: {hooks_path}")
        else:
            print("❌ Git hooks path not configured")
            return False
    except Exception as e:
        print(f"❌ Error checking git config: {e}")
        return False
    
    # Test 3: Check virtual environment
    venv_path = Path("/Users/alexmccarthy/SecurityScanner/Mark_II/.venv/bin/python3")
    if venv_path.exists():
        print("✅ Virtual environment found")
    else:
        print("⚠️  Virtual environment not found, using system Python")
    
    # Test 4: Check scanner script
    scanner_path = Path("/Users/alexmccarthy/SecurityScanner/Mark_II/security_scanner.py")
    if scanner_path.exists():
        print("✅ Security scanner script found")
    else:
        print("❌ Security scanner script not found")
        return False
    
    # Test 5: Quick scanner test
    print("\n🧪 Testing scanner functionality...")
    try:
        os.chdir("/Users/alexmccarthy/SecurityScanner/Mark_II")
        if venv_path.exists():
            cmd = [str(venv_path), "security_scanner.py", "--config-check"]
        else:
            cmd = ["python3", "security_scanner.py", "--config-check"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Scanner configuration test passed")
            print(result.stdout)
        else:
            print("❌ Scanner configuration test failed")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print("⚠️  Scanner test timed out")
        return False
    except Exception as e:
        print(f"❌ Error testing scanner: {e}")
        return False
    
    print("\n💡 VS Code Integration Tips:")
    print("1. Try committing from VS Code terminal instead of GUI")
    print("2. Check VS Code settings: git.useEditorAsCommitInput")
    print("3. Restart VS Code after hook changes")
    print("4. Check VS Code Output panel (Git) for hook messages")
    print("5. Use 'git commit --no-verify' to bypass if needed")
    
    return True

def simulate_vscode_commit():
    """Simulate how VS Code would run the hook"""
    print("\n🎯 Simulating VS Code commit process...")
    
    # Set environment variables that VS Code might set
    os.environ['VSCODE_GIT_COMMAND'] = '1'
    
    hook_path = "/Users/alexmccarthy/.git-hooks/pre-commit"
    
    try:
        result = subprocess.run([hook_path], 
                              capture_output=True, text=True, timeout=30,
                              cwd="/Users/alexmccarthy/SecurityScanner")
        
        print(f"Exit code: {result.returncode}")
        print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
            
        if result.returncode == 0:
            print("✅ Simulated commit would succeed")
        else:
            print("❌ Simulated commit would fail")
            
    except subprocess.TimeoutExpired:
        print("⚠️  Hook timed out (this might be the VS Code issue)")
    except Exception as e:
        print(f"❌ Error simulating commit: {e}")

if __name__ == "__main__":
    if test_vscode_integration():
        simulate_vscode_commit()
    else:
        print("\n❌ Basic tests failed. Fix the issues above first.")
