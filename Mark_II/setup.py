#!/usr/bin/env python3
"""
Security Scanner Setup and Configuration Script
Helps users configure the scanner and test functionality
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from getpass import getpass

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'anthropic', 'gitpython', 'plyer', 'python-dotenv'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n📦 Installing missing packages: {', '.join(missing_packages)}")
        subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing_packages)
        return False
    
    return True

def setup_environment():
    """Interactive setup of environment variables"""
    print("\n🔧 Environment Configuration")
    print("=" * 50)
    
    env_file = Path('.env')
    env_vars = {}
    
    # Load existing .env if it exists
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key] = value
    
    # Claude API Key
    print("\n1. Claude AI Configuration")
    current_api_key = env_vars.get('ANTHROPIC_API_KEY', '')
    if current_api_key and current_api_key != 'your_anthropic_api_key_here':
        print(f"   Current API key: {current_api_key[:20]}..." if len(current_api_key) > 20 else f"   Current API key: {current_api_key}")
        update = input("   Update API key? (y/N): ").lower() == 'y'
    else:
        update = True
    
    if update:
        api_key = getpass("   Enter your Anthropic API key: ").strip()
        if api_key:
            env_vars['ANTHROPIC_API_KEY'] = api_key
    
    # Email Configuration
    print("\n2. Email Alert Configuration")
    email = env_vars.get('EMAIL_ADDRESS', '')
    if email and email != 'your_email@gmail.com':
        print(f"   Current email: {email}")
        update = input("   Update email settings? (y/N): ").lower() == 'y'
    else:
        update = True
    
    if update:
        email = input("   Enter your email address: ").strip()
        if email:
            env_vars['EMAIL_ADDRESS'] = email
            
            print("\n   For Gmail, you'll need an app password:")
            print("   1. Go to Google Account settings")
            print("   2. Enable 2-factor authentication")
            print("   3. Generate an app password for 'Mail'")
            
            password = getpass("   Enter your email app password: ").strip()
            if password:
                env_vars['EMAIL_PASSWORD'] = password
    
    # Scanner Configuration
    print("\n3. Scanner Configuration")
    
    threshold = env_vars.get('VULNERABILITY_THRESHOLD', 'high')
    print(f"   Current vulnerability threshold: {threshold}")
    print("   Options: low, medium, high, critical")
    new_threshold = input(f"   Enter threshold (current: {threshold}): ").strip()
    if new_threshold and new_threshold in ['low', 'medium', 'high', 'critical']:
        env_vars['VULNERABILITY_THRESHOLD'] = new_threshold
    
    notifications = env_vars.get('ENABLE_NOTIFICATIONS', 'true')
    new_notifications = input(f"   Enable Mac notifications? (current: {notifications}): ").strip()
    if new_notifications.lower() in ['true', 'false']:
        env_vars['ENABLE_NOTIFICATIONS'] = new_notifications.lower()
    
    email_alerts = env_vars.get('ENABLE_EMAIL_ALERTS', 'true')
    new_email_alerts = input(f"   Enable email alerts? (current: {email_alerts}): ").strip()
    if new_email_alerts.lower() in ['true', 'false']:
        env_vars['ENABLE_EMAIL_ALERTS'] = new_email_alerts.lower()
    
    # Write updated .env file
    with open(env_file, 'w') as f:
        f.write("# Claude API Configuration\n")
        f.write(f"ANTHROPIC_API_KEY={env_vars.get('ANTHROPIC_API_KEY', 'your_anthropic_api_key_here')}\n\n")
        
        f.write("# Email Configuration\n")
        f.write(f"SMTP_SERVER={env_vars.get('SMTP_SERVER', 'smtp.gmail.com')}\n")
        f.write(f"SMTP_PORT={env_vars.get('SMTP_PORT', '587')}\n")
        f.write(f"EMAIL_ADDRESS={env_vars.get('EMAIL_ADDRESS', 'your_email@gmail.com')}\n")
        f.write(f"EMAIL_PASSWORD={env_vars.get('EMAIL_PASSWORD', 'your_app_password_here')}\n\n")
        
        f.write("# GitHub Configuration (optional)\n")
        f.write(f"GITHUB_TOKEN={env_vars.get('GITHUB_TOKEN', 'your_github_token_here')}\n")
        f.write(f"WEBHOOK_SECRET={env_vars.get('WEBHOOK_SECRET', 'your_webhook_secret_here')}\n\n")
        
        f.write("# Scanner Configuration\n")
        f.write(f"VULNERABILITY_THRESHOLD={env_vars.get('VULNERABILITY_THRESHOLD', 'high')}\n")
        f.write(f"ENABLE_NOTIFICATIONS={env_vars.get('ENABLE_NOTIFICATIONS', 'true')}\n")
        f.write(f"ENABLE_EMAIL_ALERTS={env_vars.get('ENABLE_EMAIL_ALERTS', 'true')}\n")
        f.write(f"LOG_LEVEL={env_vars.get('LOG_LEVEL', 'INFO')}\n")
    
    print("\n✅ Environment configuration saved!")

def create_test_files():
    """Create test files with known vulnerabilities"""
    print("\n🧪 Creating test files with vulnerabilities...")
    
    test_dir = Path('test_vulnerabilities')
    test_dir.mkdir(exist_ok=True)
    
    # Python test file with vulnerabilities
    python_test = test_dir / 'vulnerable_test.py'
    with open(python_test, 'w') as f:
        f.write('''#!/usr/bin/env python3
"""
Test file with intentional security vulnerabilities
DO NOT USE THIS CODE IN PRODUCTION
"""

import os
import subprocess
import pickle

# Hard-coded credentials (VULNERABILITY)
API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
PASSWORD = "admin123"
SECRET_TOKEN = "super-secret-token-123"

def unsafe_command_execution(user_input):
    """Unsafe command execution (VULNERABILITY)"""
    # Command injection vulnerability
    os.system(f"echo {user_input}")
    
    # Shell injection with subprocess
    subprocess.call(f"ls {user_input}", shell=True)

def unsafe_eval(user_code):
    """Unsafe eval usage (VULNERABILITY)"""
    # Code injection vulnerability
    result = eval(user_code)
    return result

def unsafe_pickle_load(data):
    """Unsafe pickle deserialization (VULNERABILITY)"""
    # Arbitrary code execution vulnerability
    return pickle.loads(data)

def sql_injection_example(user_id):
    """SQL injection vulnerability"""
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    # This is vulnerable to SQL injection
    return query

# Using input() function (potential vulnerability in Python 2)
user_data = input("Enter some data: ")

if __name__ == "__main__":
    print("This is a test file with security vulnerabilities")
    unsafe_command_execution("test")
    unsafe_eval("1+1")
''')
    
    # JavaScript test file
    js_test = test_dir / 'vulnerable_test.js'
    with open(js_test, 'w') as f:
        f.write('''// Test JavaScript file with vulnerabilities
// DO NOT USE THIS CODE IN PRODUCTION

// Hard-coded API key (VULNERABILITY)
const API_KEY = "xoxb-DUMMY-TOKEN-FOR-TESTING";
const PASSWORD = "admin123";

// Unsafe eval usage (VULNERABILITY)
function unsafeEval(userCode) {
    return eval(userCode);
}

// DOM XSS vulnerability
function unsafeHTML(userInput) {
    document.getElementById('content').innerHTML = userInput;
}

// Command injection (if running in Node.js)
const exec = require('child_process').exec;
function unsafeCommand(userInput) {
    exec(`echo ${userInput}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// SQL injection vulnerability
function getUserData(userId) {
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    return query;
}

console.log("This is a test file with security vulnerabilities");
''')
    
    print(f"✅ Test files created in {test_dir}/")
    return test_dir

def test_scanner(test_dir):
    """Test the scanner with vulnerable files"""
    print("\n🔍 Testing scanner with vulnerable files...")
    
    # Initialize a git repo in test directory if not exists
    if not (test_dir / '.git').exists():
        subprocess.run(['git', 'init'], cwd=test_dir, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=test_dir)
        subprocess.run(['git', 'config', 'user.name', 'Test User'], cwd=test_dir)
    
    # Add and stage the test files
    subprocess.run(['git', 'add', '.'], cwd=test_dir)
    
    # Run the scanner
    scanner_path = Path(__file__).parent / 'security_scanner.py'
    result = subprocess.run([
        sys.executable, str(scanner_path), 
        '--repo-path', str(test_dir)
    ], capture_output=True, text=True)
    
    print("Scanner output:")
    print(result.stdout)
    
    if result.stderr:
        print("Scanner errors:")
        print(result.stderr)
    
    # Check if results file was created
    results_file = test_dir / 'security_scan_results.json'
    if results_file.exists():
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        summary = results.get('summary', {})
        print(f"\n📊 Test Results:")
        print(f"   Files scanned: {summary.get('total_files', 0)}")
        print(f"   Vulnerable files: {summary.get('vulnerable_files', 0)}")
        print(f"   Critical issues: {summary.get('critical_issues', 0)}")
        print(f"   High issues: {summary.get('high_issues', 0)}")
        print(f"   Medium issues: {summary.get('medium_issues', 0)}")
        print(f"   Low issues: {summary.get('low_issues', 0)}")
        
        if summary.get('vulnerable_files', 0) > 0:
            print("✅ Scanner successfully detected vulnerabilities!")
        else:
            print("⚠️  No vulnerabilities detected - check configuration")
    
    return result.returncode == 0

def install_git_hooks():
    """Install git hooks"""
    print("\n🪝 Installing Git Hooks...")
    
    hooks_installer = Path(__file__).parent / 'install_hooks.py'
    
    print("Choose hook installation type:")
    print("1. Local (current repository only)")
    print("2. Global (all repositories)")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        result = subprocess.run([sys.executable, str(hooks_installer), '--local'])
    elif choice == "2":
        result = subprocess.run([sys.executable, str(hooks_installer), '--global'])
    else:
        print("Invalid choice")
        return False
    
    return result.returncode == 0

def main():
    print("🔒 Security Scanner Mark II - Setup & Configuration")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        print("\n📦 Dependencies installed. Please run the setup again.")
        return
    
    # Setup environment
    setup_environment()
    
    # Create and test with vulnerable files
    test_dir = create_test_files()
    test_scanner(test_dir)
    
    # Install git hooks
    print("\n" + "=" * 60)
    install_hooks = input("Install git hooks now? (Y/n): ").lower()
    if install_hooks != 'n':
        install_git_hooks()
    
    print("\n✅ Setup complete!")
    print("\nNext steps:")
    print("1. Update your .env file with actual API keys")
    print("2. Test the scanner: python3 security_scanner.py --config-check")
    print("3. The scanner will automatically run on git commits")
    print("4. Check security_scan_results.json for detailed reports")

if __name__ == "__main__":
    main()
