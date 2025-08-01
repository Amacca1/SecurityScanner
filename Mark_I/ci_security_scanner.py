#!/usr/bin/env python3
"""
Portable Security Scanner for CI/CD Integration
Can be used with GitHub Actions, GitLab CI, Jenkins, etc.
"""

import os
import sys
import json
import subprocess
from pathlib import Path

def send_notification(message, webhook_url=None):
    """Send notification to various services"""
    
    # Slack notification
    if webhook_url and 'slack' in webhook_url:
        import requests
        payload = {
            "text": message,
            "username": "Security Scanner",
            "icon_emoji": ":warning:"
        }
        requests.post(webhook_url, json=payload)
    
    # Discord notification
    elif webhook_url and 'discord' in webhook_url:
        import requests
        payload = {
            "content": message,
            "username": "Security Scanner"
        }
        requests.post(webhook_url, json=payload)
    
    # Email notification (if configured)
    email = os.environ.get('SECURITY_EMAIL')
    if email:
        subprocess.run(['mail', '-s', 'Security Alert', email], 
                      input=message, text=True)

def run_security_scan():
    """Run security scan and return results"""
    
    # Download scanner if not present
    scanner_path = Path('scanner.py')
    if not scanner_path.exists():
        print("📥 Downloading security scanner...")
        import urllib.request
        urllib.request.urlretrieve(
            'https://raw.githubusercontent.com/amacca1/SecurityScanner/main/scanner.py',
            'scanner.py'
        )
    
    # Run scanner
    result = subprocess.run(['python3', 'scanner.py', '--format', 'json'], 
                          capture_output=True, text=True)
    
    if result.returncode == 0:
        return json.loads(result.stdout), False
    else:
        try:
            return json.loads(result.stdout), True
        except:
            return {'error': 'Scanner failed', 'output': result.stdout}, True

def main():
    """Main CI/CD integration function"""
    
    print("🔍 Running Security Scanner in CI/CD mode...")
    
    # Get configuration from environment
    webhook_url = os.environ.get('SECURITY_WEBHOOK_URL')
    fail_on_high = os.environ.get('FAIL_ON_HIGH', 'true').lower() == 'true'
    fail_on_critical = os.environ.get('FAIL_ON_CRITICAL', 'true').lower() == 'true'
    
    # Run scan
    results, had_errors = run_security_scan()
    
    if had_errors and 'summary' not in results:
        print("❌ Scanner failed to run")
        sys.exit(1)
    
    summary = results.get('summary', {})
    critical = summary.get('critical', 0)
    high = summary.get('high', 0)
    medium = summary.get('medium', 0)
    low = summary.get('low', 0)
    
    # Print results
    print(f"📊 Scan Results:")
    print(f"   Critical: {critical}")
    print(f"   High: {high}")
    print(f"   Medium: {medium}")
    print(f"   Low: {low}")
    
    # Check if we should fail
    should_fail = False
    if fail_on_critical and critical > 0:
        should_fail = True
        print("🚨 CRITICAL vulnerabilities found - failing build")
    
    if fail_on_high and high > 0:
        should_fail = True
        print("⚠️ HIGH vulnerabilities found - failing build")
    
    # Send notifications
    if critical > 0 or high > 0:
        repo = os.environ.get('GITHUB_REPOSITORY', 'Unknown Repository')
        commit = os.environ.get('GITHUB_SHA', 'Unknown Commit')
        
        message = f"🚨 Security vulnerabilities found in {repo}\n"
        message += f"Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}\n"
        message += f"Commit: {commit}"
        
        send_notification(message, webhook_url)
    
    # Save results for artifacts
    with open('security-results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # Exit with appropriate code
    if should_fail:
        sys.exit(1)
    else:
        print("✅ Security scan completed successfully")
        sys.exit(0)

if __name__ == '__main__':
    main()
