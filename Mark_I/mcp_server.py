#!/usr/bin/env python3
"""
Enhanced MCP Server for Automated Security Scanning
Monitors all repositories you manage, triggers scanner, and executes security actions
Includes GitHub webhook integration for scanning commits across multiple accounts/orgs
"""

import os
import subprocess
import json
import requests
import hashlib
import hmac
import base64
import re
from flask import Flask, request, jsonify
from pathlib import Path

# Load environment variables from .env file if it exists
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

app = Flask(__name__)

SCANNER_PATH = 'scanner.py'  # Path to your scanner
REPO_PATH = '.'  # Path to your repo

# GitHub configuration
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')  # Set this in your environment
GITHUB_USERNAME = 'amacca1'
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', 'your-webhook-secret')  # Set this in your environment

# Configuration for multi-repository monitoring
MONITORED_USERS = os.environ.get('MONITORED_USERS', 'amacca1').split(',')  # Comma-separated list
MONITORED_ORGS = os.environ.get('MONITORED_ORGS', '').split(',') if os.environ.get('MONITORED_ORGS') else []
ALLOWED_REPOS = os.environ.get('ALLOWED_REPOS', '').split(',') if os.environ.get('ALLOWED_REPOS') else []  # Specific repos
IGNORED_REPOS = os.environ.get('IGNORED_REPOS', '').split(',') if os.environ.get('IGNORED_REPOS') else []  # Repos to ignore

# Utility: Run scanner and parse results
def run_scanner(scan_staged=True):
    cmd = ['python3', SCANNER_PATH]
    if scan_staged:
        cmd.append('--staged')
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        output = json.loads(result.stdout)
    except Exception:
        output = {'error': 'Failed to parse scanner output', 'raw': result.stdout}
    return output

# Utility: Send Mac notification
def send_mac_notification(message):
    result = subprocess.run(['osascript', '-e', f'display notification "{message}" with title "Security Alert"'], capture_output=True, text=True)
    if result.returncode != 0:
        print("Notification error:", result.stderr)

# Utility: Log incident
def log_incident(data):
    with open('security_incidents.log', 'a') as f:
        f.write(json.dumps(data) + '\n')

# Utility: Send email (example using mail)
def send_email(subject, body, to='alexcomp2@outlook.com'):
    subprocess.run(['mail', '-s', subject, to], input=body, text=True)

# Endpoint: Trigger scan (simulate git event)
@app.route('/scan', methods=['POST'])
def scan():
    scan_staged = request.json.get('staged', True)
    results = run_scanner(scan_staged)
    summary = results.get('summary', {})
    if summary.get('critical', 0) > 0 or summary.get('high', 0) > 0:
        send_mac_notification('Critical/High vulnerabilities found!')
        log_incident(results)
        send_email('Security Alert', json.dumps(results, indent=2))
        return jsonify({'status': 'fail', 'results': results}), 400
    return jsonify({'status': 'ok', 'results': results})

# Utility: Verify GitHub webhook signature
def verify_github_signature(payload_body, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256"""
    if not signature_header:
        return False
    
    hash_object = hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

# Utility: Get file content from GitHub API
def get_file_content_from_github(repo_full_name, file_path, commit_sha):
    """Get file content from GitHub API"""
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    url = f'https://api.github.com/repos/{repo_full_name}/contents/{file_path}?ref={commit_sha}'
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        content_data = response.json()
        if content_data['encoding'] == 'base64':
            return base64.b64decode(content_data['content']).decode('utf-8')
    return None

# Utility: Scan modified files from a GitHub commit
def scan_github_files(repo_full_name, commit_sha, modified_files):
    """Scan modified files from a GitHub commit"""
    issues = []
    scanned_files = 0
    
    # File extensions to scan
    extensions = ['.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs']
    
    for file_info in modified_files:
        file_path = file_info['filename']
        file_ext = Path(file_path).suffix
        
        # Skip if not a supported file type
        if file_ext not in extensions:
            continue
            
        # Skip deleted files
        if file_info['status'] == 'removed':
            continue
            
        # Get file content from GitHub
        content = get_file_content_from_github(repo_full_name, file_path, commit_sha)
        if not content:
            continue
            
        # Scan the content using the same patterns from SecurityScanner
        file_issues = scan_content(content, file_path)
        issues.extend(file_issues)
        scanned_files += 1
    
    # Create summary
    summary = {
        'total': len(issues),
        'critical': len([i for i in issues if i['severity'] == 'critical']),
        'high': len([i for i in issues if i['severity'] == 'high']),
        'medium': len([i for i in issues if i['severity'] == 'medium']),
        'low': len([i for i in issues if i['severity'] == 'low']),
    }
    
    return {
        'issues': issues,
        'summary': summary,
        'scanned_files': scanned_files,
        'repository': repo_full_name,
        'commit': commit_sha,
        'timestamp': subprocess.check_output(['date', '-Iseconds']).decode().strip()
    }

# Utility: Scan file content using the same patterns as SecurityScanner
def scan_content(content, file_path):
    """Scan file content using the same patterns as SecurityScanner"""
    issues = []
    
    # Skip scanning the scanner files themselves to avoid false positives
    scanner_files = ['scanner.py', 'mcp_server.py', 'mcp_server_enhanced.py']
    if any(file_path.endswith(f) for f in scanner_files):
        return issues
    
    lines = content.split('\n')
    
    # Same patterns as in SecurityScanner
    patterns = {
        'secrets': [
            (r'(?:password|pwd|pass)\s*[:=]\s*[\'"][^\'"]+[\'"]', 'high', 'Hardcoded password'),
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"][^\'"]+[\'"]', 'critical', 'API key in code'),
            (r'(?:secret|token)\s*[:=]\s*[\'"][^\'"]+[\'"]', 'high', 'Secret token in code'),
            (r'sk-[a-zA-Z0-9]{48}', 'critical', 'OpenAI API key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'critical', 'GitHub personal access token'),
            (r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}', 'critical', 'Slack bot token'),
        ],
        # Security vulnerability patterns
        'vulnerabilities': [
            (r'\beval\s*\(', 'high', 'Use of eval() function'),
            (r'\bexec\s*\(', 'high', 'Use of exec() function'),
            (r'os\.system\s*\(', 'high', 'OS command execution'),
            (r'subprocess\.call\s*\(.*shell\s*=\s*True', 'high', 'Shell injection risk'),
            (r'\binput\s*\([^)]*\)', 'medium', 'Use of input() function'),
            (r'pickle\.loads?\s*\(', 'high', 'Unsafe pickle deserialization'),
            (r'yaml\.load\s*\(', 'medium', 'Unsafe YAML loading'),
            (r'sql.*\+.*[\'"].*%[\'"]', 'high', 'Potential SQL injection'),
        ]
    }
    
    # Check for secrets
    for pattern, severity, description in patterns['secrets']:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    'type': 'secret',
                    'severity': severity,
                    'file': file_path,
                    'line': line_num,
                    'description': description,
                    'recommendation': 'Move secrets to environment variables'
                })
    
    # Check for vulnerabilities
    for pattern, severity, description in patterns['vulnerabilities']:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    'type': 'vulnerability',
                    'severity': severity,
                    'file': file_path,
                    'line': line_num,
                    'description': description,
                    'recommendation': 'Review and use safer alternatives'
                })
    
    return issues

# Utility: Determine if a repository should be monitored
def should_monitor_repository(repo_full_name):
    """Determine if a repository should be monitored based on configuration"""
    
    # If specific repos are allowed, only monitor those
    if ALLOWED_REPOS and ALLOWED_REPOS != ['']:
        return repo_full_name in ALLOWED_REPOS
    
    # Skip ignored repositories
    if repo_full_name in IGNORED_REPOS:
        return False
    
    # Check if it's from a monitored user
    for user in MONITORED_USERS:
        if repo_full_name.startswith(f'{user}/'):
            return True
    
    # Check if it's from a monitored organization
    for org in MONITORED_ORGS:
        if repo_full_name.startswith(f'{org}/'):
            return True
    
    # If you have admin access, check via GitHub API
    if GITHUB_TOKEN:
        try:
            headers = {'Authorization': f'token {GITHUB_TOKEN}'}
            response = requests.get(f'https://api.github.com/repos/{repo_full_name}', headers=headers)
            if response.status_code == 200:
                repo_data = response.json()
                permissions = repo_data.get('permissions', {})
                # Monitor if you have admin or maintain permissions
                return permissions.get('admin', False) or permissions.get('maintain', False)
        except:
            pass
    
    return False
# Enhanced endpoint: GitHub webhook for monitoring ALL repositories you manage
@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    """Handle GitHub webhook events for push commits across all managed repositories"""
    
    # Verify webhook signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_github_signature(request.data, signature):
        return jsonify({'error': 'Invalid signature'}), 403
    
    event_type = request.headers.get('X-GitHub-Event')
    
    if event_type == 'push':
        payload = request.json
        
        # Check if we should monitor this repository
        repo_full_name = payload['repository']['full_name']
        if not should_monitor_repository(repo_full_name):
            return jsonify({'message': f'Ignored - repository {repo_full_name} not in monitoring scope'}), 200
        
        print(f"📡 Processing webhook for repository: {repo_full_name}")
        
        # Get commit information
        commits = payload['commits']
        
        for commit in commits:
            commit_sha = commit['id']
            modified_files = commit.get('modified', []) + commit.get('added', [])
            
            # Convert to format expected by scan_github_files
            file_list = [{'filename': f, 'status': 'modified'} for f in modified_files]
            
            # Scan the commit
            results = scan_github_files(repo_full_name, commit_sha, file_list)
            
            # If critical or high vulnerabilities found, take action
            summary = results.get('summary', {})
            if summary.get('critical', 0) > 0 or summary.get('high', 0) > 0:
                # Enhanced notification message with repository info
                message = f'🚨 Critical/High vulnerabilities found in {repo_full_name}!'
                send_mac_notification(message)
                
                # Log incident with GitHub context
                log_incident({
                    **results,
                    'source': 'github_webhook',
                    'commit_url': f"https://github.com/{repo_full_name}/commit/{commit_sha}"
                })
                
                # Enhanced email with GitHub context
                email_body = f"""
Security Alert: Vulnerabilities detected in GitHub repository

Repository: {repo_full_name}
Commit: {commit_sha}
Commit URL: https://github.com/{repo_full_name}/commit/{commit_sha}
Author: {commit.get('author', {}).get('name', 'Unknown')}

Scan Results:
{json.dumps(results, indent=2)}
"""
                send_email(f'Security Alert - {repo_full_name}', email_body)
                
                print(f"🚨 Vulnerabilities found in {repo_full_name}: {summary.get('critical', 0)} critical, {summary.get('high', 0)} high")
            else:
                print(f"✅ No critical/high vulnerabilities in {repo_full_name}")
        
        return jsonify({'message': 'Webhook processed successfully', 'repository': repo_full_name}), 200
    
    return jsonify({'message': 'Event type not supported'}), 200

# New endpoint: List all repositories you manage
@app.route('/repositories', methods=['GET'])
def list_repositories():
    """List all repositories that would be monitored"""
    if not GITHUB_TOKEN:
        return jsonify({'error': 'GitHub token not configured'}), 400
    
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    repositories = []
    
    try:
        # Get repositories you have access to
        response = requests.get('https://api.github.com/user/repos', headers=headers, params={'per_page': 100})
        if response.status_code == 200:
            for repo in response.json():
                repo_name = repo['full_name']
                if should_monitor_repository(repo_name):
                    repositories.append({
                        'name': repo_name,
                        'private': repo['private'],
                        'permissions': repo.get('permissions', {}),
                        'url': repo['html_url']
                    })
        
        return jsonify({
            'monitored_repositories': repositories,
            'count': len(repositories),
            'configuration': {
                'monitored_users': MONITORED_USERS,
                'monitored_orgs': MONITORED_ORGS,
                'allowed_repos': ALLOWED_REPOS,
                'ignored_repos': IGNORED_REPOS
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Enhanced MCP Security Scanner Server")
    print(f"📋 Monitored Users: {MONITORED_USERS}")
    print(f"🏢 Monitored Organizations: {MONITORED_ORGS}")
    print(f"✅ Allowed Repositories: {ALLOWED_REPOS if ALLOWED_REPOS != [''] else 'All (based on other filters)'}")
    print(f"❌ Ignored Repositories: {IGNORED_REPOS}")
    print(f"🔗 Server starting on port 5001...")
    app.run(port=5001)
