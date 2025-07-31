#!/usr/bin/env python3
"""
MCP Server for Automated Security Scanning
Monitors git repo, triggers scanner, and executes security actions
"""

import os
import subprocess
import json
from flask import Flask, request, jsonify
from pathlib import Path

app = Flask(__name__)

SCANNER_PATH = 'scanner.py'  # Path to your scanner
REPO_PATH = '.'  # Path to your repo

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

# Example: Poll for git changes (could be run in background)
def poll_git_changes():
    # This is a stub. In production, use webhooks or polling logic.
    pass

if __name__ == '__main__':
    app.run(port=5001)
