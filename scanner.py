#!/usr/bin/env python3
"""
Security Scanner - A comprehensive security analysis tool
Integrates with MCP server for automated scanning and monitoring
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Any
import re

class SecurityScanner:
    def __init__(self):
        self.issues = []
        self.patterns = {
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

    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for security issues"""
        issues = []
        
        # Skip scanning the scanner files themselves to avoid false positives
        scanner_files = ['scanner.py', 'mcp_server.py', 'mcp_server_enhanced.py']
        if file_path.name in scanner_files:
            return issues
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Check for secrets
                for pattern, severity, description in self.patterns['secrets']:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            issues.append({
                                'type': 'secret',
                                'severity': severity,
                                'file': str(file_path),
                                'line': line_num,
                                'description': description,
                                'recommendation': 'Move secrets to environment variables'
                            })
                
                # Check for vulnerabilities
                for pattern, severity, description in self.patterns['vulnerabilities']:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            issues.append({
                                'type': 'vulnerability',
                                'severity': severity,
                                'file': str(file_path),
                                'line': line_num,
                                'description': description,
                                'recommendation': 'Review and use safer alternatives'
                            })
                            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            
        return issues

    def scan_directory(self, directory: Path, extensions: List[str] = None) -> Dict[str, Any]:
        """Scan a directory for security issues"""
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs']
        
        all_issues = []
        scanned_files = 0
        
        for file_path in directory.rglob('*'):
            if (file_path.is_file() and 
                file_path.suffix in extensions and
                not any(part.startswith('.') for part in file_path.parts) and
                'node_modules' not in file_path.parts):
                
                file_issues = self.scan_file(file_path)
                all_issues.extend(file_issues)
                scanned_files += 1
        
        # Create summary
        summary = {
            'total': len(all_issues),
            'critical': len([i for i in all_issues if i['severity'] == 'critical']),
            'high': len([i for i in all_issues if i['severity'] == 'high']),
            'medium': len([i for i in all_issues if i['severity'] == 'medium']),
            'low': len([i for i in all_issues if i['severity'] == 'low']),
        }
        
        return {
            'issues': all_issues,
            'summary': summary,
            'scanned_files': scanned_files,
            'timestamp': subprocess.check_output(['date', '-Iseconds']).decode().strip()
        }

    def scan_git_staged(self) -> Dict[str, Any]:
        """Scan only git staged files"""
        try:
            # Get staged files
            result = subprocess.run(['git', 'diff', '--cached', '--name-only'], 
                                  capture_output=True, text=True, check=True)
            staged_files = result.stdout.strip().split('\n')
            
            if not staged_files or staged_files == ['']:
                return {
                    'issues': [],
                    'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'scanned_files': 0,
                    'message': 'No staged files to scan'
                }
            
            all_issues = []
            scanned_files = 0
            
            for file_name in staged_files:
                file_path = Path(file_name)
                if file_path.exists() and file_path.is_file():
                    file_issues = self.scan_file(file_path)
                    all_issues.extend(file_issues)
                    scanned_files += 1
            
            summary = {
                'total': len(all_issues),
                'critical': len([i for i in all_issues if i['severity'] == 'critical']),
                'high': len([i for i in all_issues if i['severity'] == 'high']),
                'medium': len([i for i in all_issues if i['severity'] == 'medium']),
                'low': len([i for i in all_issues if i['severity'] == 'low']),
            }
            
            return {
                'issues': all_issues,
                'summary': summary,
                'scanned_files': scanned_files,
                'timestamp': subprocess.check_output(['date', '-Iseconds']).decode().strip()
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'error': f'Git command failed: {e}',
                'issues': [],
                'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'scanned_files': 0
            }

    def generate_report(self, results: Dict[str, Any], output_format: str = 'json') -> str:
        """Generate a report in the specified format"""
        if output_format == 'json':
            return json.dumps(results, indent=2)
        
        elif output_format == 'text':
            report = []
            report.append("=" * 60)
            report.append("SECURITY SCAN REPORT")
            report.append("=" * 60)
            report.append(f"Timestamp: {results.get('timestamp', 'N/A')}")
            report.append(f"Files Scanned: {results.get('scanned_files', 0)}")
            report.append("")
            
            summary = results.get('summary', {})
            report.append("SUMMARY:")
            report.append(f"  Total Issues: {summary.get('total', 0)}")
            report.append(f"  Critical: {summary.get('critical', 0)}")
            report.append(f"  High: {summary.get('high', 0)}")
            report.append(f"  Medium: {summary.get('medium', 0)}")
            report.append(f"  Low: {summary.get('low', 0)}")
            report.append("")
            
            if results.get('issues'):
                report.append("ISSUES FOUND:")
                report.append("-" * 40)
                
                for issue in results['issues']:
                    report.append(f"[{issue['severity'].upper()}] {issue['description']}")
                    report.append(f"  File: {issue['file']}:{issue.get('line', '?')}")
                    report.append(f"  Type: {issue['type']}")
                    report.append(f"  Recommendation: {issue['recommendation']}")
                    report.append("")
            
            return '\n'.join(report)
        
        return json.dumps(results, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Security Scanner')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan (default: current directory)')
    parser.add_argument('--staged', action='store_true', help='Scan only git staged files')
    parser.add_argument('--format', choices=['json', 'text'], default='json', help='Output format')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    scanner = SecurityScanner()
    
    if args.staged:
        results = scanner.scan_git_staged()
    else:
        scan_path = Path(args.path)
        if not scan_path.exists():
            print(f"Error: Path '{scan_path}' does not exist", file=sys.stderr)
            sys.exit(1)
        
        results = scanner.scan_directory(scan_path)
    
    report = scanner.generate_report(results, args.format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)
    
    # Exit with error code if critical or high severity issues found
    summary = results.get('summary', {})
    if summary.get('critical', 0) > 0 or summary.get('high', 0) > 0:
        sys.exit(1)

if __name__ == '__main__':
    main()
