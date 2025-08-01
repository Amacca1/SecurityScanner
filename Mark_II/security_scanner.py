#!/usr/bin/env python3
"""
Advanced Security Scanner Mark II
A pre-commit security scanner that uses Claude AI to analyze code for vulnerabilities.
Sends Mac notifications and email alerts for high-severity issues.
"""

import os
import sys
import json
import subprocess
import smtplib
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Email imports with error handling for Python 3.13 compatibility
try:
    from email.mime.text import MIMEText as MimeText
    from email.mime.multipart import MIMEMultipart as MimeMultipart  
    from email.mime.base import MIMEBase as MimeBase
    from email import encoders
except ImportError:
    # Fallback for older Python versions
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    from email.mime.base import MimeBase
    from email import encoders

import git
from anthropic import Anthropic
from dotenv import load_dotenv
from plyer import notification

# Load environment variables
load_dotenv()

class SecurityNotificationManager:
    """Handles notifications via Mac notifications and email"""
    
    def __init__(self):
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.email_address = os.getenv('EMAIL_ADDRESS')
        self.email_password = os.getenv('EMAIL_PASSWORD')
        self.enable_notifications = os.getenv('ENABLE_NOTIFICATIONS', 'true').lower() == 'true'
        self.enable_email = os.getenv('ENABLE_EMAIL_ALERTS', 'true').lower() == 'true'
        
    def send_mac_notification(self, title: str, message: str, timeout: int = 10):
        """Send a macOS notification"""
        if not self.enable_notifications:
            return
            
        try:
            notification.notify(
                title=title,
                message=message,
                timeout=timeout,
                app_name="Security Scanner"
            )
            logging.info(f"Mac notification sent: {title}")
        except Exception as e:
            logging.error(f"Failed to send Mac notification: {e}")
    
    def send_email_alert(self, subject: str, body: str, attachments: List[str] = None):
        """Send an email alert with vulnerability details"""
        if not self.enable_email or not self.email_address or not self.email_password:
            logging.warning("Email configuration incomplete, skipping email alert")
            return
            
        try:
            msg = MimeMultipart()
            msg['From'] = self.email_address
            msg['To'] = self.email_address
            msg['Subject'] = subject
            
            msg.attach(MimeText(body, 'html'))
            
            # Add attachments if provided
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as attachment:
                            part = MimeBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {os.path.basename(file_path)}'
                            )
                            msg.attach(part)
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_address, self.email_password)
            text = msg.as_string()
            server.sendmail(self.email_address, self.email_address, text)
            server.quit()
            
            logging.info(f"Email alert sent: {subject}")
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")


class ClaudeSecurityAnalyzer:
    """Uses Claude AI to analyze code for security vulnerabilities"""
    
    def __init__(self):
        self.client = None
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if api_key:
            self.client = Anthropic(api_key=api_key)
        else:
            logging.warning("ANTHROPIC_API_KEY not set, Claude analysis will be skipped")
    
    def analyze_code(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze code content using Claude AI"""
        if not self.client:
            return {"error": "Claude API not configured"}
        
        prompt = f"""
You are a cybersecurity expert analyzing code for vulnerabilities. Please analyze the following code file and identify any security issues.

File: {file_path}
Content:
```
{content}
```

Please provide a detailed analysis in the following JSON format:
{{
    "severity": "low|medium|high|critical",
    "vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "line": line_number,
            "description": "detailed description",
            "impact": "potential impact",
            "recommendation": "specific fix recommendation",
            "code_snippet": "vulnerable code"
        }}
    ],
    "summary": "overall security assessment",
    "recommended_actions": [
        "action 1",
        "action 2"
    ]
}}

Focus on:
1. Injection vulnerabilities (SQL, Command, Code)
2. Authentication and authorization issues
3. Cryptographic weaknesses
4. Input validation problems
5. Secrets and credentials exposure
6. Insecure dependencies
7. Business logic flaws
8. Data exposure risks

Only flag actual security vulnerabilities, not code quality issues.
"""
        
        try:
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Parse the JSON response
            response_text = response.content[0].text
            # Extract JSON from response if it's wrapped in markdown
            if "```json" in response_text:
                start = response_text.find("```json") + 7
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            
            return json.loads(response_text)
        except Exception as e:
            logging.error(f"Claude analysis failed: {e}")
            return {"error": f"Analysis failed: {str(e)}"}


class GitCommitScanner:
    """Handles git integration and file detection"""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        try:
            self.repo = git.Repo(repo_path)
        except git.InvalidGitRepositoryError:
            logging.error(f"Not a git repository: {repo_path}")
            self.repo = None
    
    def get_staged_files(self) -> List[str]:
        """Get list of staged files for commit"""
        if not self.repo:
            return []
        
        staged_files = []
        for item in self.repo.index.diff("HEAD"):
            if item.change_type in ['A', 'M']:  # Added or Modified
                staged_files.append(item.a_path)
        
        return staged_files
    
    def get_file_content(self, file_path: str) -> str:
        """Get content of a file from the staging area"""
        if not self.repo:
            return ""
        
        try:
            # Get content from staging area
            blob = self.repo.index.entries[file_path].binsha
            return self.repo.odb.stream(blob).read().decode('utf-8', errors='ignore')
        except:
            # Fallback to reading from working directory
            full_path = self.repo_path / file_path
            if full_path.exists():
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        
        return ""


class SecurityScanner:
    """Main security scanner class"""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path
        self.git_scanner = GitCommitScanner(repo_path)
        self.claude_analyzer = ClaudeSecurityAnalyzer()
        self.notification_manager = SecurityNotificationManager()
        self.vulnerability_threshold = os.getenv('VULNERABILITY_THRESHOLD', 'high')
        
        # Setup logging
        log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO'))
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_scanner.log'),
                logging.StreamHandler()
            ]
        )
    
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if a file should be scanned"""
        # File extensions to scan
        scan_extensions = {
            '.py', '.js', '.ts', '.php', '.java', '.cpp', '.c', '.cs',
            '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.sh', '.bash',
            '.sql', '.yaml', '.yml', '.json', '.xml', '.html', '.jsp'
        }
        
        # Skip certain directories and files
        skip_patterns = {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            'build', 'dist', 'target', '.next', 'coverage'
        }
        
        path_obj = Path(file_path)
        
        # Check if file is in a directory we should skip
        for part in path_obj.parts:
            if part in skip_patterns:
                return False
        
        # Check file extension
        return path_obj.suffix.lower() in scan_extensions
    
    def scan_commit(self) -> Dict[str, Any]:
        """Scan all staged files for security vulnerabilities"""
        logging.info("Starting security scan of staged files...")
        
        staged_files = self.git_scanner.get_staged_files()
        if not staged_files:
            logging.info("No staged files found")
            return {"status": "success", "message": "No files to scan"}
        
        logging.info(f"Found {len(staged_files)} staged files")
        
        scan_results = {
            "timestamp": datetime.now().isoformat(),
            "scanned_files": [],
            "vulnerabilities": [],
            "summary": {
                "total_files": 0,
                "vulnerable_files": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
                "low_issues": 0
            }
        }
        
        for file_path in staged_files:
            if not self.should_scan_file(file_path):
                continue
            
            logging.info(f"Scanning file: {file_path}")
            scan_results["summary"]["total_files"] += 1
            
            content = self.git_scanner.get_file_content(file_path)
            if not content:
                continue
            
            # Analyze with Claude
            analysis = self.claude_analyzer.analyze_code(file_path, content)
            
            if "error" in analysis:
                logging.error(f"Analysis failed for {file_path}: {analysis['error']}")
                continue
            
            file_result = {
                "file": file_path,
                "analysis": analysis
            }
            
            scan_results["scanned_files"].append(file_result)
            
            # Count vulnerabilities by severity
            if "vulnerabilities" in analysis and analysis["vulnerabilities"]:
                scan_results["summary"]["vulnerable_files"] += 1
                scan_results["vulnerabilities"].extend(analysis["vulnerabilities"])
                
                for vuln in analysis["vulnerabilities"]:
                    severity = vuln.get("severity", "low")
                    if severity == "critical":
                        scan_results["summary"]["critical_issues"] += 1
                    elif severity == "high":
                        scan_results["summary"]["high_issues"] += 1
                    elif severity == "medium":
                        scan_results["summary"]["medium_issues"] += 1
                    else:
                        scan_results["summary"]["low_issues"] += 1
        
        self._process_scan_results(scan_results)
        return scan_results
    
    def _process_scan_results(self, results: Dict[str, Any]):
        """Process scan results and send notifications if needed"""
        summary = results["summary"]
        
        # Check if we need to alert based on threshold
        should_alert = False
        if self.vulnerability_threshold == "critical" and summary["critical_issues"] > 0:
            should_alert = True
        elif self.vulnerability_threshold == "high" and (summary["critical_issues"] > 0 or summary["high_issues"] > 0):
            should_alert = True
        elif self.vulnerability_threshold == "medium" and (summary["critical_issues"] > 0 or summary["high_issues"] > 0 or summary["medium_issues"] > 0):
            should_alert = True
        elif self.vulnerability_threshold == "low" and len(results["vulnerabilities"]) > 0:
            should_alert = True
        
        if should_alert:
            self._send_security_alert(results)
        
        # Save results to file
        with open('security_scan_results.json', 'w') as f:
            json.dump(results, f, indent=2)
    
    def _send_security_alert(self, results: Dict[str, Any]):
        """Send security alerts via notifications and email"""
        summary = results["summary"]
        
        # Mac notification
        critical_count = summary["critical_issues"]
        high_count = summary["high_issues"]
        
        if critical_count > 0:
            title = "🚨 CRITICAL Security Issues Found!"
            message = f"Found {critical_count} critical and {high_count} high severity vulnerabilities in staged files"
        elif high_count > 0:
            title = "⚠️  High Security Issues Found"
            message = f"Found {high_count} high severity vulnerabilities in staged files"
        else:
            title = "⚠️  Security Issues Found"
            message = f"Found security vulnerabilities in staged files"
        
        self.notification_manager.send_mac_notification(title, message)
        
        # Email alert
        email_subject = f"Security Alert: Vulnerabilities Found in Commit"
        email_body = self._generate_email_report(results)
        self.notification_manager.send_email_alert(
            email_subject,
            email_body,
            ['security_scan_results.json']
        )
    
    def _generate_email_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML email report"""
        summary = results["summary"]
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #f44336; color: white; padding: 10px; }}
                .summary {{ background-color: #f9f9f9; padding: 10px; margin: 10px 0; }}
                .vulnerability {{ border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
                .critical {{ border-left-color: #f44336; }}
                .high {{ border-left-color: #ff9800; }}
                .medium {{ border-left-color: #ffeb3b; }}
                .low {{ border-left-color: #4caf50; }}
                .recommendation {{ background-color: #e8f5e8; padding: 10px; margin: 5px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Security Vulnerability Report</h2>
                <p>Scan completed at: {results['timestamp']}</p>
            </div>
            
            <div class="summary">
                <h3>Summary</h3>
                <ul>
                    <li>Total files scanned: {summary['total_files']}</li>
                    <li>Vulnerable files: {summary['vulnerable_files']}</li>
                    <li>Critical issues: {summary['critical_issues']}</li>
                    <li>High issues: {summary['high_issues']}</li>
                    <li>Medium issues: {summary['medium_issues']}</li>
                    <li>Low issues: {summary['low_issues']}</li>
                </ul>
            </div>
        """
        
        # Add vulnerability details
        for file_result in results["scanned_files"]:
            if "vulnerabilities" in file_result["analysis"] and file_result["analysis"]["vulnerabilities"]:
                html += f"<h3>File: {file_result['file']}</h3>"
                
                for vuln in file_result["analysis"]["vulnerabilities"]:
                    severity_class = vuln.get("severity", "low")
                    html += f"""
                    <div class="vulnerability {severity_class}">
                        <h4>{vuln.get('type', 'Unknown')} ({vuln.get('severity', 'unknown').upper()})</h4>
                        <p><strong>Line:</strong> {vuln.get('line', 'N/A')}</p>
                        <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                        <p><strong>Impact:</strong> {vuln.get('impact', 'N/A')}</p>
                        <div class="recommendation">
                            <strong>Recommendation:</strong> {vuln.get('recommendation', 'N/A')}
                        </div>
                    </div>
                    """
        
        html += "</body></html>"
        return html


def main():
    """Main function to run the security scanner"""
    parser = argparse.ArgumentParser(description='Security Scanner Mark II')
    parser.add_argument('--repo-path', default='.', help='Path to git repository')
    parser.add_argument('--config-check', action='store_true', help='Check configuration')
    args = parser.parse_args()
    
    if args.config_check:
        print("Configuration Check:")
        print(f"  Anthropic API Key: {'✓' if os.getenv('ANTHROPIC_API_KEY') else '✗'}")
        print(f"  Email configured: {'✓' if os.getenv('EMAIL_ADDRESS') else '✗'}")
        print(f"  Notifications enabled: {os.getenv('ENABLE_NOTIFICATIONS', 'true')}")
        print(f"  Vulnerability threshold: {os.getenv('VULNERABILITY_THRESHOLD', 'high')}")
        return
    
    scanner = SecurityScanner(args.repo_path)
    results = scanner.scan_commit()
    
    print(json.dumps(results, indent=2))
    
    # Exit with error code if vulnerabilities found above threshold
    summary = results.get("summary")
    if not summary:
        # If no summary (e.g., no files to scan), exit successfully
        sys.exit(0)
        
    threshold = os.getenv('VULNERABILITY_THRESHOLD', 'high')
    
    if threshold == "critical" and summary["critical_issues"] > 0:
        sys.exit(1)
    elif threshold == "high" and (summary["critical_issues"] > 0 or summary["high_issues"] > 0):
        sys.exit(1)
    elif threshold == "medium" and (summary["critical_issues"] > 0 or summary["high_issues"] > 0 or summary["medium_issues"] > 0):
        sys.exit(1)
    elif threshold == "low" and len(results.get("vulnerabilities", [])) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
