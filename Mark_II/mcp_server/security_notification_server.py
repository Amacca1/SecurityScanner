#!/usr/bin/env python3
"""
Security Scanner MCP Server
Provides intelligent notifications and AI-powered fix suggestions for security vulnerabilities
"""

import json
import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional
from pathlib import Path
import os
from datetime import datetime

import mcp.types as types
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
from anthropic import Anthropic

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security-notification-server")

def load_scan_results_safely(scan_results_file: str) -> Dict[str, Any]:
    """Load scan results with security validation and size limits"""
    import os
    from pathlib import Path
    
    # Validate file path
    file_path = Path(scan_results_file).resolve()
    if not file_path.exists():
        raise FileNotFoundError(f"Scan results file not found: {scan_results_file}")
    
    # Check file size (limit to 10MB to prevent DoS)
    file_size = file_path.stat().st_size
    if file_size > 10 * 1024 * 1024:  # 10MB limit
        raise ValueError(f"Scan results file too large: {file_size} bytes (max 10MB)")
    
    # Load JSON with security considerations
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Read file content with size limit
            content = f.read(10 * 1024 * 1024)  # 10MB max
            
            # Parse JSON with error handling
            scan_results = json.loads(content)
            
            # Validate basic structure
            if not isinstance(scan_results, dict):
                raise ValueError("Scan results must be a JSON object")
            
            # Validate required fields
            required_fields = ['timestamp', 'scanned_files', 'vulnerabilities', 'summary']
            for field in required_fields:
                if field not in scan_results:
                    logger.warning(f"Missing field in scan results: {field}")
                    scan_results[field] = [] if field in ['scanned_files', 'vulnerabilities'] else {}
            
            # Validate vulnerabilities structure
            vulnerabilities = scan_results.get('vulnerabilities', [])
            if not isinstance(vulnerabilities, list):
                logger.warning("Vulnerabilities field is not a list, resetting to empty list")
                scan_results['vulnerabilities'] = []
            
            # Sanitize vulnerability data
            sanitized_vulns = []
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    # Sanitize strings in vulnerability data
                    sanitized_vuln = {}
                    for key, value in vuln.items():
                        if isinstance(value, str):
                            # Remove potential malicious content
                            sanitized_vuln[key] = value.replace('\x00', '').strip()[:1000]  # Max 1000 chars per field
                        elif isinstance(value, (int, float, bool)):
                            sanitized_vuln[key] = value
                        else:
                            sanitized_vuln[key] = str(value)[:1000]
                    sanitized_vulns.append(sanitized_vuln)
            
            scan_results['vulnerabilities'] = sanitized_vulns
            return scan_results
            
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in scan results file: {e}")
    except UnicodeDecodeError as e:
        raise ValueError(f"Invalid encoding in scan results file: {e}")
    except Exception as e:
        raise ValueError(f"Failed to load scan results: {e}")

class SecurityNotificationMCP:
    def __init__(self):
        self.anthropic_client = None
        self.smtp_config = {}
        self.notification_config = {}
        self.load_config()
    
    def load_config(self):
        """Load configuration from environment variables"""
        # Load environment from .env file if it exists
        env_file = Path(__file__).parent.parent / '.env'
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key] = value
        
        # Initialize Anthropic client
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if api_key and api_key != 'your_anthropic_api_key_here':
            self.anthropic_client = Anthropic(api_key=api_key)
        
        # SMTP configuration
        self.smtp_config = {
            'server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'port': int(os.getenv('SMTP_PORT', '587')),
            'email': os.getenv('EMAIL_ADDRESS', ''),
            'password': os.getenv('EMAIL_PASSWORD', ''),
            'enabled': os.getenv('ENABLE_EMAIL_ALERTS', 'true').lower() == 'true'
        }
        
        # Notification configuration
        self.notification_config = {
            'mac_notifications': os.getenv('ENABLE_NOTIFICATIONS', 'true').lower() == 'true',
            'threshold': os.getenv('VULNERABILITY_THRESHOLD', 'high'),
        }
    
    async def generate_fix_suggestions(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate AI-powered fix suggestions for vulnerabilities"""
        if not self.anthropic_client:
            logger.warning("Anthropic client not configured, skipping AI suggestions")
            return {}
        
        fix_suggestions = {}
        
        for vuln in vulnerabilities:
            if vuln.get('severity') in ['critical', 'high']:
                try:
                    # Create a detailed prompt for fix suggestions
                    prompt = f"""
You are a cybersecurity expert. Analyze this security vulnerability and provide specific, actionable fix suggestions.

File: {vuln.get('file', 'unknown')}
Vulnerability Type: {vuln.get('type', 'unknown')}
Severity: {vuln.get('severity', 'unknown')}
Description: {vuln.get('description', 'No description')}
Code Context: {vuln.get('context', 'No context available')}

Please provide:
1. A clear explanation of why this is a security risk
2. Specific code changes needed to fix the vulnerability
3. Best practices to prevent similar issues
4. Any relevant security tools or libraries that could help

Keep the response practical and actionable for a developer.
"""
                    
                    response = await asyncio.to_thread(
                        self.anthropic_client.messages.create,
                        model="claude-3-haiku-20240307",
                        max_tokens=1000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    
                    fix_suggestions[f"{vuln.get('file', 'unknown')}:{vuln.get('line', 0)}"] = response.content[0].text
                    
                except Exception as e:
                    logger.error(f"Failed to generate fix suggestion: {e}")
                    fix_suggestions[f"{vuln.get('file', 'unknown')}:{vuln.get('line', 0)}"] = "AI suggestion generation failed. Please review manually."
        
        return fix_suggestions
    
    async def send_mac_notification(self, title: str, message: str, critical_count: int = 0, high_count: int = 0):
        """Send Mac notification using secure native Python notification library"""
        if not self.notification_config['mac_notifications']:
            return
            
        try:
            # Truncate and sanitize title
            severity_icon = "⚠️" if critical_count > 0 else "🔍"
            full_title = f"{severity_icon} {title}"
            if len(full_title) > 50:
                full_title = full_title[:47] + "..."
            
            # Sanitize title - remove all non-alphanumeric except spaces, dashes, colons
            import re
            sanitized_title = re.sub(r'[^\w\s\-:.]', '', full_title)
            
            # Truncate and sanitize message
            short_message = message[:100] + "..." if len(message) > 100 else message
            sanitized_message = re.sub(r'[^\w\s\-:.,!?()]', '', short_message)
            
            # Try using plyer first (cross-platform and safer)
            try:
                from plyer import notification
                notification.notify(
                    title=sanitized_title,
                    message=sanitized_message,
                    timeout=10
                )
                logger.info("Mac notification sent successfully via plyer")
                return
            except Exception as plyer_error:
                logger.warning(f"Plyer notification failed: {plyer_error}")
            
            # Fallback to osascript with strict input validation
            # Additional validation: only allow safe characters  
            if not re.match(r'^[\w\s\-:.,!?()⚠️🔍]+$', sanitized_title) or not re.match(r'^[\w\s\-:.,!?()]+$', sanitized_message):
                logger.error("Notification content contains unsafe characters, skipping")
                return
                
            import subprocess
            # Use safer approach with list arguments (no shell interpretation)
            subprocess.run([
                'osascript', '-e',
                f'display notification "{sanitized_message}" with title "{sanitized_title}"'
            ], check=True, timeout=10, capture_output=True)
            
            logger.info("Mac notification sent successfully via osascript")
            
        except Exception as e:
            logger.error(f"Failed to send Mac notification: {e}")
    
    async def send_email_alert(self, scan_results: Dict[str, Any], fix_suggestions: Dict[str, str]):
        """Send detailed email alert with fix suggestions"""
        if not self.smtp_config['enabled'] or not self.smtp_config['email']:
            logger.info("Email alerts disabled or not configured")
            return
        
        try:
            # Create email content
            summary = scan_results.get('summary', {})
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            subject = f"🚨 Security Vulnerabilities Detected - {summary.get('critical_issues', 0)} Critical, {summary.get('high_issues', 0)} High"
            
            # HTML email template
            html_content = self._create_email_html(scan_results, fix_suggestions)
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.smtp_config['email']
            msg['To'] = self.smtp_config['email']
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email using secure SMTP
            await asyncio.to_thread(self._send_smtp_email, msg)
            
            logger.info("Security alert email sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def _send_smtp_email(self, msg):
        """Send email via secure SMTP (synchronous) - requires SSL/TLS"""
        import ssl
        
        # Create strict secure SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        # Disable weak protocols
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Only use secure SMTP_SSL connection (no fallback)
        if self.smtp_config['port'] == 465:
            # Use SMTP_SSL for port 465
            with smtplib.SMTP_SSL(self.smtp_config['server'], 465, context=context) as server:
                server.login(self.smtp_config['email'], self.smtp_config['password'])
                server.send_message(msg)
        elif self.smtp_config['port'] == 587:
            # Use STARTTLS for port 587 with mandatory encryption
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls(context=context)  # Use secure context
                server.login(self.smtp_config['email'], self.smtp_config['password'])
                server.send_message(msg)
        else:
            raise ValueError(f"Unsupported SMTP port {self.smtp_config['port']}. Only ports 465 (SSL) and 587 (STARTTLS) are allowed for security.")
    
    def _create_email_html(self, scan_results: Dict[str, Any], fix_suggestions: Dict[str, str]) -> str:
        """Create HTML email content with fix suggestions"""
        summary = scan_results.get('summary', {})
        vulnerabilities = scan_results.get('vulnerabilities', [])
        timestamp = scan_results.get('timestamp', datetime.now().isoformat())
        
        # Filter high/critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
        .header {{ background: #d32f2f; color: white; padding: 20px; border-radius: 8px; }}
        .summary {{ background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 8px; }}
        .vulnerability {{ background: #ffebee; border-left: 4px solid #d32f2f; margin: 15px 0; padding: 15px; }}
        .critical {{ border-left-color: #b71c1c; background: #ffebee; }}
        .high {{ border-left-color: #f57c00; background: #fff3e0; }}
        .fix-suggestion {{ background: #e8f5e8; border: 1px solid #4caf50; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .code {{ background: #f5f5f5; padding: 10px; font-family: monospace; border-radius: 4px; overflow-x: auto; }}
        .severity {{ font-weight: bold; padding: 4px 8px; border-radius: 4px; color: white; }}
        .severity.critical {{ background: #b71c1c; }}
        .severity.high {{ background: #f57c00; }}
        h1, h2, h3 {{ color: #d32f2f; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Security Scanner Alert</h1>
        <p>High-severity vulnerabilities detected in your code</p>
        <p><strong>Scan Time:</strong> {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <ul>
            <li><strong>Total Files Scanned:</strong> {summary.get('total_files', 0)}</li>
            <li><strong>Vulnerable Files:</strong> {summary.get('vulnerable_files', 0)}</li>
            <li><strong>Critical Issues:</strong> {summary.get('critical_issues', 0)}</li>
            <li><strong>High Issues:</strong> {summary.get('high_issues', 0)}</li>
            <li><strong>Medium Issues:</strong> {summary.get('medium_issues', 0)}</li>
            <li><strong>Low Issues:</strong> {summary.get('low_issues', 0)}</li>
        </ul>
    </div>
"""
        
        # Add critical vulnerabilities
        if critical_vulns:
            html += "<h2>🔴 Critical Vulnerabilities</h2>"
            for vuln in critical_vulns:
                html += self._create_vulnerability_html(vuln, fix_suggestions, 'critical')
        
        # Add high vulnerabilities
        if high_vulns:
            html += "<h2>🟠 High Vulnerabilities</h2>"
            for vuln in high_vulns:
                html += self._create_vulnerability_html(vuln, fix_suggestions, 'high')
        
        html += """
    <div style="margin-top: 30px; padding: 20px; background: #e3f2fd; border-radius: 8px;">
        <h3>🛡️ Next Steps</h3>
        <ol>
            <li>Review each vulnerability and its fix suggestion</li>
            <li>Implement the recommended changes</li>
            <li>Test your code thoroughly after applying fixes</li>
            <li>Consider adding security linting to your CI/CD pipeline</li>
            <li>Regular security audits are recommended</li>
        </ol>
    </div>
    
    <div style="margin-top: 20px; padding: 15px; background: #f9f9f9; border-radius: 8px;">
        <p><small>This alert was generated by Security Scanner Mark II. 
        For questions or support, review the scanner documentation.</small></p>
    </div>
</body>
</html>
"""
        return html
    
    def _create_vulnerability_html(self, vuln: Dict[str, Any], fix_suggestions: Dict[str, str], severity: str) -> str:
        """Create HTML for a single vulnerability"""
        file_name = vuln.get('file', 'unknown')
        line_num = vuln.get('line', 0)
        vuln_key = f"{file_name}:{line_num}"
        fix_suggestion = fix_suggestions.get(vuln_key, "No AI suggestion available")
        
        return f"""
    <div class="vulnerability {severity}">
        <h3>{vuln.get('type', 'Unknown Vulnerability')} 
            <span class="severity {severity}">{severity.upper()}</span>
        </h3>
        <p><strong>File:</strong> {file_name} (Line {line_num})</p>
        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
        
        {f'<div class="code"><strong>Code Context:</strong><br><pre>{vuln.get("context", "No context available")}</pre></div>' if vuln.get('context') else ''}
        
        <div class="fix-suggestion">
            <h4>🔧 AI-Generated Fix Suggestion</h4>
            <div style="white-space: pre-wrap;">{fix_suggestion}</div>
        </div>
    </div>
"""

    def _load_scan_results_safely(self, scan_results_file: str) -> Dict[str, Any]:
        """Load scan results with security validation and size limits"""
        import os
        from pathlib import Path
        
        # Validate file path
        file_path = Path(scan_results_file).resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"Scan results file not found: {scan_results_file}")
        
        # Check file size (limit to 10MB to prevent DoS)
        file_size = file_path.stat().st_size
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            raise ValueError(f"Scan results file too large: {file_size} bytes (max 10MB)")
        
        # Load JSON with security considerations
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read file content with size limit
                content = f.read(10 * 1024 * 1024)  # 10MB max
                
                # Parse JSON with error handling
                scan_results = json.loads(content)
                
                # Validate basic structure
                if not isinstance(scan_results, dict):
                    raise ValueError("Scan results must be a JSON object")
                
                # Validate required fields
                required_fields = ['timestamp', 'scanned_files', 'vulnerabilities', 'summary']
                for field in required_fields:
                    if field not in scan_results:
                        logger.warning(f"Missing field in scan results: {field}")
                        scan_results[field] = [] if field in ['scanned_files', 'vulnerabilities'] else {}
                
                # Validate vulnerabilities structure
                vulnerabilities = scan_results.get('vulnerabilities', [])
                if not isinstance(vulnerabilities, list):
                    logger.warning("Vulnerabilities field is not a list, resetting to empty list")
                    scan_results['vulnerabilities'] = []
                
                # Sanitize vulnerability data
                sanitized_vulns = []
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        # Sanitize strings in vulnerability data
                        sanitized_vuln = {}
                        for key, value in vuln.items():
                            if isinstance(value, str):
                                # Remove potential malicious content
                                sanitized_vuln[key] = value.replace('\x00', '').strip()[:1000]  # Max 1000 chars per field
                            elif isinstance(value, (int, float, bool)):
                                sanitized_vuln[key] = value
                            else:
                                sanitized_vuln[key] = str(value)[:1000]
                        sanitized_vulns.append(sanitized_vuln)
                
                scan_results['vulnerabilities'] = sanitized_vulns
                return scan_results
                
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in scan results file: {e}")
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid encoding in scan results file: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load scan results: {e}")

# Initialize MCP server
server = Server("security-notification-server")
notification_mcp = SecurityNotificationMCP()

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools"""
    return [
        types.Tool(
            name="send_security_alert",
            description="Send security alert notifications with AI-powered fix suggestions",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_results_file": {
                        "type": "string",
                        "description": "Path to the security scan results JSON file"
                    },
                    "include_fix_suggestions": {
                        "type": "boolean",
                        "description": "Whether to generate AI-powered fix suggestions",
                        "default": True
                    }
                },
                "required": ["scan_results_file"]
            }
        ),
        types.Tool(
            name="send_mac_notification",
            description="Send a Mac notification",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Notification title"
                    },
                    "message": {
                        "type": "string",
                        "description": "Notification message"
                    },
                    "critical_count": {
                        "type": "integer",
                        "description": "Number of critical vulnerabilities",
                        "default": 0
                    },
                    "high_count": {
                        "type": "integer",
                        "description": "Number of high vulnerabilities",
                        "default": 0
                    }
                },
                "required": ["title", "message"]
            }
        ),
        types.Tool(
            name="generate_fix_suggestions",
            description="Generate AI-powered fix suggestions for vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "vulnerabilities": {
                        "type": "array",
                        "description": "List of vulnerability objects",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "line": {"type": "integer"},
                                "type": {"type": "string"},
                                "severity": {"type": "string"},
                                "description": {"type": "string"},
                                "context": {"type": "string"}
                            }
                        }
                    }
                },
                "required": ["vulnerabilities"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Handle tool calls"""
    try:
        if name == "send_security_alert":
            scan_results_file = arguments["scan_results_file"]
            include_fix_suggestions = arguments.get("include_fix_suggestions", True)
            
            # Load scan results with security validation
            scan_results = load_scan_results_safely(scan_results_file)
            
            vulnerabilities = scan_results.get('vulnerabilities', [])
            summary = scan_results.get('summary', {})
            
            # Generate fix suggestions if requested
            fix_suggestions = {}
            if include_fix_suggestions and vulnerabilities:
                fix_suggestions = await notification_mcp.generate_fix_suggestions(vulnerabilities)
            
            # Send notifications
            critical_count = summary.get('critical_issues', 0)
            high_count = summary.get('high_issues', 0)
            
            if critical_count > 0 or high_count > 0:
                # Send Mac notification
                title = "Security Vulnerabilities Detected"
                message = f"Found {critical_count} critical and {high_count} high severity issues"
                await notification_mcp.send_mac_notification(title, message, critical_count, high_count)
                
                # Send email with fix suggestions
                await notification_mcp.send_email_alert(scan_results, fix_suggestions)
                
                return [types.TextContent(
                    type="text",
                    text=f"Security alerts sent successfully. {critical_count} critical, {high_count} high severity issues found."
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text="No high or critical vulnerabilities found. No alerts sent."
                )]
        
        elif name == "send_mac_notification":
            title = arguments["title"]
            message = arguments["message"]
            critical_count = arguments.get("critical_count", 0)
            high_count = arguments.get("high_count", 0)
            
            await notification_mcp.send_mac_notification(title, message, critical_count, high_count)
            
            return [types.TextContent(
                type="text",
                text="Mac notification sent successfully"
            )]
        
        elif name == "generate_fix_suggestions":
            vulnerabilities = arguments["vulnerabilities"]
            fix_suggestions = await notification_mcp.generate_fix_suggestions(vulnerabilities)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(fix_suggestions, indent=2)
            )]
        
        else:
            raise ValueError(f"Unknown tool: {name}")
    
    except Exception as e:
        logger.error(f"Tool call failed: {e}")
        return [types.TextContent(
            type="text",
            text=f"Error: {str(e)}"
        )]

async def main():
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="security-notification-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities={},
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())
