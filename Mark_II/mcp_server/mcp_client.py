#!/usr/bin/env python3
"""
MCP Client for Security Notifications
Integrates with the security scanner to send intelligent notifications
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-client")

class SecurityNotificationClient:
    def __init__(self, mcp_server_path: str):
        self.mcp_server_path = mcp_server_path
    
    async def send_security_alert(self, scan_results_file: str, include_fix_suggestions: bool = True) -> bool:
        """Send security alert using MCP server"""
        try:
            # Validate and sanitize the file path first
            from pathlib import Path
            scan_path = Path(scan_results_file).resolve()
            if not scan_path.exists() or not scan_path.is_file():
                logger.error(f"Invalid scan results file: {scan_results_file}")
                return False
            
            # Ensure the file is within allowed directory
            working_dir = Path.cwd().resolve()
            if not str(scan_path).startswith(str(working_dir)):
                logger.error(f"Scan results file outside working directory: {scan_results_file}")
                return False
            
            # Simplified approach - direct import without MCP framework dependency
            import sys
            import os
            sys.path.append(os.path.dirname(__file__))
            
            # Try to import the notification MCP, but handle missing dependencies gracefully
            try:
                from security_notification_server import SecurityNotificationMCP
            except ImportError as e:
                logger.warning(f"MCP dependencies not available: {e}")
                return self._send_fallback_notifications(str(scan_path))
            
            # Create MCP instance and send notifications
            mcp = SecurityNotificationMCP()
            
            # Load scan results with validation
            if scan_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                logger.error("Scan results file too large")
                return False
            
            with open(scan_path, 'r') as f:
                scan_results = json.load(f)
            
            # Validate JSON structure
            if not isinstance(scan_results, dict):
                logger.error("Invalid scan results format")
                return False
            
            vulnerabilities = scan_results.get('vulnerabilities', [])
            summary = scan_results.get('summary', {})
            
            # Generate fix suggestions if requested
            fix_suggestions = {}
            if include_fix_suggestions and vulnerabilities:
                fix_suggestions = await mcp.generate_fix_suggestions(vulnerabilities)
            
            # Send notifications
            critical_count = summary.get('critical_issues', 0)
            high_count = summary.get('high_issues', 0)
            
            if critical_count > 0 or high_count > 0:
                # Send Mac notification
                title = "Security Vulnerabilities Detected"
                message = f"Found {critical_count} critical and {high_count} high severity issues"
                await mcp.send_mac_notification(title, message, critical_count, high_count)
                
                # Send email with fix suggestions
                await mcp.send_email_alert(scan_results, fix_suggestions)
                
                logger.info(f"Security alerts sent successfully. {critical_count} critical, {high_count} high severity issues found.")
                return True
            else:
                logger.info("No high or critical vulnerabilities found. No alerts sent.")
                return True
                
        except Exception as e:
            logger.error(f"Failed to send security alert via MCP: {e}")
            return False
    
    async def _send_message(self, process, message: Dict[str, Any]):
        """Send a JSON-RPC message to the MCP server"""
        message_str = json.dumps(message) + "\n"
        process.stdin.write(message_str.encode())
        await process.stdin.drain()
    
    async def _read_message(self, process) -> Optional[Dict[str, Any]]:
        """Read a JSON-RPC response from the MCP server"""
        try:
            line = await process.stdout.readline()
            if line:
                return json.loads(line.decode().strip())
            return None
        except Exception as e:
            logger.error(f"Failed to read MCP response: {e}")
            return None

    def _send_fallback_notifications(self, scan_results_file: str) -> bool:
        """Fallback notification method when MCP dependencies are not available"""
        try:
            import subprocess
            import json
            import shlex
            from pathlib import Path
            
            # Validate and sanitize the file path
            scan_path = Path(scan_results_file).resolve()
            if not scan_path.exists() or not scan_path.is_file():
                logger.error(f"Invalid scan results file: {scan_results_file}")
                return False
            
            # Ensure the file is within allowed directory (current working directory)
            working_dir = Path.cwd().resolve()
            if not str(scan_path).startswith(str(working_dir)):
                logger.error(f"Scan results file outside working directory: {scan_results_file}")
                return False
            
            # Load scan results with secure validation
            try:
                scan_results = self._load_json_safely(scan_path)
            except Exception as e:
                logger.error(f"Failed to load scan results: {e}")
                return False
            
            # Validate JSON structure
            if not isinstance(scan_results, dict) or 'summary' not in scan_results:
                logger.error("Invalid scan results format")
                return False
            
            summary = scan_results.get('summary', {})
            critical_count = summary.get('critical_issues', 0)
            high_count = summary.get('high_issues', 0)
            
            # Validate counts are reasonable integers
            try:
                critical_count = max(0, min(int(critical_count), 9999))
                high_count = max(0, min(int(high_count), 9999))
            except (ValueError, TypeError):
                logger.error("Invalid vulnerability counts in scan results")
                return False
            
            if critical_count > 0 or high_count > 0:
                # Send notification using secure method
                title = "Security Vulnerabilities Detected"
                message = f"Found {critical_count} critical and {high_count} high severity issues"
                
                return self._send_secure_notification(title, message)
            else:
                logger.info("No high or critical vulnerabilities found. No alerts sent.")
                return True
                
        except Exception as e:
            logger.error(f"Fallback notification failed: {e}")
            return False

    def _load_json_safely(self, file_path: Path) -> Dict[str, Any]:
        """Load JSON file with security validation"""
        # Check file size (limit to 10MB to prevent DoS)
        file_size = file_path.stat().st_size
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            raise ValueError(f"File too large: {file_size} bytes (max 10MB)")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read with size limit
                content = f.read(10 * 1024 * 1024)  # 10MB max
                
                # Parse JSON
                data = json.loads(content)
                
                if not isinstance(data, dict):
                    raise ValueError("JSON must be an object")
                
                return data
                
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid encoding: {e}")
    
    def _send_secure_notification(self, title: str, message: str) -> bool:
        """Send notification using secure method without shell injection"""
        import re
        
        # Sanitize title and message - only allow safe characters
        sanitized_title = re.sub(r'[^\w\s\-:.]', '', title)[:100]
        sanitized_message = re.sub(r'[^\w\s\-:.,!?()]', '', message)[:200]
        
        # Validate sanitized content
        if not sanitized_title or not sanitized_message:
            logger.error("Notification content is empty after sanitization")
            return False
        
        try:
            # Try using plyer first (safer cross-platform approach)
            try:
                from plyer import notification
                notification.notify(
                    title=sanitized_title,
                    message=sanitized_message,
                    timeout=10
                )
                logger.info("Notification sent successfully via plyer")
                return True
            except ImportError:
                logger.info("Plyer not available, using osascript fallback")
            
            # Fallback to osascript with very strict validation
            # Only proceed if content passes strict regex check
            if not re.match(r'^[\w\s\-:.]+$', sanitized_title) or not re.match(r'^[\w\s\-:.,!?()]+$', sanitized_message):
                logger.error("Content failed strict validation for osascript")
                return False
            
            # Use subprocess with list arguments (no shell interpretation)
            subprocess.run([
                'osascript', '-e',
                f'display notification "{sanitized_message}" with title "{sanitized_title}"'
            ], check=True, timeout=10, capture_output=True)
            
            logger.info("Fallback Mac notification sent successfully")
            return True
            
        except Exception as e:
            logger.warning(f"Notification failed: {e}")
            return False

async def main():
    """Main function for testing the MCP client"""
    if len(sys.argv) < 2:
        print("Usage: python3 mcp_client.py <scan_results_file>")
        sys.exit(1)
    
    scan_results_file = sys.argv[1]
    
    # Path to MCP server
    current_dir = Path(__file__).parent
    mcp_server_path = current_dir / "security_notification_server.py"
    
    # Create client and send alert
    client = SecurityNotificationClient(str(mcp_server_path))
    success = await client.send_security_alert(scan_results_file)
    
    if success:
        print("✅ Security alert sent successfully")
        sys.exit(0)
    else:
        print("❌ Failed to send security alert")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
