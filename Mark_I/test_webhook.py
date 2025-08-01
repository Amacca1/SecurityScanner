#!/usr/bin/env python3
"""
Test script to simulate GitHub webhook events locally
"""

import requests
import json
import hashlib
import hmac
import os

# Load environment variables from .env file if it exists
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Load the webhook secret from environment
webhook_secret = os.environ.get('WEBHOOK_SECRET', 'default-test-secret')

def create_test_payload():
    """Create a test GitHub webhook payload"""
    return {
        "repository": {
            "full_name": "amacca1/test-repo"
        },
        "commits": [
            {
                "id": "abc123456",
                "modified": ["test.py"],
                "added": []
            }
        ]
    }

def sign_payload(payload_str, secret):
    """Sign the payload with HMAC SHA256"""
    signature = hmac.new(
        secret.encode('utf-8'),
        payload_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f"sha256={signature}"

def test_webhook():
    """Test the GitHub webhook endpoint"""
    payload = create_test_payload()
    payload_str = json.dumps(payload)
    signature = sign_payload(payload_str, webhook_secret)
    
    headers = {
        'Content-Type': 'application/json',
        'X-GitHub-Event': 'push',
        'X-Hub-Signature-256': signature
    }
    
    try:
        response = requests.post(
            'http://localhost:5001/webhook/github',
            headers=headers,
            data=payload_str
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to MCP server on port 5001")
        print("💡 Make sure to start the server first: python3 mcp_server.py")

if __name__ == '__main__':
    print("🧪 Testing GitHub webhook endpoint...")
    test_webhook()
