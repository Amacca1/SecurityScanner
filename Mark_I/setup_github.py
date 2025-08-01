#!/usr/bin/env python3
"""
Setup script for GitHub webhook integration
This script helps configure your MCP server to monitor all repositories in the amacca1 account
"""

import os
import secrets
import json

def generate_webhook_secret():
    """Generate a secure webhook secret"""
    return secrets.token_urlsafe(32)

def create_env_file():
    """Create .env file with necessary environment variables"""
    webhook_secret = generate_webhook_secret()
    
    env_content = f"""# GitHub configuration for MCP Security Scanner
# Set your GitHub personal access token here
GITHUB_TOKEN=your_github_token_here

# Webhook secret (generated automatically)
WEBHOOK_SECRET={webhook_secret}

# Instructions:
# 1. Go to https://github.com/settings/tokens
# 2. Create a new token with 'repo' scope
# 3. Replace 'your_github_token_here' with your actual token
# 4. Use the WEBHOOK_SECRET above when setting up GitHub webhooks
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("✅ Created .env file with webhook secret")
    print(f"🔑 Your webhook secret: {webhook_secret}")
    return webhook_secret

def print_webhook_setup_instructions(webhook_secret):
    """Print instructions for setting up GitHub webhooks"""
    print("\n" + "="*60)
    print("GITHUB WEBHOOK SETUP INSTRUCTIONS")
    print("="*60)
    print()
    print("To monitor ALL repositories in the amacca1 account:")
    print()
    print("1. Go to GitHub Organization Settings:")
    print("   https://github.com/orgs/amacca1/settings/hooks")
    print("   (Or for personal account: https://github.com/settings/hooks)")
    print()
    print("2. Click 'Add webhook'")
    print()
    print("3. Configure the webhook:")
    print(f"   Payload URL: http://your-server.com:5001/webhook/github")
    print("   Content type: application/json")
    print(f"   Secret: {webhook_secret}")
    print("   Events: Just the push event")
    print()
    print("4. For local testing, use ngrok to expose your server:")
    print("   brew install ngrok")
    print("   ngrok http 5001")
    print("   Use the ngrok URL in the webhook configuration")
    print()
    print("5. Set your GitHub token in .env file")
    print()
    print("ALTERNATIVE: Set up webhooks for individual repositories:")
    print("Go to each repo settings > Webhooks > Add webhook")
    print("Use the same configuration as above")
    print()

def main():
    print("🚀 Setting up GitHub webhook integration for MCP Security Scanner")
    print()
    
    # Check if .env already exists
    if os.path.exists('.env'):
        print("⚠️  .env file already exists")
        try:
            # SECURITY NOTE: input() usage here is intentional and safe - this is an interactive setup script
            response = input("Do you want to regenerate it? (y/N): ").strip().lower()
            if response not in ['y', 'yes']:
                print("Setup cancelled")
                return
        except (EOFError, KeyboardInterrupt):
            print("\nSetup cancelled")
            return
    
    # Generate webhook secret and create .env
    webhook_secret = create_env_file()
    
    # Print setup instructions
    print_webhook_setup_instructions(webhook_secret)
    
    print("\n✅ Setup complete!")
    print("🔧 Next steps:")
    print("   1. Edit .env file and add your GitHub token")
    print("   2. Set up GitHub webhooks using the instructions above")
    print("   3. Start your MCP server: python3 mcp_server.py")
    print("   4. Test with a commit to any amacca1 repository")

if __name__ == '__main__':
    main()
