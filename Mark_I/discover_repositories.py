#!/usr/bin/env python3
"""
Repository Discovery and Setup Script
Helps configure monitoring for all repositories you manage across GitHub
"""

import os
import requests
import json

def load_env():
    """Load environment variables from .env file"""
    env_vars = {}
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#') and '=' in line:
                    key, value = line.strip().split('=', 1)
                    env_vars[key] = value
    return env_vars

def get_all_user_repositories(token):
    """Get all repositories the user has access to"""
    headers = {'Authorization': f'token {token}'}
    repositories = []
    page = 1
    
    while True:
        response = requests.get(
            'https://api.github.com/user/repos',
            headers=headers,
            params={'per_page': 100, 'page': page}
        )
        
        if response.status_code != 200:
            print(f"Error fetching repositories: {response.status_code}")
            break
        
        repos = response.json()
        if not repos:
            break
            
        repositories.extend(repos)
        page += 1
    
    return repositories

def get_organization_repositories(token, org):
    """Get all repositories from an organization"""
    headers = {'Authorization': f'token {token}'}
    repositories = []
    page = 1
    
    while True:
        response = requests.get(
            f'https://api.github.com/orgs/{org}/repos',
            headers=headers,
            params={'per_page': 100, 'page': page}
        )
        
        if response.status_code != 200:
            print(f"Error fetching org repositories: {response.status_code}")
            break
        
        repos = response.json()
        if not repos:
            break
            
        repositories.extend(repos)
        page += 1
    
    return repositories

def categorize_repositories(repositories):
    """Categorize repositories by access level and ownership"""
    categories = {
        'owned': [],           # You own these
        'admin': [],           # You have admin access
        'maintain': [],        # You have maintain access
        'collaborator': [],    # You're a collaborator
        'organizations': {}    # Grouped by organization
    }
    
    for repo in repositories:
        repo_info = {
            'name': repo['full_name'],
            'private': repo['private'],
            'fork': repo['fork'],
            'permissions': repo.get('permissions', {}),
            'owner_type': repo['owner']['type']
        }
        
        # Categorize by ownership
        if repo['owner']['login'] == repo.get('owner', {}).get('login'):
            if repo_info['permissions'].get('admin', False):
                if repo['owner']['type'] == 'User':
                    categories['owned'].append(repo_info)
                else:
                    org_name = repo['owner']['login']
                    if org_name not in categories['organizations']:
                        categories['organizations'][org_name] = []
                    categories['organizations'][org_name].append(repo_info)
        
        # Categorize by permission level
        permissions = repo_info['permissions']
        if permissions.get('admin', False):
            categories['admin'].append(repo_info)
        elif permissions.get('maintain', False):
            categories['maintain'].append(repo_info)
        elif permissions.get('push', False):
            categories['collaborator'].append(repo_info)
    
    return categories

def print_repository_summary(categories):
    """Print a summary of discovered repositories"""
    print("\n" + "="*60)
    print("REPOSITORY DISCOVERY SUMMARY")
    print("="*60)
    
    print(f"\n📁 Repositories you own: {len(categories['owned'])}")
    for repo in categories['owned'][:5]:  # Show first 5
        print(f"   - {repo['name']} ({'private' if repo['private'] else 'public'})")
    if len(categories['owned']) > 5:
        print(f"   ... and {len(categories['owned']) - 5} more")
    
    print(f"\n🔧 Repositories with admin access: {len(categories['admin'])}")
    for repo in categories['admin'][:5]:
        print(f"   - {repo['name']} ({'private' if repo['private'] else 'public'})")
    if len(categories['admin']) > 5:
        print(f"   ... and {len(categories['admin']) - 5} more")
    
    if categories['organizations']:
        print(f"\n🏢 Organization repositories:")
        for org, repos in categories['organizations'].items():
            print(f"   {org}: {len(repos)} repositories")
    
    print(f"\n🤝 Repositories with maintain access: {len(categories['maintain'])}")
    print(f"👥 Repositories as collaborator: {len(categories['collaborator'])}")

def generate_monitoring_config(categories):
    """Generate monitoring configuration recommendations"""
    print("\n" + "="*60)
    print("MONITORING CONFIGURATION RECOMMENDATIONS")
    print("="*60)
    
    # Get unique users and organizations
    users = set()
    orgs = set()
    
    for repo_list in [categories['owned'], categories['admin'], categories['maintain']]:
        for repo in repo_list:
            owner, _ = repo['name'].split('/', 1)
            if repo['owner_type'] == 'User':
                users.add(owner)
            else:
                orgs.add(owner)
    
    print("\n📋 Recommended .env configuration:")
    print(f"MONITORED_USERS={','.join(users)}")
    if orgs:
        print(f"MONITORED_ORGS={','.join(orgs)}")
    else:
        print("MONITORED_ORGS=")
    
    print("\n🎯 This configuration will monitor:")
    total_monitored = len(categories['owned']) + len(categories['admin'])
    print(f"   - {total_monitored} repositories where you have admin access")
    print(f"   - Across {len(users)} user accounts and {len(orgs)} organizations")
    
    # Show webhook setup options
    print("\n🔗 Webhook setup options:")
    print("1. Organization-wide webhooks (recommended for orgs):")
    for org in orgs:
        print(f"   https://github.com/orgs/{org}/settings/hooks")
    
    print("2. User-level webhooks:")
    for user in users:
        print(f"   https://github.com/settings/hooks")
    
    print("3. Individual repository webhooks (for specific repos)")

def main():
    print("🔍 Discovering all repositories you manage...")
    
    # Load configuration
    env_vars = load_env()
    token = env_vars.get('GITHUB_TOKEN')
    
    if not token:
        print("❌ No GitHub token found in .env file")
        print("💡 Please add your GitHub token to .env file")
        return
    
    # Discover repositories
    print("📡 Fetching repositories from GitHub API...")
    repositories = get_all_user_repositories(token)
    
    if not repositories:
        print("❌ No repositories found or API error")
        return
    
    print(f"✅ Found {len(repositories)} repositories")
    
    # Categorize repositories
    categories = categorize_repositories(repositories)
    
    # Print summary
    print_repository_summary(categories)
    
    # Generate configuration
    generate_monitoring_config(categories)
    
    # Save detailed report
    with open('repository_discovery.json', 'w') as f:
        json.dump(categories, f, indent=2)
    
    print(f"\n💾 Detailed report saved to: repository_discovery.json")
    print("\n✅ Discovery complete!")
    print("🔧 Next steps:")
    print("   1. Update your .env file with the recommended configuration")
    print("   2. Set up webhooks using the provided URLs")
    print("   3. Start the enhanced MCP server: python3 mcp_server_enhanced.py")
    print("   4. Test with: curl http://localhost:5001/repositories")

if __name__ == '__main__':
    main()
