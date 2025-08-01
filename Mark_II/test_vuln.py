#!/usr/bin/env python3
# Test vulnerable code to trigger scanner

import os
import subprocess

def vulnerable_function():
    # SQL injection vulnerability
    user_input = input("Enter username: ")
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    
    # Command injection vulnerability
    command = f"ls {user_input}"
    os.system(command)
    
    # Hardcoded secret
    api_key = "sk-1234567890abcdef"
    
    return query
