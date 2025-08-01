# Security Scanner Mark II

A comprehensive pre-commit security scanner that uses Claude AI to analyze code for vulnerabilities and automatically sends Mac notifications and email alerts for high-severity issues.

## 🚀 Features

- **AI-Powered Analysis**: Uses Claude AI to perform deep security analysis of code
- **Git Integration**: Automatically scans staged files before commits
- **Mac Notifications**: Sends native macOS notifications for critical issues
- **Email Alerts**: Detailed email reports with vulnerability descriptions and recommendations
- **Multi-Language Support**: Scans Python, JavaScript, TypeScript, PHP, Java, C/C++, and more
- **Configurable Thresholds**: Set custom vulnerability severity thresholds
- **Pre-commit Hooks**: Automatically blocks commits with high-severity vulnerabilities
- **Comprehensive Reports**: Detailed JSON reports with line-by-line analysis

## 📋 Requirements

- Python 3.7+
- Git repository
- Anthropic API key (for Claude AI)
- macOS (for notifications)

## 🛠️ Installation

1. **Clone or download the scanner:**
   ```bash
   cd /Users/alexmccarthy/SecurityScanner/Mark_II
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the setup script:**
   ```bash
   python3 setup.py
   ```

4. **Configure your environment:**
   - Get an Anthropic API key from: https://console.anthropic.com/
   - Set up email credentials (Gmail app password recommended)
   - Choose your vulnerability threshold

## ⚙️ Configuration

The scanner is configured via the `.env` file:

```bash
# Claude API Configuration
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Email Configuration  
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
EMAIL_ADDRESS=your_email@gmail.com
EMAIL_PASSWORD=your_app_password_here

# Scanner Configuration
VULNERABILITY_THRESHOLD=high
ENABLE_NOTIFICATIONS=true
ENABLE_EMAIL_ALERTS=true
LOG_LEVEL=INFO
```

### Vulnerability Thresholds

- **critical**: Only alert on critical vulnerabilities
- **high**: Alert on critical and high vulnerabilities (default)
- **medium**: Alert on critical, high, and medium vulnerabilities
- **low**: Alert on all vulnerabilities

## 🔧 Usage

### Manual Scanning

Scan staged files in the current repository:
```bash
python3 security_scanner.py
```

Scan a specific repository:
```bash
python3 security_scanner.py --repo-path /path/to/repo
```

Check configuration:
```bash
python3 security_scanner.py --config-check
```

### Git Integration

The scanner automatically integrates with git via pre-commit hooks:

1. **Install hooks for current repository:**
   ```bash
   python3 install_hooks.py --local
   ```

2. **Install hooks globally for all repositories:**
   ```bash
   python3 install_hooks.py --global
   ```

3. **Normal git workflow:**
   ```bash
   git add file.py
   git commit -m "Add new feature"
   # Scanner automatically runs and blocks commit if vulnerabilities found
   ```

### Bypassing the Scanner (Not Recommended)

If you need to commit despite vulnerabilities:
```bash
git commit --no-verify -m "Emergency fix"
```

## 📊 Output

### Console Output
```json
{
  "timestamp": "2025-01-08T10:30:00",
  "summary": {
    "total_files": 3,
    "vulnerable_files": 1,
    "critical_issues": 0,
    "high_issues": 2,
    "medium_issues": 1,
    "low_issues": 0
  },
  "vulnerabilities": [...]
}
```

### Mac Notifications
- **Critical**: 🚨 CRITICAL Security Issues Found!
- **High**: ⚠️ High Security Issues Found
- **Medium/Low**: ⚠️ Security Issues Found

### Email Reports
Detailed HTML reports including:
- Vulnerability descriptions
- Line numbers and code snippets
- Impact assessment
- Specific fix recommendations

## 🔍 Supported File Types

The scanner analyzes files with these extensions:
- **Python**: `.py`
- **JavaScript/TypeScript**: `.js`, `.ts`
- **Web**: `.html`, `.php`, `.jsp`
- **Compiled**: `.java`, `.cpp`, `.c`, `.cs`
- **Other**: `.rb`, `.go`, `.rs`, `.swift`, `.kt`, `.scala`
- **Scripts**: `.sh`, `.bash`
- **Config**: `.yaml`, `.yml`, `.json`, `.xml`, `.sql`

## 🛡️ Security Checks

The scanner detects:

### Critical Vulnerabilities
- API keys and tokens in code
- Hard-coded passwords and secrets
- Unsafe deserialization (pickle, YAML)
- SQL injection patterns
- Command injection vulnerabilities

### High Vulnerabilities
- Use of `eval()` and `exec()`
- OS command execution
- Shell injection risks
- Unsafe file operations

### Medium/Low Vulnerabilities
- Input validation issues
- Deprecated functions
- Weak cryptographic practices
- Information disclosure risks

## 📁 File Structure

```
Mark_II/
├── security_scanner.py      # Main scanner application
├── install_hooks.py         # Git hooks installer
├── setup.py                 # Setup and configuration script
├── requirements.txt         # Python dependencies
├── .env                     # Environment configuration
├── .gitignore              # Git ignore rules
└── README.md               # This file

Generated files:
├── security_scanner.log     # Scanner log file
├── security_scan_results.json  # Detailed scan results
└── test_vulnerabilities/    # Test files (created by setup.py)
```

## 🧪 Testing

The setup script creates test files with known vulnerabilities:

```bash
python3 setup.py
```

This creates:
- `test_vulnerabilities/vulnerable_test.py`
- `test_vulnerabilities/vulnerable_test.js`

Test the scanner manually:
```bash
cd test_vulnerabilities
git add .
python3 ../security_scanner.py
```

## 🚨 Troubleshooting

### Common Issues

1. **"ANTHROPIC_API_KEY not set"**
   - Add your Claude API key to `.env`
   - Get one from: https://console.anthropic.com/

2. **Email alerts not working**
   - Use Gmail app passwords, not your regular password
   - Enable 2-factor authentication first
   - Check SMTP settings

3. **Mac notifications not showing**
   - Grant notification permissions to Terminal/VS Code
   - Check System Preferences > Notifications

4. **Scanner not blocking commits**
   - Ensure hooks are installed: `python3 install_hooks.py --local`
   - Check hook file permissions: `ls -la .git/hooks/pre-commit`

5. **False positives**
   - Adjust `VULNERABILITY_THRESHOLD` in `.env`
   - Review scanner patterns in the code

### Debug Mode

Enable debug logging:
```bash
# In .env file
LOG_LEVEL=DEBUG
```

Check logs:
```bash
tail -f security_scanner.log
```

## 🔄 Updates

To update the scanner:
1. Back up your `.env` file
2. Download the latest version
3. Restore your `.env` file
4. Run `python3 setup.py` if needed

## 📝 Contributing

To add new vulnerability patterns:
1. Edit the `ClaudeSecurityAnalyzer` class
2. Update the prompt for new vulnerability types
3. Test with example vulnerable code

## 📄 License

This project is intended for educational and security research purposes. Use responsibly and in accordance with your organization's security policies.

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section
2. Review the log files
3. Test with the provided vulnerable files
4. Verify your API keys and configuration

## 🎯 Next Steps

After installation:
1. ✅ Test with vulnerable files
2. ✅ Verify notifications work
3. ✅ Install git hooks
4. ✅ Configure team repositories
5. ✅ Set up CI/CD integration (optional)

---

**⚠️ Security Notice**: This scanner is a tool to help identify potential vulnerabilities. It should not be the only security measure in your development process. Always follow security best practices and conduct thorough security reviews.
