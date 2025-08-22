# 🛡️ API Security Scanner

A comprehensive, automated API security scanner built with Python, featuring OWASP ZAP integration, real-time Slack notifications, and cross-platform compatibility. This tool helps identify vulnerabilities in web APIs and provides detailed security assessments.

![Python](https://img.shields.io/badge/python-v3.13.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![OWASP ZAP](https://img.shields.io/badge/OWASP%20ZAP-Integrated-orange.svg)
![Slack](https://img.shields.io/badge/Slack-Notifications-4A154B.svg)

## 🎯 Features

### 🔍 Security Scanning
- **OWASP ZAP Integration**: Automated vulnerability scanning using industry-standard tools
- **Multiple Scan Types**: Quick scans, full assessments, and ultimate comprehensive reports
- **Vulnerability Triage**: Intelligent filtering and prioritization of security findings
- **Real Vulnerability Testing**: Built-in support for OWASP Juice Shop and VAmPI

### 📊 Reporting & Notifications
- **Slack Integration**: Real-time security alerts sent to your team channels
- **JSON Reports**: Structured vulnerability data for further analysis
- **Executive Summaries**: High-level security assessments for stakeholders
- **Comprehensive Analysis**: Combined results from multiple scan types

### 🚀 Automation & Usability
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Professional CLI**: User-friendly command-line interface with colored output
- **Docker Integration**: Automated setup of vulnerable test environments
- **Background Processing**: Non-blocking scans with progress monitoring

## 📦 Installation

### Prerequisites

- **Python 3.13.6+** (or compatible version)
- **Docker** (for vulnerable API testing)
- **OWASP ZAP** (optional, falls back to direct HTTP testing)
- **Slack Bot Token** (for notifications)

### Quick Setup

1. **Clone the repository:**
```bash
git clone https://github.com/AdityaChaudhari901/API-SECURITY-SCANNER.git
cd API-SECURITY-SCANNER
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your Slack bot token and other settings
```

4. **Set up vulnerable APIs for testing (optional):**
```bash
python3 run.py setup-vulns
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Slack Integration
SLACK_BOT_TOKEN=xoxb-your-bot-token-here
SLACK_CHANNEL=#security-alerts

# OWASP ZAP Configuration
ZAP_PROXY_HOST=127.0.0.1
ZAP_PROXY_PORT=8080
ZAP_API_KEY=your-zap-api-key-here

# Scanner Configuration
TARGET_API_URL=http://localhost:3000
API_NAME=Test API
SCAN_TIMEOUT=300
POLL_INTERVAL=10
REPORTS_DIR=./reports

# Vulnerable API Configuration
JUICE_SHOP_URL=http://localhost:3000
VAMPI_URL=http://localhost:5001
```

### Slack Bot Setup

1. Go to [Slack API Apps](https://api.slack.com/apps)
2. Create a new app or use existing one
3. Navigate to "OAuth & Permissions"
4. Add the following scopes:
   - `chat:write`
   - `files:write`
   - `channels:read`
5. Install the app to your workspace
6. Copy the "Bot User OAuth Token" to your `.env` file

## 🚀 Usage

### Command Line Interface

The scanner provides a comprehensive CLI with multiple scanning modes:

```bash
# Show all available commands
python3 run.py help

# Setup vulnerable APIs for testing
python3 run.py setup-vulns

# Quick security scan
python3 run.py quick-scan <URL> [--timeout 60]

# Enhanced vulnerability testing
python3 run.py test-vulns <URL> [--timeout 120]

# Ultimate comprehensive report with Slack notifications
python3 run.py ultimate-report [--timeout 300]
```

### Scanning Examples

**Quick scan of a web API:**
```bash
python3 run.py quick-scan https://api.example.com
```

**Comprehensive vulnerability assessment:**
```bash
python3 run.py test-vulns https://api.example.com --timeout 180
```

**Ultimate security report with Slack alerts:**
```bash
python3 run.py ultimate-report
```

### Vulnerable API Management

**Setup test environments:**
```bash
python3 setup_vulnerable_apis.py setup
```

**Check status of test APIs:**
```bash
python3 setup_vulnerable_apis.py status
```

**Clean up test containers:**
```bash
python3 setup_vulnerable_apis.py cleanup
```

## 🧪 Testing Environments

The scanner includes built-in support for vulnerable applications:

### OWASP Juice Shop
- **URL**: http://localhost:3000
- **Purpose**: Web application vulnerability testing
- **Features**: XSS, SQL injection, broken authentication, etc.

### VAmPI (Vulnerable API)
- **URL**: http://localhost:5001
- **Purpose**: REST API vulnerability testing
- **Features**: Broken access control, API-specific vulnerabilities

## 📊 Report Types

### 1. Quick Scan Reports
- Basic vulnerability detection
- Fast execution (< 2 minutes)
- JSON format output
- Essential security findings

### 2. Enhanced Vulnerability Reports
- Comprehensive API testing
- Specialized vulnerability checks
- Detailed finding descriptions
- Risk severity ratings

### 3. Ultimate Security Assessments
- Combined scan results
- Executive summaries
- Slack notifications for high-severity findings
- Complete security posture analysis

## 📁 Project Structure

```
API-SECURITY-SCANNER/
├── run.py                        # Main CLI entry point
├── setup_vulnerable_apis.py      # Vulnerable API management
├── ultimate_report_generator.py  # Comprehensive reporting
├── enhanced_vuln_tester.py       # Specialized vulnerability tests
├── core_scripts/                 # Core scanner modules
│   ├── api_security_scanner.py   # Main scanning engine
│   ├── bulk_scanner.py          # Batch scanning capabilities
│   └── quick_scan.py            # Quick scan implementation
├── requirements.txt              # Python dependencies
├── .env.example                 # Configuration template
├── reports/                     # Generated security reports
└── README.md                    # This file
```

## 🔧 Advanced Usage

### Custom Configuration

**Timeout Control:**
```bash
python3 run.py quick-scan https://api.example.com --timeout 120
```

**Background Processing:**
```bash
python3 run.py ultimate-report > scan.log 2>&1 &
```

**Batch Scanning:**
```python
# Use the bulk_scanner module for multiple targets
from core_scripts.bulk_scanner import BulkScanner
scanner = BulkScanner()
scanner.scan_multiple(['url1', 'url2', 'url3'])
```

### Integration with CI/CD

```yaml
# Example GitHub Actions workflow
- name: Run Security Scan
  run: |
    python3 run.py quick-scan ${{ env.API_URL }} --timeout 300
    
- name: Upload Security Report
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: reports/
```

## 📈 Monitoring & Alerting

### Slack Notifications

High-severity vulnerabilities automatically trigger Slack alerts containing:

- **Vulnerability Summary**: Type, severity, and affected endpoints
- **Risk Assessment**: Potential impact and exploitability
- **Remediation Guidance**: Recommended fixes and best practices
- **Report Links**: Direct access to detailed findings

### Log Files

Scanner activities are logged to:
- `reports/scanner.log` - General scanner operations
- `reports/*.json` - Structured vulnerability reports
- Console output with colored status indicators

## 🛠️ Development

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and test thoroughly
4. Commit with descriptive messages
5. Push and create a Pull Request

### Testing

```bash
# Test with vulnerable applications
python3 run.py setup-vulns
python3 run.py test-vulns http://localhost:3000

# Verify Slack integration
python3 run.py ultimate-report
```

### Dependencies

Key Python packages:
- `requests` - HTTP client for API testing
- `slack-sdk` - Slack integration
- `python-zapv2` - OWASP ZAP integration
- `colorama` - Cross-platform colored terminal output
- `python-dotenv` - Environment configuration

## 🚨 Security Considerations

### Sensitive Data Protection
- Never commit `.env` files with real credentials
- Use `.env.example` for configuration templates
- Regularly rotate API keys and tokens

### Network Security
- Scanner creates network connections to target APIs
- Ensure proper firewall rules for ZAP proxy
- Use VPNs when scanning external targets

### Responsible Disclosure
- Only scan APIs you own or have permission to test
- Follow responsible disclosure practices for findings
- Respect rate limits and terms of service

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

### Getting Help

- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/AdityaChaudhari901/API-SECURITY-SCANNER/issues)
- **Documentation**: Check this README and inline code comments
- **Community**: Join discussions in the repository

### FAQ

**Q: What if OWASP ZAP is not installed?**
A: The scanner falls back to direct HTTP testing without requiring ZAP.

**Q: Can I scan external APIs?**
A: Yes, but ensure you have permission and follow responsible disclosure practices.

**Q: How do I customize vulnerability checks?**
A: Modify the test cases in `enhanced_vuln_tester.py` or add new modules.

**Q: What if Slack notifications fail?**
A: Check your bot token, channel permissions, and network connectivity.

## 🎯 Roadmap

### Planned Features
- [ ] Web dashboard for report visualization
- [ ] Integration with additional security tools
- [ ] Custom vulnerability rule engine
- [ ] API documentation analysis
- [ ] Automated penetration testing workflows

### Recent Updates
- ✅ Cross-platform Python implementation
- ✅ Slack integration with SSL fixes
- ✅ Docker-based vulnerable API setup
- ✅ Professional CLI with enhanced UX
- ✅ Comprehensive vulnerability detection

---

**Built with ❤️ for API security by [Aditya Chaudhari](https://github.com/AdityaChaudhari901)**

*Last updated: August 22, 2025*