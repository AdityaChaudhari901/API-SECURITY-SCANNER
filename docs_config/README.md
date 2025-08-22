# API Security Scanner

An automated security scanning tool that integrates OWASP ZAP with Slack notifications for API vulnerability assessment. This tool is designed for security engineers who need to perform quick automated security scans on new API endpoints and triage potential vulnerabilities.

## Features

- 🔍 **Automated API Security Scanning**: Uses OWASP ZAP for comprehensive vulnerability detection
- 🎯 **High-Severity Filtering**: Focuses on critical vulnerabilities requiring immediate attention  
- 📱 **Slack Integration**: Automatic notifications for high-severity findings
- 📊 **Detailed Reporting**: JSON and CSV report generation
- 🔄 **Bulk Scanning**: Scan multiple API endpoints from configuration files
- 📈 **Report Analysis**: Compare and analyze scan results over time

## Quick Start

### Prerequisites

- Python 3.8+
- OWASP ZAP
- Docker (optional, for test applications)
- Slack Bot Token (for notifications)

### Installation

1. **Clone or download the project**
2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Setup OWASP ZAP**:
   ```bash
   chmod +x setup_zap.sh
   ./setup_zap.sh install  # Download and install ZAP
   ./setup_zap.sh start    # Start ZAP daemon
   ```

4. **Configure the scanner**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

### Basic Usage

1. **Start ZAP daemon** (if not already running):
   ```bash
   ./setup_zap.sh start
   ```

2. **Run a quick scan**:
   ```bash
   python quick_scan.py http://localhost:3000
   ```

3. **Run a full scan**:
   ```bash
   python api_security_scanner.py
   ```

## Configuration

### Environment Variables (.env)

```bash
# OWASP ZAP Configuration
ZAP_PROXY_HOST=127.0.0.1
ZAP_PROXY_PORT=8080
ZAP_API_KEY=your_zap_api_key_here

# Slack Configuration  
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token-here
SLACK_CHANNEL=#security-alerts

# Target API Configuration
TARGET_API_URL=http://localhost:3000/api
API_NAME=Production API

# Scan Configuration
SCAN_TIMEOUT=300
POLL_INTERVAL=10
```

### Slack Setup

1. Create a Slack App at https://api.slack.com/apps
2. Add Bot Token Scopes: `chat:write`, `channels:read`
3. Install the app to your workspace
4. Copy the Bot User OAuth Token to your `.env` file

## Usage Examples

### Single API Scan
```bash
# Scan with default configuration
python api_security_scanner.py

# Scan specific URL
python quick_scan.py https://api.example.com "Production API"
```

### Bulk Scanning
```bash
# Create sample configuration
python bulk_scanner.py --create-sample

# Edit targets.json with your APIs
# Then run bulk scan
python bulk_scanner.py targets.json
```

### Report Analysis
```bash
# Analyze single report
python report_analyzer.py reports/zap_report_20240822_143022.json

# Compare multiple reports
python report_analyzer.py compare report1.json report2.json

# Convert to CSV
python report_analyzer.py csv report.json
```

## Test Applications

For testing purposes, you can use deliberately vulnerable applications:

```bash
# Install test applications
./setup_zap.sh test-apps

# This will start:
# - OWASP Juice Shop on http://localhost:3000
# - VAmPI API on http://localhost:5000
```

## Vulnerability Triage

The scanner automatically filters vulnerabilities based on severity:

- **High**: Critical vulnerabilities requiring immediate attention
- **Medium**: Important issues to be addressed
- **Low/Informational**: Issues for awareness (filtered out by default)

Only **High severity** vulnerabilities trigger Slack alerts.

## Report Structure

Reports are saved in JSON format with the following structure:

```json
{
  "scan_info": {
    "target_url": "http://localhost:3000",
    "api_name": "Test API", 
    "scan_timestamp": "2024-08-22T14:30:22",
    "total_alerts": 15,
    "high_severity_count": 3
  },
  "alerts": [
    {
      "name": "SQL Injection",
      "risk": "High",
      "confidence": "High",
      "url": "http://localhost:3000/api/users",
      "description": "SQL injection vulnerability detected...",
      "solution": "Use parameterized queries..."
    }
  ]
}
```

## Common Vulnerability Types Detected

- SQL Injection
- Cross-Site Scripting (XSS)  
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object References
- Security Misconfiguration
- Insecure Cryptographic Storage
- Insufficient Transport Layer Protection
- Unvalidated Redirects and Forwards

## Troubleshooting

### ZAP Connection Issues
```bash
# Check ZAP status
./setup_zap.sh status

# Restart ZAP
./setup_zap.sh restart

# Check ZAP logs
tail -f zap.log
```

### Common Issues

1. **"ZAP is not accessible"**
   - Ensure ZAP daemon is running: `./setup_zap.sh start`
   - Check if port 8080 is available
   - Verify ZAP_API_KEY in .env file

2. **"Scan timeout"**
   - Increase SCAN_TIMEOUT in .env
   - Check target API is accessible
   - Verify network connectivity

3. **"Slack notification failed"**
   - Verify SLACK_BOT_TOKEN is correct
   - Check bot permissions in Slack
   - Ensure channel exists and bot is invited

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Scanner       │    │   OWASP ZAP     │    │   Target API    │
│   Application   │◄──►│   Proxy/Daemon  │◄──►│   Endpoint      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐    ┌─────────────────┐
│   Report        │    │   Slack         │
│   Generator     │    │   Notifier      │
└─────────────────┘    └─────────────────┘
```

## Security Considerations

- Run ZAP in a secure, isolated environment
- Use API keys for ZAP access control
- Secure Slack bot tokens
- Only scan APIs you have permission to test
- Review scan results before sharing
- Consider rate limiting for production APIs

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is for authorized security testing only. Only scan APIs and applications you own or have explicit permission to test. Unauthorized scanning may violate terms of service or laws.
