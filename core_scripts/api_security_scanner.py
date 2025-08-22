#!/usr/bin/env python3
"""
OWASP ZAP API Security Scanner
Automated security scanning tool that integrates with OWASP ZAP and Slack notifications
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

import requests
from zapv2 import ZAPv2
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from colorama import init, Fore, Style
from tabulate import tabulate

# Initialize colorama for cross-platform colored output
init()

# Load environment variables
load_dotenv()

class Config:
    """Configuration class for the API security scanner"""
    
    def __init__(self):
        self.zap_host = os.getenv('ZAP_PROXY_HOST', '127.0.0.1')
        self.zap_port = int(os.getenv('ZAP_PROXY_PORT', 8080))
        self.zap_api_key = os.getenv('ZAP_API_KEY')
        
        self.slack_token = os.getenv('SLACK_BOT_TOKEN')
        self.slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
        
        self.target_url = os.getenv('TARGET_API_URL')
        self.api_name = os.getenv('API_NAME', 'Unknown API')
        
        self.scan_timeout = int(os.getenv('SCAN_TIMEOUT', 300))
        self.poll_interval = int(os.getenv('POLL_INTERVAL', 10))
        
        self.reports_dir = Path(os.getenv('REPORTS_DIR', './reports'))
        self.reports_dir.mkdir(exist_ok=True)
    
    def validate(self) -> bool:
        """Validate required configuration"""
        required_configs = {
            'ZAP_API_KEY': self.zap_api_key,
            'TARGET_API_URL': self.target_url,
        }
        
        missing_configs = [key for key, value in required_configs.items() if not value]
        
        if missing_configs:
            print(f"{Fore.RED}Missing required configuration: {', '.join(missing_configs)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please check your .env file{Style.RESET_ALL}")
            return False
        
        return True

class ZAPScanner:
    """OWASP ZAP Scanner interface"""
    
    def __init__(self, config: Config):
        self.config = config
        # Initialize ZAP connection - connect directly to ZAP API, not through proxy
        zap_url = f'http://{config.zap_host}:{config.zap_port}'
        self.zap = ZAPv2(apikey=config.zap_api_key, proxies=None)
        # Override the base URL to point directly to ZAP
        self.zap.base = f'{zap_url}/JSON/'
        self.zap.base_other = f'{zap_url}/OTHER/'
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(config.reports_dir / 'scanner.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def check_zap_status(self) -> bool:
        """Check if ZAP is running and accessible"""
        try:
            version = self.zap.core.version
            self.logger.info(f"Connected to OWASP ZAP version: {version}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to ZAP: {e}")
            self.logger.error("💡 Solutions:")
            self.logger.error("   1. Install ZAP: brew install --cask owasp-zap")
            self.logger.error("   2. Start ZAP daemon: ./setup_zap.sh start")  
            self.logger.error("   3. Check ZAP is running on localhost:8080")
            return False
    
    def start_spider_scan(self, target_url: str) -> str:
        """Start a spider scan on the target URL"""
        try:
            self.logger.info(f"Starting spider scan on: {target_url}")
            scan_id = self.zap.spider.scan(target_url)
            self.logger.info(f"Spider scan started with ID: {scan_id}")
            return scan_id
        except Exception as e:
            self.logger.error(f"Failed to start spider scan: {e}")
            raise
    
    def start_active_scan(self, target_url: str) -> str:
        """Start an active scan on the target URL"""
        try:
            self.logger.info(f"Starting active scan on: {target_url}")
            scan_id = self.zap.ascan.scan(target_url)
            self.logger.info(f"Active scan started with ID: {scan_id}")
            return scan_id
        except Exception as e:
            self.logger.error(f"Failed to start active scan: {e}")
            raise
    
    def wait_for_spider_completion(self, scan_id: str) -> None:
        """Wait for spider scan to complete"""
        self.logger.info("Waiting for spider scan to complete...")
        
        timeout = time.time() + self.config.scan_timeout
        
        while time.time() < timeout:
            try:
                status = int(self.zap.spider.status(scan_id))
                self.logger.info(f"Spider scan progress: {status}%")
                
                if status >= 100:
                    self.logger.info("Spider scan completed successfully")
                    return
                
                time.sleep(self.config.poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error checking spider status: {e}")
                break
        
        raise TimeoutError("Spider scan timed out")
    
    def wait_for_active_scan_completion(self, scan_id: str) -> None:
        """Wait for active scan to complete"""
        self.logger.info("Waiting for active scan to complete...")
        
        timeout = time.time() + self.config.scan_timeout
        
        while time.time() < timeout:
            try:
                status = int(self.zap.ascan.status(scan_id))
                self.logger.info(f"Active scan progress: {status}%")
                
                if status >= 100:
                    self.logger.info("Active scan completed successfully")
                    return
                
                time.sleep(self.config.poll_interval)
                
            except Exception as e:
                self.logger.error(f"Error checking active scan status: {e}")
                break
        
        raise TimeoutError("Active scan timed out")
    
    def get_scan_results(self) -> List[Dict[str, Any]]:
        """Retrieve scan results from ZAP"""
        try:
            alerts = self.zap.core.alerts()
            self.logger.info(f"Retrieved {len(alerts)} alerts from scan")
            return alerts
        except Exception as e:
            self.logger.error(f"Failed to retrieve scan results: {e}")
            raise
    
    def filter_high_severity_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter alerts to only include high severity findings"""
        high_severity_alerts = []
        
        for alert in alerts:
            risk = alert.get('risk', '').lower()
            if risk == 'high':
                high_severity_alerts.append(alert)
        
        self.logger.info(f"Found {len(high_severity_alerts)} high-severity alerts out of {len(alerts)} total alerts")
        return high_severity_alerts
    
    def generate_report(self, alerts: List[Dict[str, Any]], target_url: str) -> str:
        """Generate a detailed report of the scan results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"zap_report_{timestamp}.json"
        report_path = self.config.reports_dir / report_filename
        
        report_data = {
            "scan_info": {
                "target_url": target_url,
                "api_name": self.config.api_name,
                "scan_timestamp": datetime.now().isoformat(),
                "total_alerts": len(alerts),
                "high_severity_count": len([a for a in alerts if a.get('risk', '').lower() == 'high'])
            },
            "alerts": alerts
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Report saved to: {report_path}")
        return str(report_path)

class SlackNotifier:
    """Slack notification handler"""
    
    def __init__(self, config: Config):
        self.config = config
        self.client = None
        
        if config.slack_token:
            self.client = WebClient(token=config.slack_token)
            self.logger = logging.getLogger(__name__)
        else:
            logging.warning("Slack token not provided, notifications will be skipped")
    
    def send_alert(self, high_severity_alerts: List[Dict[str, Any]], target_url: str, report_path: str) -> bool:
        """Send Slack alert for high-severity vulnerabilities"""
        if not self.client:
            self.logger.warning("Slack client not initialized, skipping notification")
            return False
        
        if not high_severity_alerts:
            self.logger.info("No high-severity alerts to notify about")
            return True
        
        try:
            # Create alert message
            alert_count = len(high_severity_alerts)
            
            # Build vulnerability list
            vuln_list = []
            for alert in high_severity_alerts[:10]:  # Limit to top 10 to avoid message length issues
                name = alert.get('name', 'Unknown Vulnerability')
                description = alert.get('description', 'No description available')[:200]
                vuln_list.append(f"• *{name}*\n  _{description}_")
            
            if len(high_severity_alerts) > 10:
                vuln_list.append(f"... and {len(high_severity_alerts) - 10} more vulnerabilities")
            
            message = f"""🚨 *HIGH SEVERITY SECURITY ALERT* 🚨

*Target API:* {self.config.api_name}
*Endpoint:* {target_url}
*High-Severity Vulnerabilities Found:* {alert_count}

*Critical Findings:*
{chr(10).join(vuln_list)}

*Full Report:* {report_path}

⚠️ *Immediate Action Required* ⚠️
Please review and address these security vulnerabilities immediately."""

            # Send message to Slack
            response = self.client.chat_postMessage(
                channel=self.config.slack_channel,
                text=message,
                username="Security Scanner Bot",
                icon_emoji=":warning:"
            )
            
            self.logger.info(f"Slack alert sent successfully to {self.config.slack_channel}")
            return True
            
        except SlackApiError as e:
            self.logger.error(f"Failed to send Slack alert: {e.response['error']}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending Slack alert: {e}")
            return False

class SecurityScanner:
    """Main security scanner orchestrator"""
    
    def __init__(self):
        self.config = Config()
        self.zap_scanner = ZAPScanner(self.config)
        self.slack_notifier = SlackNotifier(self.config)
        self.logger = logging.getLogger(__name__)
    
    def run_scan(self, target_url: Optional[str] = None) -> Dict[str, Any]:
        """Run complete security scan"""
        if not self.config.validate():
            return {"success": False, "error": "Configuration validation failed"}
        
        target_url = target_url or self.config.target_url
        
        try:
            print(f"{Fore.CYAN}🔍 Starting API Security Scan{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Target: {target_url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}API Name: {self.config.api_name}{Style.RESET_ALL}")
            print("=" * 60)
            
            # Check ZAP status
            if not self.zap_scanner.check_zap_status():
                error_msg = """ZAP is not accessible. Please:
1. Install OWASP ZAP: brew install --cask owasp-zap
2. Start ZAP daemon: ./setup_zap.sh start
3. Or run: python3 test_connection.py for diagnostics"""
                return {"success": False, "error": error_msg}
            
            # Run spider scan
            print(f"{Fore.BLUE}🕷️  Running Spider Scan...{Style.RESET_ALL}")
            spider_scan_id = self.zap_scanner.start_spider_scan(target_url)
            self.zap_scanner.wait_for_spider_completion(spider_scan_id)
            
            # Run active scan
            print(f"{Fore.BLUE}🎯 Running Active Security Scan...{Style.RESET_ALL}")
            active_scan_id = self.zap_scanner.start_active_scan(target_url)
            self.zap_scanner.wait_for_active_scan_completion(active_scan_id)
            
            # Get scan results
            print(f"{Fore.BLUE}📊 Retrieving Scan Results...{Style.RESET_ALL}")
            all_alerts = self.zap_scanner.get_scan_results()
            
            # Filter high-severity alerts
            high_severity_alerts = self.zap_scanner.filter_high_severity_alerts(all_alerts)
            
            # Generate report
            print(f"{Fore.BLUE}📝 Generating Report...{Style.RESET_ALL}")
            report_path = self.zap_scanner.generate_report(all_alerts, target_url)
            
            # Display results
            self._display_results(all_alerts, high_severity_alerts)
            
            # Send Slack notification if high-severity issues found
            if high_severity_alerts:
                print(f"{Fore.RED}🚨 High-severity vulnerabilities detected! Sending Slack alert...{Style.RESET_ALL}")
                self.slack_notifier.send_alert(high_severity_alerts, target_url, report_path)
            else:
                print(f"{Fore.GREEN}✅ No high-severity vulnerabilities found{Style.RESET_ALL}")
            
            return {
                "success": True,
                "total_alerts": len(all_alerts),
                "high_severity_count": len(high_severity_alerts),
                "report_path": report_path,
                "high_severity_alerts": high_severity_alerts
            }
            
        except Exception as e:
            error_msg = f"Scan failed: {e}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg}
    
    def _display_results(self, all_alerts: List[Dict[str, Any]], high_severity_alerts: List[Dict[str, Any]]) -> None:
        """Display scan results in a formatted table"""
        print(f"\n{Fore.CYAN}📋 SCAN RESULTS SUMMARY{Style.RESET_ALL}")
        print("=" * 60)
        
        # Count alerts by severity
        severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for alert in all_alerts:
            risk = alert.get('risk', 'Unknown')
            if risk in severity_counts:
                severity_counts[risk] += 1
        
        # Display summary table
        summary_data = [[severity, count] for severity, count in severity_counts.items()]
        print(tabulate(summary_data, headers=["Severity", "Count"], tablefmt="grid"))
        
        # Display high-severity details
        if high_severity_alerts:
            print(f"\n{Fore.RED}🚨 HIGH SEVERITY VULNERABILITIES:{Style.RESET_ALL}")
            print("=" * 60)
            
            for i, alert in enumerate(high_severity_alerts, 1):
                print(f"{Fore.RED}{i}. {alert.get('name', 'Unknown')}{Style.RESET_ALL}")
                print(f"   URL: {alert.get('url', 'N/A')}")
                print(f"   Description: {alert.get('description', 'No description')[:100]}...")
                print(f"   Confidence: {alert.get('confidence', 'Unknown')}")
                print()

def main():
    """Main entry point"""
    scanner = SecurityScanner()
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        result = scanner.run_scan(target_url)
    else:
        result = scanner.run_scan()
    
    if result["success"]:
        print(f"\n{Fore.GREEN}✅ Scan completed successfully!{Style.RESET_ALL}")
        print(f"Report saved to: {result['report_path']}")
        
        if result["high_severity_count"] > 0:
            sys.exit(1)  # Exit with error code if high-severity issues found
    else:
        print(f"\n{Fore.RED}❌ Scan failed: {result['error']}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
