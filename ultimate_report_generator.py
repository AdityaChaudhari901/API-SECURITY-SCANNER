#!/usr/bin/env python3
"""
Ultimate All-in-One Report Generator
Runs ALL scan types and generates comprehensive security assessment with Slack notifications
"""

import json
import sys
import subprocess
import time
import os
import ssl
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Fix SSL certificate issues on macOS
ssl._create_default_https_context = ssl._create_unverified_context

# Add core_scripts to path
sys.path.insert(0, str(Path(__file__).parent / 'core_scripts'))

# Load environment variables
project_root = Path(__file__).parent
env_path = project_root / "docs_config" / ".env"
load_dotenv(env_path)

try:
    from api_security_scanner import Config
except ImportError:
    # Fallback config
    class Config:
        def __init__(self):
            self.api_name = "Target API"
            self.reports_dir = Path("reports")
            self.reports_dir.mkdir(exist_ok=True)

init()

class SlackNotifier:
    """Slack notification handler for ultimate reports"""
    
    def __init__(self):
        self.slack_token = os.getenv('SLACK_BOT_TOKEN')
        self.slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
        self.client = None
        
        if self.slack_token:
            self.client = WebClient(token=self.slack_token)
            print(f"{Fore.GREEN}✅ Slack integration enabled{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}⚠️  Slack token not found - notifications disabled{Style.RESET_ALL}")
    
    def send_ultimate_report(self, report_data, report_path):
        """Send ultimate security report to Slack"""
        if not self.client:
            return False
        
        try:
            # Extract key metrics from ultimate report structure
            assessment_info = report_data.get('assessment_info', {})
            vulnerability_analysis = report_data.get('vulnerability_analysis', {})
            
            total_findings = assessment_info.get('total_findings', 0)
            security_posture = assessment_info.get('security_posture', 'UNKNOWN')
            target_url = assessment_info.get('target_url', 'Unknown')
            
            risk_dist = assessment_info.get('risk_distribution', {})
            high_severity = risk_dist.get('high', 0)
            medium_severity = risk_dist.get('medium', 0)
            
            # Get critical vulnerabilities
            critical_vulns = vulnerability_analysis.get('by_severity', {}).get('critical_high', [])
            
            # Create alert message
            if high_severity > 0:
                alert_emoji = "🚨"
                status = "HIGH RISK"
            elif total_findings > 5:
                alert_emoji = "⚠️"
                status = "MEDIUM RISK"
            else:
                alert_emoji = "✅"
                status = "LOW RISK"
            
            # Build vulnerability summary
            vuln_summary = ""
            if critical_vulns:
                vuln_summary = "\n*🚨 Critical Vulnerabilities:*\n"
                for i, vuln in enumerate(critical_vulns[:5], 1):
                    name = vuln.get('name', 'Unknown Vulnerability')[:50]
                    vuln_summary += f"{i}. {name}...\n"
                if len(critical_vulns) > 5:
                    vuln_summary += f"... and {len(critical_vulns) - 5} more\n"
            
            message = f"""{alert_emoji} *ULTIMATE SECURITY ASSESSMENT COMPLETE*

*Target:* {target_url}
*Security Posture:* {security_posture}
*Total Findings:* {total_findings}
*High Severity Issues:* {high_severity}
*Medium Severity Issues:* {medium_severity}
{vuln_summary}
*Full Report:* {report_path}

⚡ *Immediate Security Review Required*"""
            
            # Send to Slack
            response = self.client.chat_postMessage(
                channel=self.slack_channel,
                text=message,
                username="Security Scanner Bot",
                icon_emoji=":shield:"
            )
            
            print(f"{Fore.GREEN}📤 Ultimate report sent to Slack channel: {self.slack_channel}{Style.RESET_ALL}")
            return True
            
        except SlackApiError as e:
            print(f"{Fore.RED}❌ Failed to send Slack notification: {e.response['error']}{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}❌ Unexpected Slack error: {e}{Style.RESET_ALL}")
            return False

class UltimateReportGenerator:
    """Generate comprehensive security report from all scan types"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.config = Config()
        self.slack_notifier = SlackNotifier()
        self.all_findings = []
        self.scan_results = {}
        
    def run_all_scans(self):
        """Execute all available scan types"""
        print(f"{Fore.CYAN}🚀 ULTIMATE SECURITY ASSESSMENT{Style.RESET_ALL}")
        print(f"Target: {self.target_url}")
        print("=" * 80)
        
        scans_to_run = [
            ("Enhanced Vulnerability Testing", "enhanced_vuln_tester.py"),
            ("Quick Scan", "core_scripts/quick_scan.py"),
            ("Main Scanner (if ZAP available)", "core_scripts/api_security_scanner.py")
        ]
        
        for scan_name, script_path in scans_to_run:
            print(f"\n{Fore.BLUE}🔍 Running {scan_name}...{Style.RESET_ALL}")
            success = self._run_scan(scan_name, script_path)
            if success:
                print(f"   ✅ {scan_name} completed successfully")
            else:
                print(f"   ⚠️  {scan_name} completed with warnings")
    
    def _run_scan(self, scan_name, script_path):
        """Run individual scan"""
        try:
            if "api_security_scanner.py" in script_path:
                # Main scanner might fail if ZAP not available
                cmd = [sys.executable, script_path, self.target_url]
            else:
                cmd = [sys.executable, script_path, self.target_url]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            self.scan_results[scan_name] = {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print(f"   ⏱️  {scan_name} timed out after 2 minutes")
            return False
        except Exception as e:
            print(f"   ❌ {scan_name} failed: {e}")
            return False
    
    def collect_all_reports(self):
        """Collect findings from all generated reports"""
        print(f"\n{Fore.BLUE}📊 Collecting All Report Data...{Style.RESET_ALL}")
        
        reports_dir = Path("reports")
        all_reports = sorted(reports_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
        
        # Get reports from the last 10 minutes (recent scans)
        recent_time = time.time() - 600  # 10 minutes ago
        recent_reports = [r for r in all_reports if r.stat().st_mtime > recent_time]
        
        print(f"   Found {len(recent_reports)} recent reports")
        
        combined_findings = []
        report_metadata = []
        
        for report_file in recent_reports:
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                    
                    # Extract alerts/findings
                    alerts = report_data.get('alerts', [])
                    if not alerts and 'detailed_findings' in report_data:
                        alerts = report_data['detailed_findings']
                    
                    # Add source information
                    for alert in alerts:
                        alert['source_report'] = report_file.name
                        alert['scan_timestamp'] = report_data.get('scan_info', {}).get('scan_timestamp', '')
                    
                    combined_findings.extend(alerts)
                    
                    # Collect metadata
                    scan_info = report_data.get('scan_info', report_data.get('generation_info', {}))
                    report_metadata.append({
                        'file': report_file.name,
                        'scan_type': scan_info.get('scan_type', 'Unknown'),
                        'timestamp': scan_info.get('timestamp', scan_info.get('scan_timestamp', '')),
                        'total_alerts': len(alerts),
                        'target_url': scan_info.get('target_url', ''),
                        'file_size': report_file.stat().st_size
                    })
                    
            except Exception as e:
                print(f"   ⚠️  Could not process {report_file.name}: {e}")
        
        self.all_findings = combined_findings
        return report_metadata
    
    def generate_ultimate_report(self, report_metadata):
        """Generate the ultimate comprehensive report"""
        print(f"\n{Fore.BLUE}📝 Generating Ultimate Security Report...{Style.RESET_ALL}")
        
        # Analyze findings
        high_severity = [f for f in self.all_findings if f.get('risk') == 'High']
        medium_severity = [f for f in self.all_findings if f.get('risk') == 'Medium'] 
        low_severity = [f for f in self.all_findings if f.get('risk') == 'Low']
        
        # Count vulnerability types
        vuln_types = {}
        for finding in self.all_findings:
            vuln_name = finding.get('name', 'Unknown')
            vuln_types[vuln_name] = vuln_types.get(vuln_name, 0) + 1
        
        # Determine security posture
        if len(high_severity) >= 5:
            security_posture = "CRITICAL"
            posture_color = Fore.RED
        elif len(high_severity) >= 1:
            security_posture = "HIGH RISK"
            posture_color = Fore.YELLOW
        elif len(medium_severity) >= 5:
            security_posture = "MEDIUM RISK"
            posture_color = Fore.YELLOW
        else:
            security_posture = "LOW RISK"
            posture_color = Fore.GREEN
            
        # Create ultimate report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        ultimate_report = {
            "report_type": "ULTIMATE COMPREHENSIVE SECURITY ASSESSMENT",
            "assessment_info": {
                "target_url": self.target_url,
                "api_name": self.config.api_name,
                "assessment_timestamp": datetime.now().isoformat(),
                "total_scans_performed": len(report_metadata),
                "total_findings": len(self.all_findings),
                "security_posture": security_posture,
                "risk_distribution": {
                    "high": len(high_severity),
                    "medium": len(medium_severity), 
                    "low": len(low_severity)
                }
            },
            "executive_summary": {
                "overall_security_rating": security_posture,
                "immediate_attention_required": len(high_severity),
                "total_vulnerabilities_found": len(self.all_findings),
                "scans_performed": len(report_metadata),
                "key_vulnerability_types": list(vuln_types.keys())[:10],
                "recommendations_count": 8,
                "compliance_status": "NON-COMPLIANT" if len(high_severity) > 0 else "REVIEW REQUIRED"
            },
            "detailed_scan_results": {
                "scan_metadata": report_metadata,
                "scan_execution_results": self.scan_results,
                "total_scan_coverage": f"{len(report_metadata)} different scan types"
            },
            "vulnerability_analysis": {
                "by_severity": {
                    "critical_high": [f for f in high_severity],
                    "medium_risk": [f for f in medium_severity][:10],  # Limit for size
                    "low_risk": [f for f in low_severity][:5]   # Limit for size
                },
                "by_category": vuln_types,
                "unique_vulnerabilities": len(set([f.get('name', 'Unknown') for f in self.all_findings])),
                "affected_endpoints": len(set([f.get('url', 'Unknown') for f in self.all_findings]))
            },
            "all_findings": self.all_findings,
            "security_recommendations": [
                "🚨 IMMEDIATE: Address all HIGH severity vulnerabilities within 24 hours",
                "🔒 Implement proper authentication and authorization controls",
                "🛡️ Add security headers (HSTS, CSP, X-Frame-Options, etc.)",
                "🔍 Conduct input validation for all user inputs", 
                "⚡ Implement rate limiting and DoS protection",
                "🔐 Review and strengthen password policies",
                "📊 Set up continuous security monitoring",
                "✅ Schedule regular penetration testing"
            ],
            "compliance_checklist": {
                "OWASP_Top_10_2021": {
                    "A01_Broken_Access_Control": "FAIL" if any("Access Control" in f.get('name', '') for f in high_severity) else "REVIEW",
                    "A02_Cryptographic_Failures": "REVIEW",
                    "A03_Injection": "FAIL" if any("Injection" in f.get('name', '') for f in high_severity) else "REVIEW",
                    "A07_Identification_Authentication_Failures": "FAIL" if any("Authentication" in f.get('name', '') for f in high_severity) else "REVIEW"
                },
                "overall_owasp_compliance": "NON-COMPLIANT" if len(high_severity) > 0 else "PARTIAL"
            }
        }
        
        # Save ultimate report
        report_filename = f"ULTIMATE_security_assessment_{timestamp}.json"
        report_path = self.config.reports_dir / report_filename
        
        with open(report_path, 'w') as f:
            json.dump(ultimate_report, f, indent=2)
        
        # Display comprehensive summary
        print(f"\n{Fore.CYAN}🎯 ULTIMATE SECURITY ASSESSMENT COMPLETE{Style.RESET_ALL}")
        print("=" * 80)
        print(f"🎯 Target: {self.target_url}")
        print(f"📊 Total Scans: {len(report_metadata)}")
        print(f"🔍 Total Findings: {len(self.all_findings)}")
        print(f"📈 Security Posture: {posture_color}{security_posture}{Style.RESET_ALL}")
        print()
        
        print(f"📋 RISK BREAKDOWN:")
        print(f"   🚨 HIGH SEVERITY: {len(high_severity)}")
        print(f"   ⚠️  MEDIUM SEVERITY: {len(medium_severity)}")
        print(f"   ℹ️  LOW SEVERITY: {len(low_severity)}")
        print()
        
        if high_severity:
            print(f"{Fore.RED}🚨 CRITICAL VULNERABILITIES REQUIRING IMMEDIATE ACTION:{Style.RESET_ALL}")
            for i, vuln in enumerate(high_severity[:10], 1):
                print(f"   {i}. {vuln.get('name', 'Unknown')} - {vuln.get('description', 'No description')[:60]}...")
        
        print(f"\n{Fore.GREEN}📄 ULTIMATE REPORT SAVED: {report_path}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}📊 Contains findings from {len(report_metadata)} different scan types{Style.RESET_ALL}")
        
        # Show scan types performed
        print(f"\n{Fore.BLUE}🔍 SCANS PERFORMED:{Style.RESET_ALL}")
        for metadata in report_metadata:
            scan_type = metadata.get('scan_type', 'Unknown')
            alerts = metadata.get('total_alerts', 0)
            print(f"   ✅ {scan_type}: {alerts} findings")
        
        # Send Slack notification
        print(f"\n{Fore.CYAN}📤 Sending report to Slack...{Style.RESET_ALL}")
        self.slack_notifier.send_ultimate_report(ultimate_report, str(report_path))
        
        return str(report_path)

def main():
    """Main execution"""
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    
    print(f"{Fore.MAGENTA}🎯 ULTIMATE API SECURITY ASSESSMENT{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Comprehensive analysis using ALL available scan types{Style.RESET_ALL}")
    print("=" * 80)
    
    generator = UltimateReportGenerator(target_url)
    
    # Run all scans
    generator.run_all_scans()
    
    # Collect all findings
    report_metadata = generator.collect_all_reports()
    
    # Generate ultimate report
    ultimate_report_path = generator.generate_ultimate_report(report_metadata)
    
    print(f"\n{Fore.MAGENTA}🎉 ULTIMATE SECURITY ASSESSMENT COMPLETE!{Style.RESET_ALL}")
    print(f"📁 Report: {ultimate_report_path}")

if __name__ == "__main__":
    main()
