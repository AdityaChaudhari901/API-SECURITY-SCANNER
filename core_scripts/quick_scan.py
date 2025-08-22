#!/usr/bin/env python3
"""
Quick scan script for immediate vulnerability assessment
Simplified version for quick API security checks
"""

import sys
import json
import time
from pathlib import Path
from api_security_scanner import SecurityScanner

def quick_scan(target_url: str, api_name: str = "Quick Scan API"):
    """Perform a quick security scan"""
    print("🚀 Quick API Security Scan")
    print("=" * 50)
    print(f"Target: {target_url}")
    print(f"API: {api_name}")
    print()
    
    # Override config for quick scan
    scanner = SecurityScanner()
    scanner.config.api_name = api_name
    scanner.config.scan_timeout = 120  # Shorter timeout for quick scans
    scanner.config.poll_interval = 5   # More frequent polling
    
    # Run the scan
    result = scanner.run_scan(target_url)
    
    if result["success"]:
        print("\n" + "=" * 50)
        print("✅ Quick scan completed!")
        print(f"📊 Total vulnerabilities: {result['total_alerts']}")
        print(f"🚨 High-severity issues: {result['high_severity_count']}")
        print(f"📝 Report: {result['report_path']}")
        
        if result['high_severity_count'] > 0:
            print("\n🚨 CRITICAL: High-severity vulnerabilities found!")
            print("Action required: Review the detailed report immediately.")
            return False
        else:
            print("\n✅ No high-severity vulnerabilities detected.")
            return True
    else:
        print(f"\n❌ Scan failed: {result['error']}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python quick_scan.py <target_url> [api_name]")
        print("\nExamples:")
        print("  python quick_scan.py http://localhost:3000")
        print("  python quick_scan.py https://api.example.com 'Production API'")
        sys.exit(1)
    
    target_url = sys.argv[1]
    api_name = sys.argv[2] if len(sys.argv) > 2 else "Quick Scan API"
    
    success = quick_scan(target_url, api_name)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
