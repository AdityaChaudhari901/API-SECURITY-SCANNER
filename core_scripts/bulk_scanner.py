#!/usr/bin/env python3
"""
Bulk Scanner - Scan multiple API endpoints from a configuration file
"""

import json
import sys
import time
from pathlib import Path
from typing import List, Dict, Any
from api_security_scanner import SecurityScanner, Config

class BulkScanner:
    """Scanner for multiple API endpoints"""
    
    def __init__(self):
        self.scanner = SecurityScanner()
        self.results = []
    
    def load_targets(self, config_file: str) -> List[Dict[str, str]]:
        """Load target APIs from configuration file"""
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            targets = data.get('targets', [])
            if not targets:
                raise ValueError("No targets found in configuration file")
            
            return targets
        except Exception as e:
            print(f"❌ Failed to load targets: {e}")
            sys.exit(1)
    
    def scan_targets(self, targets: List[Dict[str, str]]) -> None:
        """Scan all target APIs"""
        total_targets = len(targets)
        high_risk_apis = []
        
        print(f"🔍 Starting bulk scan of {total_targets} API endpoints")
        print("=" * 60)
        
        for i, target in enumerate(targets, 1):
            url = target.get('url')
            name = target.get('name', f'API {i}')
            
            if not url:
                print(f"⚠️  Skipping target {i}: No URL provided")
                continue
            
            print(f"\n📍 Scanning {i}/{total_targets}: {name}")
            print(f"🎯 Target: {url}")
            
            # Override config for this scan
            self.scanner.config.api_name = name
            
            # Run scan
            result = self.scanner.run_scan(url)
            result['target_info'] = target
            self.results.append(result)
            
            if result['success'] and result['high_severity_count'] > 0:
                high_risk_apis.append({
                    'name': name,
                    'url': url,
                    'high_severity_count': result['high_severity_count']
                })
            
            # Brief pause between scans
            if i < total_targets:
                print("⏳ Brief pause before next scan...")
                time.sleep(5)
        
        # Summary
        self._print_summary(high_risk_apis)
    
    def _print_summary(self, high_risk_apis: List[Dict[str, Any]]) -> None:
        """Print scan summary"""
        print("\n" + "=" * 60)
        print("📋 BULK SCAN SUMMARY")
        print("=" * 60)
        
        successful_scans = len([r for r in self.results if r['success']])
        failed_scans = len([r for r in self.results if not r['success']])
        total_high_severity = sum(r.get('high_severity_count', 0) for r in self.results)
        
        print(f"✅ Successful scans: {successful_scans}")
        print(f"❌ Failed scans: {failed_scans}")
        print(f"🚨 Total high-severity vulnerabilities: {total_high_severity}")
        print(f"⚠️  APIs with high-severity issues: {len(high_risk_apis)}")
        
        if high_risk_apis:
            print("\n🚨 HIGH-RISK APIs REQUIRING IMMEDIATE ATTENTION:")
            print("-" * 50)
            for api in high_risk_apis:
                print(f"• {api['name']}")
                print(f"  URL: {api['url']}")
                print(f"  High-severity issues: {api['high_severity_count']}")
                print()
        
        # Save summary report
        self._save_summary_report()
    
    def _save_summary_report(self) -> None:
        """Save bulk scan summary report"""
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.scanner.config.reports_dir / f"bulk_scan_summary_{timestamp}.json"
        
        summary_data = {
            "scan_timestamp": datetime.now().isoformat(),
            "total_targets": len(self.results),
            "successful_scans": len([r for r in self.results if r['success']]),
            "failed_scans": len([r for r in self.results if not r['success']]),
            "total_high_severity": sum(r.get('high_severity_count', 0) for r in self.results),
            "results": self.results
        }
        
        with open(report_path, 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        print(f"📄 Summary report saved: {report_path}")

def create_sample_config():
    """Create a sample targets configuration file"""
    sample_config = {
        "targets": [
            {
                "name": "OWASP Juice Shop",
                "url": "http://localhost:3000",
                "description": "Vulnerable web application for testing"
            },
            {
                "name": "VAmPI API",
                "url": "http://localhost:5000",
                "description": "Vulnerable API for testing"
            },
            {
                "name": "Example API",
                "url": "https://api.example.com",
                "description": "Example production API"
            }
        ]
    }
    
    config_path = Path("targets.json")
    with open(config_path, 'w') as f:
        json.dump(sample_config, f, indent=2)
    
    print(f"📄 Sample configuration created: {config_path}")
    print("Edit this file to add your target APIs")

def main():
    if len(sys.argv) < 2:
        print("Usage: python bulk_scanner.py <targets_config.json>")
        print("       python bulk_scanner.py --create-sample")
        print("\nExamples:")
        print("  python bulk_scanner.py targets.json")
        print("  python bulk_scanner.py --create-sample")
        sys.exit(1)
    
    if sys.argv[1] == "--create-sample":
        create_sample_config()
        return
    
    config_file = sys.argv[1]
    
    if not Path(config_file).exists():
        print(f"❌ Configuration file not found: {config_file}")
        sys.exit(1)
    
    bulk_scanner = BulkScanner()
    targets = bulk_scanner.load_targets(config_file)
    bulk_scanner.scan_targets(targets)

if __name__ == "__main__":
    main()
