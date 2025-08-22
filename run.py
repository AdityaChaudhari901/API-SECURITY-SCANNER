#!/usr/bin/env python3
"""
API Security Scanner - Main Entry Point (Python Version)
Provides unified interface for all scanner functionality
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class Colors:
    """Color constants for output formatting"""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    PURPLE = Fore.MAGENTA
    CYAN = Fore.CYAN
    NC = Style.RESET_ALL  # No Color

class Emojis:
    """Emoji constants for better UX"""
    SUCCESS = "✅"
    WARNING = "⚠️"
    ERROR = "❌"
    INFO = "ℹ️"
    ROCKET = "🚀"
    SHIELD = "🛡️"
    TARGET = "🎯"
    REPORT = "📊"
    GEAR = "🔧"

class SecurityScanner:
    """Main security scanner interface"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        
    def print_header(self):
        """Print application header"""
        print(f"{Colors.PURPLE}{Emojis.ROCKET} API Security Scanner{Colors.NC}")
        print(f"{Colors.PURPLE}======================={Colors.NC}")
        print()
    
    def print_help(self):
        """Print help information"""
        self.print_header()
        print(f"{Colors.CYAN}Available commands:{Colors.NC}")
        print()
        print(f"{Emojis.REPORT} {Colors.BLUE}Core Functions:{Colors.NC}")
        print("  ultimate-report - Ultimate comprehensive assessment")
        print("  test-vulns     - Enhanced vulnerability testing")
        print("  quick-scan     - Quick security scan")
        print("  full-scan      - Complete security assessment")
        print()
        print(f"{Emojis.GEAR} {Colors.BLUE}Setup & Utilities:{Colors.NC}")
        print("  install        - Install dependencies")
        print("  setup-vulns    - Setup OWASP Juice Shop & VAmPI")
        print()
        print(f"{Colors.CYAN}Usage Examples:{Colors.NC}")
        print("  python3 run.py ultimate-report")
        print("  python3 run.py test-vulns")
        print("  python3 run.py setup-vulns")
        print()
    
    def validate_url(self, url):
        """Validate URL format"""
        if not url:
            return False
        if not (url.startswith('http://') or url.startswith('https://')):
            print(f"{Emojis.ERROR} {Colors.RED}Invalid URL format. Please use http:// or https://{Colors.NC}")
            return False
        return True
    
    def run_command(self, cmd, description, timeout=120):
        """Run a command with error handling"""
        print(f"{Emojis.INFO} {Colors.BLUE}{description}...{Colors.NC}")
        
        try:
            if isinstance(cmd, str):
                # Shell command
                result = subprocess.run(cmd, shell=True, timeout=timeout, 
                                      capture_output=False, text=True)
            else:
                # List command
                result = subprocess.run(cmd, timeout=timeout,
                                      capture_output=False, text=True)
            
            if result.returncode == 0:
                print(f"{Emojis.SUCCESS} {Colors.GREEN}{description} completed successfully{Colors.NC}")
                return True
            else:
                print(f"{Emojis.ERROR} {Colors.RED}{description} failed with code {result.returncode}{Colors.NC}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Emojis.ERROR} {Colors.RED}{description} timed out after {timeout} seconds{Colors.NC}")
            return False
        except Exception as e:
            print(f"{Emojis.ERROR} {Colors.RED}{description} failed: {e}{Colors.NC}")
            return False
    
    def install_dependencies(self):
        """Install Python dependencies"""
        print(f"{Emojis.GEAR} {Colors.BLUE}Installing dependencies...{Colors.NC}")
        
        packages = [
            "requests", "zapv2", "slack-sdk", "colorama", 
            "tabulate", "python-dotenv"
        ]
        
        for package in packages:
            cmd = [sys.executable, "-m", "pip", "install", package]
            if not self.run_command(cmd, f"Installing {package}", timeout=60):
                return False
        
        print(f"{Emojis.SUCCESS} {Colors.GREEN}All dependencies installed{Colors.NC}")
        return True
    
    def validate_dependencies(self):
        """Validate that all dependencies are available"""
        print(f"{Emojis.INFO} {Colors.BLUE}Validating dependencies...{Colors.NC}")
        
        try:
            import requests
            import zapv2  
            import slack_sdk
            import colorama
            import tabulate
            import dotenv
            print(f"{Emojis.SUCCESS} {Colors.GREEN}All dependencies available{Colors.NC}")
            return True
        except ImportError as e:
            print(f"{Emojis.ERROR} {Colors.RED}Missing dependency: {e}{Colors.NC}")
            print(f"{Emojis.INFO} Run: python3 run.py install")
            return False
    
    def setup_vulnerable_apis(self):
        """Setup vulnerable APIs using the Python script"""
        setup_script = self.project_root / "setup_vulnerable_apis.py"
        
        if not setup_script.exists():
            print(f"{Emojis.ERROR} {Colors.RED}Setup script not found: {setup_script}{Colors.NC}")
            return False
        
        cmd = [sys.executable, str(setup_script), "setup"]
        return self.run_command(cmd, "Setting up vulnerable APIs", timeout=300)
    
    def setup_zap(self):
        """Provide ZAP setup instructions"""
        print(f"{Emojis.GEAR} {Colors.BLUE}Setting up OWASP ZAP...{Colors.NC}")
        print("1. Download from: https://www.zaproxy.org/download/")
        print("2. Install and run: zap.sh -daemon -port 8080")
        print("3. Or use test-vulns command (no ZAP needed)")
    
    def run_test_vulns(self, target_url=None):
        """Run enhanced vulnerability testing"""
        if target_url is None:
            target_url = "http://localhost:3000"
            print(f"{Emojis.TARGET} {Colors.BLUE}Testing OWASP Juice Shop (default){Colors.NC}")
        else:
            if not self.validate_url(target_url):
                return False
            print(f"{Emojis.TARGET} {Colors.BLUE}Testing: {target_url}{Colors.NC}")
        
        cmd = [sys.executable, "enhanced_vuln_tester.py", target_url]
        return self.run_command(cmd, "Enhanced vulnerability testing")
    
    def run_quick_scan(self, target_url):
        """Run quick security scan"""
        if not target_url:
            print(f"{Emojis.ERROR} {Colors.RED}Please provide target URL{Colors.NC}")
            print(f"{Emojis.INFO} Usage: python3 run.py quick-scan http://localhost:3000")
            return False
        
        if not self.validate_url(target_url):
            return False
        
        print(f"{Emojis.TARGET} {Colors.BLUE}Quick scanning: {target_url}{Colors.NC}")
        
        script_path = self.project_root / "core_scripts" / "quick_scan.py"
        if not script_path.exists():
            print(f"{Emojis.ERROR} {Colors.RED}Quick scan script not found: {script_path}{Colors.NC}")
            return False
        
        cmd = [sys.executable, str(script_path), target_url]
        return self.run_command(cmd, "Quick security scan")
    
    def run_full_scan(self, target_url):
        """Run full security scan with ZAP"""
        if not target_url:
            print(f"{Emojis.ERROR} {Colors.RED}Please provide target URL{Colors.NC}")
            print(f"{Emojis.INFO} Usage: python3 run.py full-scan http://localhost:3000")
            return False
        
        if not self.validate_url(target_url):
            return False
        
        print(f"{Emojis.TARGET} {Colors.BLUE}Full scanning: {target_url}{Colors.NC}")
        
        script_path = self.project_root / "core_scripts" / "api_security_scanner.py"
        if not script_path.exists():
            print(f"{Emojis.ERROR} {Colors.RED}Main scanner script not found: {script_path}{Colors.NC}")
            return False
        
        cmd = [sys.executable, str(script_path), target_url]
        return self.run_command(cmd, "Full security scan")
    
    def run_ultimate_report(self, target_url=None):
        """Run ultimate security assessment"""
        if target_url is None:
            target_url = "http://localhost:3000"
            print(f"{Emojis.SHIELD} {Colors.PURPLE}Running Ultimate Security Assessment on OWASP Juice Shop{Colors.NC}")
        else:
            if not self.validate_url(target_url):
                return False
            print(f"{Emojis.SHIELD} {Colors.PURPLE}Running Ultimate Security Assessment on: {target_url}{Colors.NC}")
        
        script_path = self.project_root / "ultimate_report_generator.py"
        if not script_path.exists():
            print(f"{Emojis.ERROR} {Colors.RED}Ultimate report generator not found: {script_path}{Colors.NC}")
            return False
        
        cmd = [sys.executable, str(script_path), target_url]
        return self.run_command(cmd, "Ultimate security assessment", timeout=300)

def create_parser():
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description="API Security Scanner - Automated security testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run.py ultimate-report
  python3 run.py test-vulns http://localhost:3000
  python3 run.py setup-vulns
  python3 run.py install
        """
    )
    
    parser.add_argument(
        'command',
        nargs='?',
        default='help',
        choices=[
            'help', 'install', 'validate', 'setup-vulns', 'setup-zap',
            'test-vulns', 'quick-scan', 'full-scan', 'ultimate-report'
        ],
        help='Command to execute'
    )
    
    parser.add_argument(
        'target_url',
        nargs='?',
        help='Target URL for scanning (optional for some commands)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=120,
        help='Command timeout in seconds (default: 120)'
    )
    
    return parser

def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    scanner = SecurityScanner()
    
    # Route commands
    if args.command in ['help', '-h', '--help']:
        scanner.print_help()
        return 0
    
    elif args.command == 'install':
        success = scanner.install_dependencies()
        return 0 if success else 1
    
    elif args.command == 'validate':
        success = scanner.validate_dependencies()
        return 0 if success else 1
    
    elif args.command == 'setup-vulns':
        success = scanner.setup_vulnerable_apis()
        return 0 if success else 1
    
    elif args.command == 'setup-zap':
        scanner.setup_zap()
        return 0
    
    elif args.command == 'test-vulns':
        success = scanner.run_test_vulns(args.target_url)
        return 0 if success else 1
    
    elif args.command == 'quick-scan':
        success = scanner.run_quick_scan(args.target_url)
        return 0 if success else 1
    
    elif args.command == 'full-scan':
        success = scanner.run_full_scan(args.target_url)
        return 0 if success else 1
    
    elif args.command == 'ultimate-report':
        success = scanner.run_ultimate_report(args.target_url)
        return 0 if success else 1
    
    else:
        print(f"{Emojis.ERROR} {Colors.RED}Unknown command: {args.command}{Colors.NC}")
        scanner.print_help()
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{Emojis.WARNING} {Colors.YELLOW}Operation cancelled by user{Colors.NC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Emojis.ERROR} {Colors.RED}Unexpected error: {e}{Colors.NC}")
        sys.exit(1)
