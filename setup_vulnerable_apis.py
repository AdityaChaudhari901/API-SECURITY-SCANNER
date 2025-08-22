#!/usr/bin/env python3
"""
Setup Vulnerable APIs - Python Version
Sets up OWASP Juice Shop and VAmPI for vulnerability testing
"""

import sys
import subprocess
import time
import requests
import shutil
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
    NC = Style.RESET_ALL

class Emojis:
    """Emoji constants for better UX"""
    SUCCESS = "✅"
    WARNING = "⚠️"
    ERROR = "❌"
    INFO = "ℹ️"
    ROCKET = "🚀"
    DOCKER = "🐳"
    JUICE = "🧃"
    API = "🔌"
    TEST = "🔍"
    TARGET = "🎯"
    MOBILE = "📱"
    DOWNLOAD = "📥"
    CLOCK = "⏳"
    ONE = "1️⃣"
    TWO = "2️⃣"

class VulnerableApiSetup:
    """Setup and manage vulnerable APIs for testing"""
    
    def __init__(self):
        self.docker_cmd = self._find_docker()
        self.juice_shop_config = {
            'name': 'juice-shop',
            'image': 'bkimminich/juice-shop',
            'port': '3000',
            'description': 'OWASP Juice Shop - Deliberately vulnerable web application'
        }
        self.vampi_config = {
            'name': 'vampi',
            'image': 'erev0s/vampi',
            'port': '5001',  # Changed from 5000 to avoid macOS Control Center conflict
            'description': 'VAmPI - Deliberately vulnerable REST API'
        }
    
    def _find_docker(self):
        """Find Docker executable"""
        docker_cmd = shutil.which('docker')
        if not docker_cmd:
            print(f"{Emojis.ERROR} {Colors.RED}Docker is required but not installed{Colors.NC}")
            print("Please install Docker Desktop from: https://docker.com/products/docker-desktop")
            sys.exit(1)
        return docker_cmd
    
    def _run_command(self, cmd, description, capture_output=True, timeout=30):
        """Run a command with error handling"""
        try:
            if isinstance(cmd, str):
                result = subprocess.run(
                    cmd, shell=True, capture_output=capture_output, 
                    text=True, timeout=timeout
                )
            else:
                result = subprocess.run(
                    cmd, capture_output=capture_output, 
                    text=True, timeout=timeout
                )
            return result
        except subprocess.TimeoutExpired:
            print(f"{Emojis.ERROR} {Colors.RED}{description} timed out{Colors.NC}")
            return None
        except Exception as e:
            print(f"{Emojis.ERROR} {Colors.RED}{description} failed: {e}{Colors.NC}")
            return None
    
    def _is_docker_running(self):
        """Check if Docker daemon is running"""
        result = self._run_command([self.docker_cmd, 'info'], "Docker daemon check")
        return result and result.returncode == 0
    
    def _is_container_running(self, container_name):
        """Check if a container is running"""
        result = self._run_command([self.docker_cmd, 'ps'], "Container status check")
        if result and result.returncode == 0:
            return container_name in result.stdout
        return False
    
    def _stop_and_remove_container(self, container_name):
        """Stop and remove existing container"""
        print(f"   {Emojis.INFO} Stopping existing {container_name} container...")
        
        # Stop container
        self._run_command([self.docker_cmd, 'stop', container_name], f"Stop {container_name}")
        
        # Remove container
        self._run_command([self.docker_cmd, 'rm', container_name], f"Remove {container_name}")
    
    def _setup_container(self, config):
        """Setup a vulnerable API container"""
        container_name = config['name']
        image = config['image']
        port = config['port']
        description = config['description']
        
        print(f"\n{Emojis.ONE if container_name == 'juice-shop' else Emojis.TWO} Setting up {container_name}...")
        print(f"   - {description}")
        print(f"   - Will run on http://localhost:{port}")
        
        if self._is_container_running(container_name):
            print(f"   {Emojis.SUCCESS} {container_name} already running")
            return True
        
        # Check if container exists (stopped)
        result = self._run_command([self.docker_cmd, 'ps', '-a'], "Container list check")
        if result and container_name in result.stdout:
            self._stop_and_remove_container(container_name)
        
        print(f"   {Emojis.DOWNLOAD} Pulling and starting {container_name}...")
        
        # Run the container
        cmd = [
            self.docker_cmd, 'run', '-d',
            '--name', container_name,
            '-p', f'{port}:{port}',
            image
        ]
        
        result = self._run_command(cmd, f"Start {container_name}", timeout=120)
        if not result or result.returncode != 0:
            print(f"   {Emojis.ERROR} Failed to start {container_name}")
            if result and result.stderr:
                print(f"   Error: {result.stderr}")
            return False
        
        print(f"   {Emojis.CLOCK} Waiting for {container_name} to start...")
        
        # Wait for container to be ready
        wait_time = 15 if container_name == 'juice-shop' else 10
        time.sleep(wait_time)
        
        return True
    
    def _test_connectivity(self, url, service_name):
        """Test if a service is accessible"""
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                print(f"{Emojis.SUCCESS} {service_name} is accessible")
                return True
            else:
                print(f"{Emojis.ERROR} {service_name} returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"{Emojis.ERROR} {service_name} not responding: {e}")
            return False
    
    def setup_all(self):
        """Setup all vulnerable APIs"""
        print(f"{Emojis.JUICE} SETTING UP VULNERABLE APIs FOR TESTING")
        print("=" * 50)
        
        # Check Docker daemon
        if not self._is_docker_running():
            print(f"{Emojis.ERROR} {Colors.RED}Docker daemon is not running{Colors.NC}")
            print("Please start Docker Desktop and try again")
            return False
        
        print(f"{Emojis.DOCKER} Docker found. Setting up vulnerable APIs...")
        
        # Setup OWASP Juice Shop
        if not self._setup_container(self.juice_shop_config):
            return False
        
        # Setup VAmPI
        if not self._setup_container(self.vampi_config):
            return False
        
        # Print setup summary
        self._print_summary()
        
        # Test connectivity
        self._test_connectivity_all()
        
        # Print usage instructions
        self._print_usage_instructions()
        
        return True
    
    def _print_summary(self):
        """Print setup summary"""
        print(f"\n{Emojis.TARGET} VULNERABLE APIs READY FOR TESTING:")
        print()
        print(f"{Emojis.MOBILE} OWASP Juice Shop:")
        print("   Web Interface: http://localhost:3000")
        print("   API Endpoints: http://localhost:3000/api/*")
        print()
        print(f"{Emojis.API} VAmPI (Vulnerable API):")
        print("   API Base: http://localhost:5001")
        print("   Swagger UI: http://localhost:5001/docs")
        print()
    
    def _test_connectivity_all(self):
        """Test connectivity to all services"""
        print(f"{Emojis.TEST} Testing connectivity...")
        
        juice_shop_ok = self._test_connectivity("http://localhost:3000", "Juice Shop")
        vampi_ok = self._test_connectivity("http://localhost:5001", "VAmPI")
        
        return juice_shop_ok and vampi_ok
    
    def _print_usage_instructions(self):
        """Print usage instructions"""
        print()
        print(f"{Emojis.ROCKET} Ready to test! Run one of these commands:")
        print()
        print("# Ultimate comprehensive assessment")
        print(f"{Colors.GREEN}python3 run.py ultimate-report{Colors.NC}")
        print()
        print("# Test OWASP Juice Shop")
        print(f"{Colors.GREEN}python3 run.py test-vulns http://localhost:3000{Colors.NC}")
        print()
        print("# Test VAmPI API")  
        print(f"{Colors.GREEN}python3 run.py test-vulns http://localhost:5001{Colors.NC}")
        print()
        print("# Quick security scan")
        print(f"{Colors.GREEN}python3 run.py quick-scan http://localhost:3000{Colors.NC}")
        print()
        print("# Main scanner interface")
        print(f"{Colors.GREEN}python3 run.py help{Colors.NC}")
    
    def cleanup(self):
        """Cleanup all vulnerable API containers"""
        print(f"{Emojis.INFO} Cleaning up vulnerable API containers...")
        
        containers = ['juice-shop', 'vampi']
        for container in containers:
            if self._is_container_running(container):
                print(f"   Stopping {container}...")
                self._run_command([self.docker_cmd, 'stop', container], f"Stop {container}")
                self._run_command([self.docker_cmd, 'rm', container], f"Remove {container}")
                print(f"   {Emojis.SUCCESS} {container} cleaned up")
            else:
                print(f"   {Emojis.INFO} {container} not running")
    
    def status(self):
        """Show status of vulnerable API containers"""
        print(f"{Emojis.INFO} Vulnerable API Status:")
        print()
        
        containers = [
            ('juice-shop', 'OWASP Juice Shop', 'http://localhost:3000'),
            ('vampi', 'VAmPI API', 'http://localhost:5001')
        ]
        
        for container, name, url in containers:
            if self._is_container_running(container):
                print(f"{Emojis.SUCCESS} {name}: Running at {url}")
            else:
                print(f"{Emojis.ERROR} {name}: Not running")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Setup Vulnerable APIs for Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'action',
        nargs='?',
        default='setup',
        choices=['setup', 'cleanup', 'status'],
        help='Action to perform (default: setup)'
    )
    
    args = parser.parse_args()
    
    setup = VulnerableApiSetup()
    
    try:
        if args.action == 'setup':
            success = setup.setup_all()
            sys.exit(0 if success else 1)
        elif args.action == 'cleanup':
            setup.cleanup()
            sys.exit(0)
        elif args.action == 'status':
            setup.status()
            sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Emojis.WARNING} {Colors.YELLOW}Setup cancelled by user{Colors.NC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Emojis.ERROR} {Colors.RED}Unexpected error: {e}{Colors.NC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
