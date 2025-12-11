"""
Guided Onboarding and Setup Wizard for ByteGuardX
Provides interactive setup and first-time user experience
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
import click

console = Console()

class OnboardingWizard:
    """Interactive onboarding wizard for ByteGuardX"""
    
    def __init__(self):
        self.config = {}
        self.scan_results = None
        
    def run_onboarding(self, skip_tour: bool = False, quick_setup: bool = False):
        """Run the complete onboarding process"""
        
        # Welcome message
        self.show_welcome()
        
        if quick_setup:
            self.quick_setup()
        else:
            # Step 1: Environment check
            self.check_environment()
            
            # Step 2: Configuration setup
            self.setup_configuration()
            
            # Step 3: Folder walkthrough
            self.folder_walkthrough()
            
            # Step 4: First scan setup
            self.first_scan_setup()
            
            # Step 5: Guided tour (optional)
            if not skip_tour:
                self.guided_tour()
        
        # Final steps
        self.show_completion()
    
    def show_welcome(self):
        """Display welcome message"""
        welcome_text = """
[bold blue]Welcome to ByteGuardX![/bold blue]

ByteGuardX is an AI-powered vulnerability scanner that helps you:
• 🔍 Find security vulnerabilities in your code
• 🤖 Get AI-powered fix suggestions
• 📊 Generate comprehensive security reports
• 🔌 Extend functionality with plugins
• 🌐 Access via CLI, API, or web interface

Let's get you set up in just a few minutes!
        """
        
        console.print(Panel(welcome_text, border_style="blue", padding=(1, 2)))
        
        if not Confirm.ask("\n[bold]Ready to begin setup?[/bold]", default=True):
            console.print("[yellow]Setup cancelled. Run 'byteguardx init' when you're ready![/yellow]")
            return False
        
        return True
    
    def check_environment(self):
        """Check system environment and dependencies"""
        console.print("\n[bold blue]🔍 Checking Environment...[/bold blue]")
        
        checks = [
            ("Python version", self._check_python),
            ("Required directories", self._check_directories),
            ("Configuration files", self._check_config_files),
            ("Database setup", self._check_database),
            ("Dependencies", self._check_dependencies)
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for check_name, check_func in checks:
                task = progress.add_task(f"Checking {check_name}...", total=1)
                
                try:
                    result = check_func()
                    if result:
                        progress.update(task, completed=1)
                        console.print(f"  ✅ {check_name}")
                    else:
                        console.print(f"  ⚠️  {check_name} - needs attention")
                except Exception as e:
                    console.print(f"  ❌ {check_name} - error: {e}")
                
                time.sleep(0.5)  # Visual delay
        
        console.print("[green]Environment check completed![/green]")
    
    def setup_configuration(self):
        """Interactive configuration setup"""
        console.print("\n[bold blue]⚙️ Configuration Setup[/bold blue]")
        
        # Ask about security features
        console.print("\n[bold]Security Features:[/bold]")
        
        enable_2fa = Confirm.ask("Enable Two-Factor Authentication (2FA)?", default=True)
        enable_rate_limiting = Confirm.ask("Enable rate limiting protection?", default=True)
        enable_audit_logging = Confirm.ask("Enable comprehensive audit logging?", default=True)
        
        # Ask about AI features
        console.print("\n[bold]AI Features:[/bold]")
        
        enable_ai = Confirm.ask("Enable AI-powered scanning?", default=True)
        if enable_ai:
            api_key = Prompt.ask("OpenAI API key (optional, press Enter to skip)", default="", show_default=False)
            if api_key:
                self.config['openai_api_key'] = api_key
        
        # Ask about monitoring
        console.print("\n[bold]Monitoring:[/bold]")
        
        enable_monitoring = Confirm.ask("Enable system health monitoring?", default=True)
        
        # Save configuration
        self.config.update({
            'enable_2fa': enable_2fa,
            'enable_rate_limiting': enable_rate_limiting,
            'enable_audit_logging': enable_audit_logging,
            'enable_ai_scanning': enable_ai,
            'enable_health_monitoring': enable_monitoring
        })
        
        self._save_config()
        console.print("[green]✅ Configuration saved![/green]")
    
    def folder_walkthrough(self):
        """Show folder structure and explain components"""
        console.print("\n[bold blue]📁 ByteGuardX Folder Structure[/bold blue]")
        
        # Create folder tree
        tree = Tree("📁 ByteGuardX")
        
        # Core folders
        core_tree = tree.add("🔧 Core Components")
        core_tree.add("📄 byteguardx/cli/ - Command line interface")
        core_tree.add("🌐 byteguardx/api/ - REST API server")
        core_tree.add("🔍 byteguardx/scanners/ - Security scanners")
        core_tree.add("🤖 byteguardx/ai_suggestions/ - AI fix engine")
        core_tree.add("📊 byteguardx/reports/ - Report generators")
        
        # Data folders
        data_tree = tree.add("💾 Data Storage")
        data_tree.add("📋 data/logs/ - Application logs")
        data_tree.add("🔒 data/secure/ - Encrypted data")
        data_tree.add("🔌 data/plugins/ - Custom plugins")
        data_tree.add("💾 data/backups/ - System backups")
        
        # Output folders
        output_tree = tree.add("📤 Output")
        output_tree.add("📄 reports/output/ - Generated reports")
        output_tree.add("🗂️ temp/ - Temporary files")
        
        console.print(tree)
        
        # Explain key concepts
        console.print("\n[bold]Key Concepts:[/bold]")
        concepts_table = Table(show_header=True, header_style="bold blue")
        concepts_table.add_column("Component", style="cyan")
        concepts_table.add_column("Purpose", style="white")
        
        concepts_table.add_row("Scanners", "Detect vulnerabilities (secrets, dependencies, patterns)")
        concepts_table.add_row("AI Engine", "Generate intelligent fix suggestions")
        concepts_table.add_row("Plugins", "Extend functionality with custom rules")
        concepts_table.add_row("Reports", "Generate PDF, JSON, and web reports")
        concepts_table.add_row("API", "Integrate with other tools and services")
        
        console.print(concepts_table)
        
        if Confirm.ask("\n[bold]Would you like to see the web interface?[/bold]", default=False):
            console.print("[yellow]💡 After setup, run 'python run.py' to start the web interface[/yellow]")
    
    def first_scan_setup(self):
        """Set up and run the first scan"""
        console.print("\n[bold blue]🔍 First Scan Setup[/bold blue]")
        
        # Ask for scan target
        scan_options = [
            "Current directory (.)",
            "Specify a custom path",
            "Use demo project",
            "Skip for now"
        ]
        
        console.print("\n[bold]What would you like to scan?[/bold]")
        for i, option in enumerate(scan_options, 1):
            console.print(f"  {i}. {option}")
        
        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4"], default="1")
        
        scan_path = None
        if choice == "1":
            scan_path = "."
        elif choice == "2":
            scan_path = Prompt.ask("Enter the path to scan")
            if not os.path.exists(scan_path):
                console.print(f"[red]❌ Path '{scan_path}' does not exist[/red]")
                return
        elif choice == "3":
            scan_path = self._create_demo_project()
        elif choice == "4":
            console.print("[yellow]Skipping first scan. You can run 'byteguardx scan <path>' later.[/yellow]")
            return
        
        if scan_path:
            self._run_first_scan(scan_path)
    
    def guided_tour(self):
        """Provide a guided tour of features"""
        console.print("\n[bold blue]🎯 Guided Tour[/bold blue]")
        
        if not Confirm.ask("Would you like a quick tour of ByteGuardX features?", default=True):
            return
        
        tour_steps = [
            ("CLI Commands", self._tour_cli),
            ("Web Interface", self._tour_web),
            ("API Usage", self._tour_api),
            ("Plugin System", self._tour_plugins),
            ("Security Features", self._tour_security)
        ]
        
        for step_name, step_func in tour_steps:
            console.print(f"\n[bold cyan]📖 {step_name}[/bold cyan]")
            step_func()
            
            if not Confirm.ask(f"Continue to next section?", default=True):
                break
    
    def show_completion(self):
        """Show completion message and next steps"""
        completion_text = """
[bold green]🎉 Setup Complete![/bold green]

ByteGuardX is now ready to use! Here are your next steps:

[bold]Quick Commands:[/bold]
• [cyan]byteguardx scan /path/to/project[/cyan] - Scan a project
• [cyan]byteguardx serve[/cyan] - Start web interface
• [cyan]byteguardx --help[/cyan] - View all commands

[bold]Web Interface:[/bold]
• Run [cyan]python run.py[/cyan] to start the dashboard
• Open [cyan]http://localhost:3000[/cyan] in your browser

[bold]Documentation:[/bold]
• Visit [cyan]https://docs.byteguardx.com[/cyan] for detailed guides
• Check [cyan]README.md[/cyan] for quick reference

[bold green]Happy scanning! 🔒[/bold green]
        """
        
        console.print(Panel(completion_text, border_style="green", padding=(1, 2)))
    
    def quick_setup(self):
        """Quick setup with sensible defaults"""
        console.print("\n[bold blue]⚡ Quick Setup[/bold blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Set default configuration
            task1 = progress.add_task("Setting up default configuration...", total=1)
            self.config = {
                'enable_2fa': True,
                'enable_rate_limiting': True,
                'enable_audit_logging': True,
                'enable_ai_scanning': True,
                'enable_health_monitoring': True
            }
            self._save_config()
            progress.update(task1, completed=1)
            
            # Check environment
            task2 = progress.add_task("Checking environment...", total=1)
            self._check_directories()
            self._check_config_files()
            progress.update(task2, completed=1)
            
            # Create demo project and scan
            task3 = progress.add_task("Running demo scan...", total=1)
            demo_path = self._create_demo_project()
            self._run_first_scan(demo_path, quiet=True)
            progress.update(task3, completed=1)
        
        console.print("[green]✅ Quick setup completed![/green]")
    
    # Helper methods
    def _check_python(self) -> bool:
        """Check Python version"""
        import sys
        return sys.version_info >= (3, 8)
    
    def _check_directories(self) -> bool:
        """Check and create necessary directories"""
        directories = [
            "data/logs", "data/audit_logs", "data/secure", 
            "data/rate_limits", "data/plugins", "data/backups",
            "reports/output", "temp"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        return True
    
    def _check_config_files(self) -> bool:
        """Check configuration files"""
        if not os.path.exists('.env') and os.path.exists('.env.backend.example'):
            import shutil
            shutil.copy('.env.backend.example', '.env')
        
        return True
    
    def _check_database(self) -> bool:
        """Check database setup"""
        try:
            from byteguardx.database.connection_pool import init_db
            init_db('sqlite:///data/byteguardx.db')
            return True
        except Exception:
            return False
    
    def _check_dependencies(self) -> bool:
        """Check if dependencies are installed"""
        try:
            import cryptography
            import rich
            import click
            return True
        except ImportError:
            return False
    
    def _save_config(self):
        """Save configuration to file"""
        config_path = "data/onboarding_config.json"
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def _create_demo_project(self) -> str:
        """Create a demo project for scanning"""
        demo_dir = "demo_project"
        os.makedirs(demo_dir, exist_ok=True)
        
        # Create demo files with various vulnerabilities
        demo_files = {
            "app.py": '''
# Demo Python application with security issues
import os
import subprocess

# Hardcoded credentials (security issue)
API_KEY = "sk_test_1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def unsafe_command(user_input):
    # Command injection vulnerability (DEMO - DO NOT USE)
    # This is intentionally vulnerable for demonstration
    # In real code, use: subprocess.run(['echo', user_input], shell=False)
    result = "DEMO: This would execute: echo " + str(user_input)
    return result

def sql_query(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

if __name__ == "__main__":
    print("Demo application")
''',
            "config.js": '''
// Demo JavaScript with security issues
const config = {
    apiKey: "AKIA1234567890EXAMPLE",
    secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    database: {
        host: "localhost",
        password: "password123"
    }
};

// Potential XSS vulnerability
function displayUserInput(input) {
    document.innerHTML = input;
}

module.exports = config;
''',
            "requirements.txt": '''
# Demo requirements with known vulnerabilities
requests==2.20.0
flask==1.0.0
django==2.0.0
''',
            "README.md": '''
# Demo Project

This is a demo project created by ByteGuardX for testing purposes.
It contains intentional security vulnerabilities for demonstration.

**Do not use this code in production!**
'''
        }
        
        for filename, content in demo_files.items():
            with open(os.path.join(demo_dir, filename), 'w') as f:
                f.write(content)
        
        console.print(f"[green]✅ Created demo project in '{demo_dir}'[/green]")
        return demo_dir
    
    def _run_first_scan(self, scan_path: str, quiet: bool = False):
        """Run the first scan"""
        if not quiet:
            console.print(f"\n[bold]🔍 Scanning '{scan_path}'...[/bold]")
        
        try:
            # Import and run scanner
            from byteguardx.core.file_processor import FileProcessor
            from byteguardx.scanners.secret_scanner import SecretScanner
            
            processor = FileProcessor()
            scanner = SecretScanner()
            
            # Process files
            files = processor.process_directory(scan_path)
            findings = []
            
            for file_info in files:
                file_findings = scanner.scan_content(
                    file_info['content'], 
                    file_info['path']
                )
                findings.extend(file_findings)
            
            self.scan_results = findings
            
            if not quiet:
                # Display results
                if findings:
                    console.print(f"[yellow]⚠️  Found {len(findings)} potential security issues[/yellow]")
                    
                    # Show top 3 findings
                    for i, finding in enumerate(findings[:3]):
                        console.print(f"  {i+1}. {finding.get('description', 'Unknown issue')} "
                                    f"in {Path(finding.get('file_path', '')).name}")
                    
                    if len(findings) > 3:
                        console.print(f"  ... and {len(findings) - 3} more")
                    
                    console.print(f"\n[cyan]💡 Run 'byteguardx scan {scan_path} --verbose' for detailed results[/cyan]")
                else:
                    console.print("[green]✅ No security issues found![/green]")
        
        except Exception as e:
            if not quiet:
                console.print(f"[red]❌ Scan failed: {e}[/red]")
    
    def _tour_cli(self):
        """CLI tour section"""
        cli_commands = Table(show_header=True, header_style="bold blue")
        cli_commands.add_column("Command", style="cyan")
        cli_commands.add_column("Description", style="white")
        
        cli_commands.add_row("byteguardx scan <path>", "Scan a directory or file")
        cli_commands.add_row("byteguardx serve", "Start web server")
        cli_commands.add_row("byteguardx config", "Create configuration file")
        cli_commands.add_row("byteguardx --help", "Show all available commands")
        
        console.print(cli_commands)
        console.print("\n[dim]💡 All commands support --help for detailed options[/dim]")
    
    def _tour_web(self):
        """Web interface tour section"""
        console.print("The web interface provides:")
        console.print("• 📊 Interactive dashboard with security metrics")
        console.print("• 🗺️ Vulnerability heatmaps")
        console.print("• 📄 Downloadable PDF reports")
        console.print("• ⚙️ Configuration management")
        console.print("• 🔌 Plugin management")
        console.print("\n[cyan]Start with: python run.py[/cyan]")
    
    def _tour_api(self):
        """API tour section"""
        console.print("REST API endpoints:")
        console.print("• [cyan]POST /api/scan[/cyan] - Submit files for scanning")
        console.print("• [cyan]GET /api/results[/cyan] - Retrieve scan results")
        console.print("• [cyan]GET /api/health[/cyan] - System health check")
        console.print("• [cyan]POST /api/auth/login[/cyan] - User authentication")
        console.print("\n[dim]💡 Full API documentation available at /api/docs[/dim]")
    
    def _tour_plugins(self):
        """Plugin system tour section"""
        console.print("Plugin system features:")
        console.print("• 🔌 Custom scanner plugins")
        console.print("• 📋 Custom detection rules")
        console.print("• 🔒 Sandboxed execution")
        console.print("• 📦 Plugin marketplace (coming soon)")
        console.print("\n[dim]💡 Check data/plugins/ for examples[/dim]")
    
    def _tour_security(self):
        """Security features tour section"""
        console.print("Security features enabled:")
        console.print("• 🔐 Two-factor authentication")
        console.print("• 🛡️ Rate limiting protection")
        console.print("• 📝 Comprehensive audit logging")
        console.print("• 🔒 Data encryption at rest")
        console.print("• 🚨 Real-time monitoring")
        console.print("\n[dim]💡 Configure in .env file or web interface[/dim]")
