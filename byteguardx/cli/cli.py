"""
ByteGuardX CLI - Command-line interface for vulnerability scanning
"""

import os
import sys
import json
import click
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from byteguardx.core.file_processor import FileProcessor
from byteguardx.scanners.secret_scanner import SecretScanner
from byteguardx.scanners.dependency_scanner import DependencyScanner
from byteguardx.scanners.ai_pattern_scanner import AIPatternScanner
from byteguardx.ai_suggestions.fix_engine import FixEngine
from byteguardx.reports.pdf_report import PDFReportGenerator

console = Console()

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    ByteGuardX - AI-Powered Vulnerability Scanner
    
    Scan your code for secrets, vulnerable dependencies, and AI-generated anti-patterns.
    """
    pass

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results (JSON)')
@click.option('--pdf', is_flag=True, help='Generate PDF report')
@click.option('--fix', is_flag=True, help='Generate fix suggestions')
@click.option('--secrets-only', is_flag=True, help='Scan for secrets only')
@click.option('--deps-only', is_flag=True, help='Scan for vulnerable dependencies only')
@click.option('--ai-only', is_flag=True, help='Scan for AI patterns only')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(path, output, pdf, fix, secrets_only, deps_only, ai_only, verbose):
    """
    Scan a file or directory for security vulnerabilities
    """
    console.print(Panel.fit(
        "[bold blue]ByteGuardX Security Scanner[/bold blue]\n"
        "AI-Powered Vulnerability Detection",
        border_style="blue"
    ))
    
    # Initialize components
    file_processor = FileProcessor()
    secret_scanner = SecretScanner()
    dependency_scanner = DependencyScanner()
    ai_pattern_scanner = AIPatternScanner()
    fix_engine = FixEngine()
    
    all_findings = []
    scan_stats = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Process files
        task = progress.add_task("Processing files...", total=None)
        
        if os.path.isfile(path):
            processed_files = [file_processor.process_file(path)]
        else:
            processed_files = file_processor.process_directory(path, recursive=True)
        
        progress.update(task, description=f"Processed {len(processed_files)} files")
        
        # Perform scans based on options
        if not (secrets_only or deps_only or ai_only):
            # Run all scans by default
            secrets_only = deps_only = ai_only = True
        
        if secrets_only:
            task = progress.add_task("Scanning for secrets...", total=None)
            secret_scanner.reset()
            for file_info in processed_files:
                if 'error' not in file_info:
                    findings = secret_scanner.scan_file(file_info)
                    all_findings.extend(findings)
            scan_stats['secrets'] = secret_scanner.get_summary()
            progress.update(task, description=f"Found {len(secret_scanner.findings)} secrets")
        
        if deps_only:
            task = progress.add_task("Scanning dependencies...", total=None)
            dependency_scanner.reset()
            for file_info in processed_files:
                if 'error' not in file_info:
                    findings = dependency_scanner.scan_file(file_info)
                    all_findings.extend(findings)
            scan_stats['dependencies'] = dependency_scanner.get_summary()
            progress.update(task, description=f"Found {len(dependency_scanner.findings)} vulnerabilities")
        
        if ai_only:
            task = progress.add_task("Scanning AI patterns...", total=None)
            ai_pattern_scanner.reset()
            for file_info in processed_files:
                if 'error' not in file_info:
                    findings = ai_pattern_scanner.scan_file(file_info)
                    all_findings.extend(findings)
            scan_stats['ai_patterns'] = ai_pattern_scanner.get_summary()
            progress.update(task, description=f"Found {len(ai_pattern_scanner.findings)} AI patterns")
        
        # Generate fixes if requested
        fixes = []
        if fix and all_findings:
            task = progress.add_task("Generating fixes...", total=None)
            fix_engine.reset()
            fixes = fix_engine.generate_fixes(all_findings)
            scan_stats['fixes'] = fix_engine.get_fix_summary()
            progress.update(task, description=f"Generated {len(fixes)} fix suggestions")
    
    # Display results
    display_scan_results(all_findings, scan_stats, verbose)
    
    if fixes:
        display_fix_suggestions(fixes, verbose)
    
    # Save results
    if output:
        save_results_to_file(all_findings, fixes, scan_stats, output)
    
    # Generate PDF report
    if pdf:
        generate_pdf_report_cli(all_findings, fixes, scan_stats, path)
    
    # Exit with error code if critical issues found
    critical_count = sum(1 for f in all_findings if f.get('severity') == 'critical')
    if critical_count > 0:
        console.print(f"\n[bold red]⚠️  {critical_count} critical issues found![/bold red]")
        sys.exit(1)

def display_scan_results(findings, stats, verbose=False):
    """Display scan results in a formatted table"""
    if not findings:
        console.print("\n[green]✅ No security issues found![/green]")
        return
    
    # Summary table
    summary_table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    summary_table.add_column("Category", style="cyan")
    summary_table.add_column("Total", justify="right", style="green")
    summary_table.add_column("Critical", justify="right", style="red")
    summary_table.add_column("High", justify="right", style="yellow")
    summary_table.add_column("Medium", justify="right", style="blue")
    summary_table.add_column("Low", justify="right", style="dim")
    
    for category, data in stats.items():
        if 'by_severity' in data:
            severity_counts = data['by_severity']
            summary_table.add_row(
                category.title(),
                str(data['total']),
                str(severity_counts.get('critical', 0)),
                str(severity_counts.get('high', 0)),
                str(severity_counts.get('medium', 0)),
                str(severity_counts.get('low', 0))
            )
    
    console.print("\n")
    console.print(summary_table)
    
    if verbose:
        # Detailed findings table
        findings_table = Table(title="Detailed Findings", show_header=True, header_style="bold magenta")
        findings_table.add_column("Severity", style="red")
        findings_table.add_column("Type", style="cyan")
        findings_table.add_column("File", style="blue")
        findings_table.add_column("Line", justify="right", style="green")
        findings_table.add_column("Description", style="white")
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'low'), 3))
        
        for finding in sorted_findings[:20]:  # Limit to first 20 for readability
            severity = finding.get('severity', 'unknown')
            severity_color = {
                'critical': '[bold red]CRITICAL[/bold red]',
                'high': '[bold yellow]HIGH[/bold yellow]',
                'medium': '[bold blue]MEDIUM[/bold blue]',
                'low': '[dim]LOW[/dim]'
            }.get(severity, severity.upper())
            
            findings_table.add_row(
                severity_color,
                finding.get('subtype', finding.get('type', 'unknown')),
                Path(finding.get('file_path', '')).name,
                str(finding.get('line_number', 0)),
                finding.get('description', '')[:60] + ('...' if len(finding.get('description', '')) > 60 else '')
            )
        
        if len(findings) > 20:
            findings_table.add_row("...", "...", "...", "...", f"({len(findings) - 20} more findings)")
        
        console.print("\n")
        console.print(findings_table)

def display_fix_suggestions(fixes, verbose=False):
    """Display fix suggestions"""
    if not fixes:
        return
    
    console.print(f"\n[bold green]🔧 Generated {len(fixes)} fix suggestions:[/bold green]")
    
    if verbose:
        for i, fix in enumerate(fixes[:10], 1):  # Show first 10 fixes
            console.print(f"\n[bold cyan]Fix #{i}:[/bold cyan]")
            console.print(f"[dim]File:[/dim] {fix.file_path}")
            console.print(f"[dim]Line:[/dim] {fix.line_number}")
            console.print(f"[dim]Type:[/dim] {fix.vulnerability_type}")
            console.print(f"[dim]Confidence:[/dim] {fix.confidence:.0%}")
            
            console.print(f"\n[red]Original:[/red]")
            console.print(f"[dim]{fix.original_code}[/dim]")
            
            console.print(f"\n[green]Fixed:[/green]")
            console.print(f"[bold]{fix.fixed_code}[/bold]")
            
            console.print(f"\n[blue]Explanation:[/blue]")
            console.print(f"{fix.explanation}")
            
            if i < len(fixes):
                console.print("[dim]" + "─" * 60 + "[/dim]")

def save_results_to_file(findings, fixes, stats, output_path):
    """Save scan results to JSON file"""
    try:
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'total_fixes': len(fixes),
            'findings': findings,
            'fixes': [
                {
                    'vulnerability_type': fix.vulnerability_type,
                    'original_code': fix.original_code,
                    'fixed_code': fix.fixed_code,
                    'explanation': fix.explanation,
                    'confidence': fix.confidence,
                    'file_path': fix.file_path,
                    'line_number': fix.line_number
                }
                for fix in fixes
            ],
            'statistics': stats
        }
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        console.print(f"\n[green]✅ Results saved to {output_path}[/green]")
        
    except Exception as e:
        console.print(f"\n[red]❌ Failed to save results: {e}[/red]")

def generate_pdf_report_cli(findings, fixes, stats, scan_path):
    """Generate PDF report from CLI"""
    try:
        pdf_generator = PDFReportGenerator()
        
        # Convert fixes to dict format
        fixes_dict = [
            {
                'vulnerability_type': fix.vulnerability_type,
                'original_code': fix.original_code,
                'fixed_code': fix.fixed_code,
                'explanation': fix.explanation,
                'confidence': fix.confidence,
                'file_path': fix.file_path,
                'line_number': fix.line_number
            }
            for fix in fixes
        ]
        
        report_path = pdf_generator.generate_report(
            findings=findings,
            fixes=fixes_dict,
            scan_metadata={
                'scan_id': f"cli_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'scan_path': scan_path,
                'total_files': stats.get('total_files', 0)
            }
        )
        
        console.print(f"\n[green]📄 PDF report generated: {report_path}[/green]")
        
    except Exception as e:
        console.print(f"\n[red]❌ Failed to generate PDF report: {e}[/red]")

@cli.command()
@click.argument('config_file', type=click.Path())
def init_config(config_file):
    """Initialize a configuration file"""
    config = {
        "scan_options": {
            "include_secrets": True,
            "include_dependencies": True,
            "include_ai_patterns": True,
            "generate_fixes": True,
            "generate_pdf": False
        },
        "file_filters": {
            "max_file_size": "5MB",
            "excluded_directories": [
                ".git", "node_modules", "__pycache__", ".venv", "venv"
            ],
            "excluded_extensions": [
                ".log", ".tmp", ".cache"
            ]
        },
        "severity_thresholds": {
            "fail_on_critical": True,
            "fail_on_high": False,
            "min_confidence": 0.7
        }
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        console.print(f"[green]✅ Configuration file created: {config_file}[/green]")
        console.print("Edit this file to customize your scan settings.")
        
    except Exception as e:
        console.print(f"[red]❌ Failed to create config file: {e}[/red]")

@cli.command()
def version():
    """Show version information"""
    console.print(Panel.fit(
        "[bold blue]ByteGuardX v1.0.0[/bold blue]\n"
        "AI-Powered Vulnerability Scanner\n"
        "Built with ❤️ for developers and security teams",
        border_style="blue"
    ))

if __name__ == '__main__':
    cli()
