"""
ByteGuardX Pre-commit Hook - Block commits with critical security issues
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from byteguardx.core.file_processor import FileProcessor
from byteguardx.scanners.secret_scanner import SecretScanner
from byteguardx.scanners.dependency_scanner import DependencyScanner
from byteguardx.scanners.ai_pattern_scanner import AIPatternScanner

class PreCommitHook:
    """
    Pre-commit hook for ByteGuardX security scanning
    """
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.file_processor = FileProcessor()
        self.secret_scanner = SecretScanner()
        self.dependency_scanner = DependencyScanner()
        self.ai_pattern_scanner = AIPatternScanner()
        
    def _load_config(self, config_path: str = None) -> Dict:
        """Load pre-commit configuration"""
        default_config = {
            "enabled": True,
            "block_on_critical": True,
            "block_on_high": False,
            "scan_secrets": True,
            "scan_dependencies": True,
            "scan_ai_patterns": False,  # Disabled by default for performance
            "max_file_size": 5 * 1024 * 1024,  # 5MB
            "excluded_files": [
                "*.log", "*.tmp", "*.cache", "*.lock",
                "node_modules/*", ".git/*", "__pycache__/*"
            ],
            "whitelist_files": [],  # Files to always allow
            "custom_patterns": {}
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                print(f"Warning: Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _get_staged_files(self) -> List[str]:
        """Get list of staged files from git"""
        try:
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only'],
                capture_output=True,
                text=True,
                check=True
            )
            return [f.strip() for f in result.stdout.splitlines() if f.strip()]
        except subprocess.CalledProcessError:
            print("Error: Failed to get staged files from git")
            return []
    
    def _should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned based on configuration"""
        file_path_obj = Path(file_path)
        
        # Check if file exists
        if not file_path_obj.exists():
            return False
        
        # Check if file is in whitelist
        if any(file_path.endswith(pattern) for pattern in self.config.get("whitelist_files", [])):
            return True
        
        # Check excluded patterns
        for pattern in self.config.get("excluded_files", []):
            if file_path.match(pattern) or file_path_obj.name.endswith(pattern.replace("*", "")):
                return False
        
        # Check file size
        try:
            if file_path_obj.stat().st_size > self.config.get("max_file_size", 5 * 1024 * 1024):
                return False
        except OSError:
            return False
        
        return True
    
    def _scan_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Scan files for security issues"""
        all_findings = []
        
        # Process files
        processed_files = []
        for file_path in file_paths:
            if self._should_scan_file(file_path):
                file_info = self.file_processor.process_file(file_path)
                if 'error' not in file_info:
                    processed_files.append(file_info)
        
        if not processed_files:
            return all_findings
        
        # Secret scanning
        if self.config.get("scan_secrets", True):
            self.secret_scanner.reset()
            for file_info in processed_files:
                findings = self.secret_scanner.scan_file(file_info)
                all_findings.extend(findings)
        
        # Dependency scanning
        if self.config.get("scan_dependencies", True):
            self.dependency_scanner.reset()
            for file_info in processed_files:
                findings = self.dependency_scanner.scan_file(file_info)
                all_findings.extend(findings)
        
        # AI pattern scanning (optional, can be slow)
        if self.config.get("scan_ai_patterns", False):
            self.ai_pattern_scanner.reset()
            for file_info in processed_files:
                findings = self.ai_pattern_scanner.scan_file(file_info)
                all_findings.extend(findings)
        
        return all_findings
    
    def _should_block_commit(self, findings: List[Dict[str, Any]]) -> bool:
        """Determine if commit should be blocked based on findings"""
        if not findings:
            return False
        
        block_on_critical = self.config.get("block_on_critical", True)
        block_on_high = self.config.get("block_on_high", False)
        
        for finding in findings:
            severity = finding.get("severity", "").lower()
            
            if severity == "critical" and block_on_critical:
                return True
            
            if severity == "high" and block_on_high:
                return True
        
        return False
    
    def _format_findings_output(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings for console output"""
        if not findings:
            return "✅ No security issues found in staged files."
        
        output = []
        output.append("🔍 ByteGuardX Security Scan Results:")
        output.append("=" * 50)
        
        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get("severity", "unknown").lower()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Display summary
        total = len(findings)
        critical = len(by_severity.get("critical", []))
        high = len(by_severity.get("high", []))
        medium = len(by_severity.get("medium", []))
        low = len(by_severity.get("low", []))
        
        output.append(f"Total Issues: {total}")
        if critical > 0:
            output.append(f"🔴 Critical: {critical}")
        if high > 0:
            output.append(f"🟡 High: {high}")
        if medium > 0:
            output.append(f"🔵 Medium: {medium}")
        if low > 0:
            output.append(f"⚪ Low: {low}")
        
        output.append("")
        
        # Display critical and high severity issues
        for severity in ["critical", "high"]:
            if severity in by_severity:
                output.append(f"{severity.upper()} ISSUES:")
                output.append("-" * 20)
                
                for finding in by_severity[severity][:5]:  # Limit to 5 per severity
                    file_path = finding.get("file_path", "unknown")
                    line_num = finding.get("line_number", 0)
                    description = finding.get("description", "No description")
                    
                    output.append(f"📁 {Path(file_path).name}:{line_num}")
                    output.append(f"   {description}")
                    
                    if "context" in finding:
                        context = finding["context"][:80] + ("..." if len(finding["context"]) > 80 else "")
                        output.append(f"   Code: {context}")
                    
                    output.append("")
                
                if len(by_severity[severity]) > 5:
                    output.append(f"   ... and {len(by_severity[severity]) - 5} more {severity} issues")
                    output.append("")
        
        return "\n".join(output)
    
    def run(self) -> int:
        """Run the pre-commit hook"""
        if not self.config.get("enabled", True):
            return 0
        
        print("🔍 Running ByteGuardX security scan...")
        
        # Get staged files
        staged_files = self._get_staged_files()
        if not staged_files:
            print("No staged files to scan.")
            return 0
        
        print(f"Scanning {len(staged_files)} staged files...")
        
        # Scan files
        findings = self._scan_files(staged_files)
        
        # Display results
        output = self._format_findings_output(findings)
        print(output)
        
        # Check if commit should be blocked
        if self._should_block_commit(findings):
            print("\n❌ COMMIT BLOCKED: Critical security issues found!")
            print("\nTo proceed:")
            print("1. Fix the critical issues above")
            print("2. Or use 'git commit --no-verify' to bypass this check")
            print("3. Or disable blocking in .byteguardx-precommit.json")
            return 1
        
        if findings:
            print("\n⚠️  Security issues found, but commit is allowed.")
            print("Please review and fix these issues when possible.")
        
        return 0

def install_hook():
    """Install the pre-commit hook"""
    git_dir = Path(".git")
    if not git_dir.exists():
        print("Error: Not in a git repository")
        return False
    
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    
    hook_file = hooks_dir / "pre-commit"
    
    hook_content = f"""#!/usr/bin/env python3
\"\"\"
ByteGuardX Pre-commit Hook
\"\"\"

import sys
from pathlib import Path

# Add ByteGuardX to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from byteguardx.pre_commit import PreCommitHook

if __name__ == "__main__":
    hook = PreCommitHook()
    sys.exit(hook.run())
"""
    
    try:
        with open(hook_file, 'w') as f:
            f.write(hook_content)
        
        # Make executable
        hook_file.chmod(0o755)
        
        print(f"✅ Pre-commit hook installed: {hook_file}")
        
        # Create default config
        config_file = Path(".byteguardx-precommit.json")
        if not config_file.exists():
            default_config = {
                "enabled": True,
                "block_on_critical": True,
                "block_on_high": False,
                "scan_secrets": True,
                "scan_dependencies": True,
                "scan_ai_patterns": False
            }
            
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            print(f"✅ Default config created: {config_file}")
        
        return True
        
    except Exception as e:
        print(f"Error installing hook: {e}")
        return False

def uninstall_hook():
    """Uninstall the pre-commit hook"""
    hook_file = Path(".git/hooks/pre-commit")
    
    if hook_file.exists():
        try:
            hook_file.unlink()
            print("✅ Pre-commit hook uninstalled")
            return True
        except Exception as e:
            print(f"Error uninstalling hook: {e}")
            return False
    else:
        print("No pre-commit hook found")
        return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ByteGuardX Pre-commit Hook")
    parser.add_argument("--install", action="store_true", help="Install the pre-commit hook")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the pre-commit hook")
    parser.add_argument("--config", help="Path to configuration file")
    
    args = parser.parse_args()
    
    if args.install:
        install_hook()
    elif args.uninstall:
        uninstall_hook()
    else:
        # Run the hook
        hook = PreCommitHook(args.config)
        sys.exit(hook.run())
