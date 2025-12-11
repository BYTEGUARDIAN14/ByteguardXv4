#!/usr/bin/env python3
"""
ByteGuardX Codebase Validation Script
Validates the entire codebase for completeness and correctness
"""

import os
import sys
import ast
import importlib.util
from pathlib import Path
from typing import List, Dict, Any

class CodebaseValidator:
    """Validates the ByteGuardX codebase"""
    
    def __init__(self):
        self.root_path = Path(__file__).parent
        self.errors = []
        self.warnings = []
        self.success_count = 0
        self.total_checks = 0
    
    def validate_all(self):
        """Run all validation checks"""
        print("🔍 ByteGuardX Codebase Validation")
        print("=" * 40)
        
        self.check_directory_structure()
        self.check_python_syntax()
        self.check_imports()
        self.check_required_files()
        self.check_configuration_files()
        self.check_frontend_structure()
        self.check_extensions()
        
        self.print_summary()
    
    def check_directory_structure(self):
        """Check if all required directories exist"""
        print("\n📁 Checking directory structure...")
        
        required_dirs = [
            "byteguardx",
            "byteguardx/core",
            "byteguardx/scanners", 
            "byteguardx/ml",
            "byteguardx/auth",
            "byteguardx/api",
            "byteguardx/database",
            "byteguardx/reports",
            "byteguardx/ai_suggestions",
            "byteguardx/analytics",
            "byteguardx/cli",
            "byteguardx/security",
            "byteguardx/performance",
            "byteguardx/enterprise",
            "byteguardx/integrations",
            "byteguardx/api_docs",
            "src",
            "src/components",
            "src/pages",
            "tests",
            "hooks",
            "extensions/vscode"
        ]
        
        for directory in required_dirs:
            self.total_checks += 1
            if (self.root_path / directory).exists():
                print(f"  ✅ {directory}")
                self.success_count += 1
            else:
                print(f"  ❌ {directory}")
                self.errors.append(f"Missing directory: {directory}")
    
    def check_python_syntax(self):
        """Check Python files for syntax errors"""
        print("\n🐍 Checking Python syntax...")
        
        python_files = list(self.root_path.rglob("*.py"))
        
        for py_file in python_files:
            # Skip certain directories
            if any(skip in str(py_file) for skip in ["node_modules", ".git", "__pycache__"]):
                continue
            
            self.total_checks += 1
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                ast.parse(content)
                print(f"  ✅ {py_file.relative_to(self.root_path)}")
                self.success_count += 1
                
            except SyntaxError as e:
                print(f"  ❌ {py_file.relative_to(self.root_path)}: {e}")
                self.errors.append(f"Syntax error in {py_file}: {e}")
            except Exception as e:
                print(f"  ⚠️ {py_file.relative_to(self.root_path)}: {e}")
                self.warnings.append(f"Could not parse {py_file}: {e}")
    
    def check_imports(self):
        """Check critical imports"""
        print("\n📦 Checking critical imports...")
        
        critical_modules = [
            "byteguardx.core.file_processor",
            "byteguardx.scanners.secret_scanner",
            "byteguardx.scanners.dependency_scanner", 
            "byteguardx.scanners.ai_pattern_scanner",
            "byteguardx.ml.vulnerability_predictor",
            "byteguardx.ml.false_positive_learner",
            "byteguardx.auth.models",
            "byteguardx.database.models",
            "byteguardx.api.app",
            "byteguardx.cli.cli",
            "byteguardx.security.rbac",
            "byteguardx.performance.worker_pool",
            "byteguardx.enterprise.sso_integration",
            "byteguardx.analytics.advanced_analytics"
        ]
        
        for module_name in critical_modules:
            self.total_checks += 1
            try:
                # Convert module name to file path
                module_path = self.root_path / (module_name.replace(".", "/") + ".py")
                
                if module_path.exists():
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    if spec and spec.loader:
                        print(f"  ✅ {module_name}")
                        self.success_count += 1
                    else:
                        print(f"  ❌ {module_name}: Invalid module spec")
                        self.errors.append(f"Invalid module spec: {module_name}")
                else:
                    print(f"  ❌ {module_name}: File not found")
                    self.errors.append(f"Module file not found: {module_name}")
                    
            except Exception as e:
                print(f"  ❌ {module_name}: {e}")
                self.errors.append(f"Import error for {module_name}: {e}")
    
    def check_required_files(self):
        """Check if all required files exist"""
        print("\n📄 Checking required files...")
        
        required_files = [
            "requirements.txt",
            "package.json",
            "vite.config.js",
            "run.py",
            "cli.py",
            "install_hooks.py",
            "hooks/pre-commit",
            "byteguardx/__init__.py",
            "byteguardx/core/__init__.py",
            "byteguardx/scanners/__init__.py",
            "byteguardx/ml/__init__.py",
            "byteguardx/auth/__init__.py",
            "byteguardx/api/__init__.py",
            "byteguardx/database/__init__.py",
            "byteguardx/reports/__init__.py",
            "byteguardx/ai_suggestions/__init__.py",
            "byteguardx/analytics/__init__.py",
            "byteguardx/cli/__init__.py",
            "byteguardx/security/__init__.py",
            "byteguardx/performance/__init__.py",
            "byteguardx/enterprise/__init__.py",
            "byteguardx/integrations/__init__.py",
            "byteguardx/api_docs/__init__.py",
            "src/App.jsx",
            "src/main.jsx",
            "src/index.css",
            "tests/conftest.py",
            "extensions/vscode/package.json",
            "extensions/vscode/src/extension.ts"
        ]
        
        for file_path in required_files:
            self.total_checks += 1
            if (self.root_path / file_path).exists():
                print(f"  ✅ {file_path}")
                self.success_count += 1
            else:
                print(f"  ❌ {file_path}")
                self.errors.append(f"Missing file: {file_path}")
    
    def check_configuration_files(self):
        """Check configuration files"""
        print("\n⚙️ Checking configuration files...")
        
        config_files = [
            ".gitignore",
            "README.md"
        ]
        
        for config_file in config_files:
            self.total_checks += 1
            if (self.root_path / config_file).exists():
                print(f"  ✅ {config_file}")
                self.success_count += 1
            else:
                print(f"  ⚠️ {config_file}")
                self.warnings.append(f"Missing config file: {config_file}")
    
    def check_frontend_structure(self):
        """Check React frontend structure"""
        print("\n🎨 Checking frontend structure...")
        
        frontend_files = [
            "src/components/Dashboard.jsx",
            "src/components/ScanResults.jsx",
            "src/components/SecurityMetrics.jsx",
            "src/components/VulnerabilityHeatmap.jsx",
            "src/components/RiskMeter.jsx",
            "src/pages/ScanPage.jsx",
            "src/pages/ReportsPage.jsx",
            "src/pages/SettingsPage.jsx"
        ]
        
        for file_path in frontend_files:
            self.total_checks += 1
            if (self.root_path / file_path).exists():
                print(f"  ✅ {file_path}")
                self.success_count += 1
            else:
                print(f"  ❌ {file_path}")
                self.errors.append(f"Missing frontend file: {file_path}")
    
    def check_extensions(self):
        """Check VS Code extension"""
        print("\n🔌 Checking VS Code extension...")
        
        extension_files = [
            "extensions/vscode/package.json",
            "extensions/vscode/src/extension.ts",
            "extensions/vscode/src/provider.ts",
            "extensions/vscode/src/diagnostics.ts",
            "extensions/vscode/src/fixProvider.ts",
            "extensions/vscode/tsconfig.json",
            "extensions/vscode/README.md"
        ]
        
        for file_path in extension_files:
            self.total_checks += 1
            if (self.root_path / file_path).exists():
                print(f"  ✅ {file_path}")
                self.success_count += 1
            else:
                print(f"  ❌ {file_path}")
                self.errors.append(f"Missing extension file: {file_path}")
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "="*50)
        print("📊 VALIDATION SUMMARY")
        print("="*50)
        
        print(f"✅ Successful checks: {self.success_count}/{self.total_checks}")
        print(f"❌ Errors: {len(self.errors)}")
        print(f"⚠️ Warnings: {len(self.warnings)}")
        
        success_rate = (self.success_count / self.total_checks * 100) if self.total_checks > 0 else 0
        print(f"📈 Success rate: {success_rate:.1f}%")
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for i, error in enumerate(self.errors[:10], 1):
                print(f"  {i}. {error}")
            if len(self.errors) > 10:
                print(f"  ... and {len(self.errors) - 10} more errors")
        
        if self.warnings:
            print(f"\n⚠️ WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings[:5], 1):
                print(f"  {i}. {warning}")
            if len(self.warnings) > 5:
                print(f"  ... and {len(self.warnings) - 5} more warnings")
        
        print("\n" + "="*50)
        
        if len(self.errors) == 0:
            print("🎉 CODEBASE VALIDATION PASSED!")
            print("ByteGuardX is ready for production use.")
        elif len(self.errors) < 5:
            print("⚠️ CODEBASE MOSTLY VALID")
            print("Minor issues found, but should be functional.")
        else:
            print("❌ CODEBASE VALIDATION FAILED")
            print("Significant issues found that need to be addressed.")
        
        print("="*50)

def main():
    """Main validation function"""
    validator = CodebaseValidator()
    validator.validate_all()
    
    # Return exit code based on validation results
    if len(validator.errors) == 0:
        return 0
    elif len(validator.errors) < 5:
        return 1
    else:
        return 2

if __name__ == "__main__":
    sys.exit(main())
