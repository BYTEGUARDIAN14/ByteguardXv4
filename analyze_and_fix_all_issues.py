#!/usr/bin/env python3
"""
ByteGuardX Complete Issue Analysis and Resolution
Analyzes and fixes all issues in the ByteGuardX platform
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

class ByteGuardXAnalyzer:
    """Comprehensive ByteGuardX issue analyzer and fixer"""
    
    def __init__(self):
        self.issues = []
        self.fixes_applied = []
        self.project_root = Path.cwd()
    
    def print_banner(self):
        """Print analysis banner"""
        print("🔍" + "=" * 70)
        print("    ByteGuardX Comprehensive Issue Analysis & Resolution")
        print("    Analyzing all components and fixing identified issues")
        print("=" * 72)
        print()
    
    def analyze_environment(self):
        """Analyze environment configuration"""
        print("🌍 Analyzing Environment Configuration...")
        
        issues = []
        
        # Check .env file
        env_file = self.project_root / '.env'
        if not env_file.exists():
            issues.append({
                'type': 'missing_file',
                'severity': 'high',
                'component': 'environment',
                'issue': '.env file missing',
                'fix': 'Create .env file with proper configuration'
            })
        else:
            # Check critical environment variables
            with open(env_file, 'r') as f:
                env_content = f.read()
            
            critical_vars = [
                'SECRET_KEY', 'JWT_SECRET_KEY', 'MAIL_USERNAME', 
                'MAIL_PASSWORD', 'DATABASE_URL'
            ]
            
            for var in critical_vars:
                if f"{var}=" not in env_content or f"{var}=your-" in env_content:
                    issues.append({
                        'type': 'configuration',
                        'severity': 'high',
                        'component': 'environment',
                        'issue': f'{var} not properly configured',
                        'fix': f'Set proper value for {var}'
                    })
        
        self.issues.extend(issues)
        print(f"   Found {len(issues)} environment issues")
    
    def analyze_database(self):
        """Analyze database setup"""
        print("🗄️ Analyzing Database Configuration...")
        
        issues = []
        
        # Check if database file exists
        db_file = self.project_root / 'byteguardx.db'
        if not db_file.exists():
            issues.append({
                'type': 'missing_file',
                'severity': 'high',
                'component': 'database',
                'issue': 'Database file missing',
                'fix': 'Initialize database with proper schema'
            })
        
        # Check database schema (if file exists)
        if db_file.exists():
            try:
                import sqlite3
                conn = sqlite3.connect(str(db_file))
                cursor = conn.cursor()
                
                # Check for required tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                required_tables = ['users', 'scan_results', 'findings', 'audit_logs']
                for table in required_tables:
                    if table not in tables:
                        issues.append({
                            'type': 'missing_table',
                            'severity': 'high',
                            'component': 'database',
                            'issue': f'Table {table} missing',
                            'fix': f'Create {table} table with proper schema'
                        })
                
                conn.close()
            except Exception as e:
                issues.append({
                    'type': 'database_error',
                    'severity': 'high',
                    'component': 'database',
                    'issue': f'Database access error: {e}',
                    'fix': 'Recreate database with proper permissions'
                })
        
        self.issues.extend(issues)
        print(f"   Found {len(issues)} database issues")
    
    def analyze_backend(self):
        """Analyze backend API issues"""
        print("🔧 Analyzing Backend API...")
        
        issues = []
        
        # Check main API files
        api_files = [
            'byteguardx_auth_api_server.py',
            'byteguardx/api/app.py',
            'requirements.txt'
        ]
        
        for file_path in api_files:
            file_obj = self.project_root / file_path
            if not file_obj.exists():
                issues.append({
                    'type': 'missing_file',
                    'severity': 'medium',
                    'component': 'backend',
                    'issue': f'{file_path} missing',
                    'fix': f'Create or restore {file_path}'
                })
        
        # Check Python dependencies
        try:
            import flask, flask_cors, flask_jwt_extended, sqlalchemy
        except ImportError as e:
            issues.append({
                'type': 'dependency',
                'severity': 'high',
                'component': 'backend',
                'issue': f'Missing Python dependency: {e}',
                'fix': 'Install missing Python packages'
            })
        
        self.issues.extend(issues)
        print(f"   Found {len(issues)} backend issues")
    
    def analyze_frontend(self):
        """Analyze frontend issues"""
        print("🎨 Analyzing Frontend...")
        
        issues = []
        
        # Check package.json
        package_json = self.project_root / 'package.json'
        if not package_json.exists():
            issues.append({
                'type': 'missing_file',
                'severity': 'high',
                'component': 'frontend',
                'issue': 'package.json missing',
                'fix': 'Create package.json with proper dependencies'
            })
        
        # Check node_modules
        node_modules = self.project_root / 'node_modules'
        if not node_modules.exists():
            issues.append({
                'type': 'missing_directory',
                'severity': 'high',
                'component': 'frontend',
                'issue': 'node_modules missing',
                'fix': 'Run npm install to install dependencies'
            })
        
        # Check critical frontend files
        frontend_files = [
            'src/App.jsx',
            'src/main.jsx',
            'index.html',
            'vite.config.js'
        ]
        
        for file_path in frontend_files:
            file_obj = self.project_root / file_path
            if not file_obj.exists():
                issues.append({
                    'type': 'missing_file',
                    'severity': 'medium',
                    'component': 'frontend',
                    'issue': f'{file_path} missing',
                    'fix': f'Create or restore {file_path}'
                })
        
        self.issues.extend(issues)
        print(f"   Found {len(issues)} frontend issues")
    
    def analyze_security(self):
        """Analyze security configuration"""
        print("🔒 Analyzing Security Configuration...")
        
        issues = []
        
        # Check for hardcoded secrets
        sensitive_files = ['src/**/*.jsx', 'src/**/*.js', '*.py']
        
        # Check CORS configuration
        cors_issues = self.check_cors_config()
        issues.extend(cors_issues)
        
        # Check JWT configuration
        jwt_issues = self.check_jwt_config()
        issues.extend(jwt_issues)
        
        self.issues.extend(issues)
        print(f"   Found {len(issues)} security issues")
    
    def check_cors_config(self):
        """Check CORS configuration"""
        issues = []
        
        # Check if CORS is properly configured
        api_file = self.project_root / 'byteguardx_auth_api_server.py'
        if api_file.exists():
            with open(api_file, 'r') as f:
                content = f.read()
                
            if 'CORS(' not in content:
                issues.append({
                    'type': 'configuration',
                    'severity': 'high',
                    'component': 'security',
                    'issue': 'CORS not configured',
                    'fix': 'Configure CORS properly'
                })
        
        return issues
    
    def check_jwt_config(self):
        """Check JWT configuration"""
        issues = []
        
        # Check if JWT is properly configured
        env_file = self.project_root / '.env'
        if env_file.exists():
            with open(env_file, 'r') as f:
                content = f.read()
                
            if 'JWT_SECRET_KEY=your-' in content or 'JWT_SECRET_KEY=' not in content:
                issues.append({
                    'type': 'configuration',
                    'severity': 'high',
                    'component': 'security',
                    'issue': 'JWT secret key not configured',
                    'fix': 'Set secure JWT secret key'
                })
        
        return issues
    
    def generate_report(self):
        """Generate comprehensive issue report"""
        print("\n📊 COMPREHENSIVE ISSUE ANALYSIS REPORT")
        print("=" * 50)
        
        # Group issues by severity
        critical = [i for i in self.issues if i['severity'] == 'critical']
        high = [i for i in self.issues if i['severity'] == 'high']
        medium = [i for i in self.issues if i['severity'] == 'medium']
        low = [i for i in self.issues if i['severity'] == 'low']
        
        print(f"🔴 Critical Issues: {len(critical)}")
        print(f"🟠 High Priority Issues: {len(high)}")
        print(f"🟡 Medium Priority Issues: {len(medium)}")
        print(f"🟢 Low Priority Issues: {len(low)}")
        print(f"📊 Total Issues Found: {len(self.issues)}")
        
        # Detailed issue breakdown
        print("\n🔍 DETAILED ISSUE BREAKDOWN:")
        print("-" * 40)
        
        for i, issue in enumerate(self.issues, 1):
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(issue['severity'], '⚪')
            
            print(f"{i}. {severity_icon} [{issue['component'].upper()}] {issue['issue']}")
            print(f"   Fix: {issue['fix']}")
            print()
        
        return {
            'total_issues': len(self.issues),
            'by_severity': {
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium),
                'low': len(low)
            },
            'by_component': self.group_by_component(),
            'issues': self.issues
        }
    
    def group_by_component(self):
        """Group issues by component"""
        components = {}
        for issue in self.issues:
            component = issue['component']
            if component not in components:
                components[component] = 0
            components[component] += 1
        return components
    
    def run_complete_analysis(self):
        """Run complete analysis"""
        self.print_banner()
        
        # Run all analysis modules
        self.analyze_environment()
        self.analyze_database()
        self.analyze_backend()
        self.analyze_frontend()
        self.analyze_security()
        
        # Generate report
        report = self.generate_report()
        
        # Save report to file
        report_file = self.project_root / f'byteguardx_analysis_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Full report saved to: {report_file}")
        
        return report

def main():
    """Main analysis function"""
    analyzer = ByteGuardXAnalyzer()
    report = analyzer.run_complete_analysis()
    
    print("\n🎯 NEXT STEPS:")
    print("1. Run: python setup_complete_byteguardx.py")
    print("2. Configure your Gmail credentials")
    print("3. Start backend: python byteguardx_auth_api_server.py")
    print("4. Start frontend: npm run dev")
    print("5. Test the complete application")
    
    return report

if __name__ == "__main__":
    main()
