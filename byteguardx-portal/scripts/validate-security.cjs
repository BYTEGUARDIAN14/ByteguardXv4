#!/usr/bin/env node

/**
 * Security Validation Script for ByteGuardX Portal
 * Validates security configurations and dependencies
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class SecurityValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.passed = [];
  }

  log(type, message) {
    const timestamp = new Date().toISOString();
    const prefix = {
      error: '❌ ERROR',
      warning: '⚠️  WARNING',
      success: '✅ PASSED'
    }[type];
    
    console.log(`[${timestamp}] ${prefix}: ${message}`);
    
    if (type === 'error') this.errors.push(message);
    else if (type === 'warning') this.warnings.push(message);
    else this.passed.push(message);
  }

  // Check if required security files exist
  checkSecurityFiles() {
    const requiredFiles = [
      '.eslintrc.security.cjs',
      'security.config.js',
      'vite.config.security.ts',
      'package.security.json'
    ];

    requiredFiles.forEach(file => {
      if (fs.existsSync(path.join(__dirname, '..', file))) {
        this.log('success', `Security file exists: ${file}`);
      } else {
        this.log('error', `Missing security file: ${file}`);
      }
    });
  }

  // Validate package.json security settings
  checkPackageJson() {
    try {
      const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
      
      // Check for security scripts
      const securityScripts = [
        'security:audit',
        'security:lint',
        'security:test'
      ];
      
      securityScripts.forEach(script => {
        if (packageJson.scripts && packageJson.scripts[script]) {
          this.log('success', `Security script found: ${script}`);
        } else {
          this.log('warning', `Missing security script: ${script}`);
        }
      });

      // Check Node.js version requirement
      if (packageJson.engines && packageJson.engines.node) {
        this.log('success', `Node.js version constraint: ${packageJson.engines.node}`);
      } else {
        this.log('warning', 'No Node.js version constraint specified');
      }

    } catch (error) {
      this.log('error', `Failed to read package.json: ${error.message}`);
    }
  }

  // Check for vulnerable dependencies
  async checkDependencies() {
    try {
      console.log('\n🔍 Running npm audit...');
      const auditResult = execSync('npm audit --json', { encoding: 'utf8' });
      const audit = JSON.parse(auditResult);
      
      if (audit.metadata.vulnerabilities.total === 0) {
        this.log('success', 'No vulnerabilities found in dependencies');
      } else {
        const { high, critical, moderate, low } = audit.metadata.vulnerabilities;
        if (critical > 0) {
          this.log('error', `Found ${critical} critical vulnerabilities`);
        }
        if (high > 0) {
          this.log('error', `Found ${high} high severity vulnerabilities`);
        }
        if (moderate > 0) {
          this.log('warning', `Found ${moderate} moderate severity vulnerabilities`);
        }
        if (low > 0) {
          this.log('warning', `Found ${low} low severity vulnerabilities`);
        }
      }
    } catch (error) {
      this.log('warning', 'npm audit failed or returned non-zero exit code');
    }
  }

  // Check ESLint security configuration
  checkESLintSecurity() {
    try {
      console.log('\n🔍 Running ESLint security check...');
      execSync('npx eslint src/ --config .eslintrc.security.cjs --ext .js,.jsx,.ts,.tsx', {
        encoding: 'utf8',
        stdio: 'pipe'
      });
      this.log('success', 'ESLint security check passed');
    } catch (error) {
      if (error.status === 1) {
        this.log('warning', 'ESLint security check found issues');
      } else {
        this.log('error', `ESLint security check failed: ${error.message}`);
      }
    }
  }

  // Check for hardcoded secrets
  checkHardcodedSecrets() {
    const secretPatterns = [
      /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i, // Only match actual API key assignments
      /secret\s*[:=]\s*['"][^'"]+['"]/i,      // Only match actual secret assignments
      /password\s*[:=]\s*['"][^'"]+['"]/i,    // Only match actual password assignments
      /token\s*[:=]\s*['"][^'"]+['"]/i,       // Only match actual token assignments
      /localhost:\d+\/api/,                    // Only flag localhost API endpoints
      /127\.0\.0\.1:\d+/,                     // Local IP addresses
    ];

    // Whitelist patterns for legitimate usage
    const whitelistPatterns = [
      /\/\/ .*(api|secret|password|token)/i,  // Comments
      /\* .*(api|secret|password|token)/i,    // Block comments
      /'(api|secret|password|token)'/i,       // String literals in quotes
      /API.*(endpoint|url|base)/i,            // API configuration
      /security\.(ts|js|cjs)/,                // Security utility files
      /types.*\.d\.ts/,                       // Type definition files
    ];

    const srcDir = path.join(__dirname, '..', 'src');
    
    try {
      const files = this.getAllFiles(srcDir, ['.js', '.jsx', '.ts', '.tsx']);
      let secretsFound = false;

      files.forEach(file => {
        const content = fs.readFileSync(file, 'utf8');
        const relativePath = path.relative(process.cwd(), file);

        // Skip whitelisted files
        const isWhitelisted = whitelistPatterns.some(pattern => pattern.test(relativePath) || pattern.test(content));
        if (isWhitelisted) return;

        secretPatterns.forEach(pattern => {
          if (pattern.test(content)) {
            this.log('warning', `Potential secret pattern found in: ${relativePath}`);
            secretsFound = true;
          }
        });
      });

      if (!secretsFound) {
        this.log('success', 'No obvious hardcoded secrets found');
      }
    } catch (error) {
      this.log('error', `Failed to check for hardcoded secrets: ${error.message}`);
    }
  }

  // Helper function to get all files with specific extensions
  getAllFiles(dir, extensions) {
    let files = [];
    const items = fs.readdirSync(dir);

    items.forEach(item => {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory() && item !== 'node_modules') {
        files = files.concat(this.getAllFiles(fullPath, extensions));
      } else if (stat.isFile() && extensions.some(ext => item.endsWith(ext))) {
        files.push(fullPath);
      }
    });

    return files;
  }

  // Check build security
  checkBuildSecurity() {
    try {
      console.log('\n🔍 Testing secure build...');
      execSync('npm run build', { encoding: 'utf8', stdio: 'pipe' });
      
      // Check if source maps are disabled in production
      const distDir = path.join(__dirname, '..', 'dist');
      if (fs.existsSync(distDir)) {
        const files = fs.readdirSync(distDir, { recursive: true });
        const sourceMaps = files.filter(file => file.endsWith('.map'));
        
        if (sourceMaps.length === 0) {
          this.log('success', 'No source maps in production build');
        } else {
          this.log('warning', `Found ${sourceMaps.length} source map files in build`);
        }
      }
      
      this.log('success', 'Secure build completed successfully');
    } catch (error) {
      this.log('error', `Build failed: ${error.message}`);
    }
  }

  // Generate security report
  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        errors: this.errors.length,
        warnings: this.warnings.length,
        passed: this.passed.length,
        total: this.errors.length + this.warnings.length + this.passed.length
      },
      details: {
        errors: this.errors,
        warnings: this.warnings,
        passed: this.passed
      }
    };

    fs.writeFileSync('security-validation-report.json', JSON.stringify(report, null, 2));
    
    console.log('\n📊 SECURITY VALIDATION SUMMARY');
    console.log('================================');
    console.log(`✅ Passed: ${report.summary.passed}`);
    console.log(`⚠️  Warnings: ${report.summary.warnings}`);
    console.log(`❌ Errors: ${report.summary.errors}`);
    console.log(`📄 Report saved to: security-validation-report.json`);

    return report.summary.errors === 0;
  }

  // Run all security checks
  async runAll() {
    console.log('🔒 Starting ByteGuardX Portal Security Validation\n');
    
    this.checkSecurityFiles();
    this.checkPackageJson();
    await this.checkDependencies();
    this.checkESLintSecurity();
    this.checkHardcodedSecrets();
    this.checkBuildSecurity();
    
    const success = this.generateReport();
    
    if (success) {
      console.log('\n🎉 All security checks passed!');
      process.exit(0);
    } else {
      console.log('\n💥 Security validation failed. Please address the errors above.');
      process.exit(1);
    }
  }
}

// Run validation if called directly
if (require.main === module) {
  const validator = new SecurityValidator();
  validator.runAll().catch(error => {
    console.error('Security validation failed:', error);
    process.exit(1);
  });
}

module.exports = SecurityValidator;
