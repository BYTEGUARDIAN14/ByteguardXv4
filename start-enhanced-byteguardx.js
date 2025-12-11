#!/usr/bin/env node

/**
 * Enhanced ByteGuardX Startup Script
 * Launches the complete enhanced security platform with all advanced features
 */

const { spawn, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const open = require('open');

// Configuration
const config = {
  frontend: {
    port: 5173,
    command: 'npm run dev',
    path: '.',
    url: 'http://localhost:5173'
  },
  backend: {
    port: 5000,
    command: 'python app.py',
    path: './byteguardx',
    url: 'http://localhost:5000'
  },
  enhanced: {
    dashboardUrl: 'http://localhost:5173/dashboard/enhanced',
    features: [
      '3D Security Visualization',
      'AI-Powered Conversational Interface',
      'Spatial Design Architecture',
      'Universal Accessibility Features',
      'Quantum Glassmorphism Effects',
      'Real-time Performance Monitoring'
    ]
  }
};

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

// Utility functions
const log = (message, color = 'white') => {
  console.log(`${colors[color]}${message}${colors.reset}`);
};

const logHeader = (title) => {
  const border = '='.repeat(60);
  log(border, 'cyan');
  log(`  ${title}`, 'bright');
  log(border, 'cyan');
};

const logFeature = (feature, status = 'enabled') => {
  const icon = status === 'enabled' ? '✅' : '❌';
  log(`  ${icon} ${feature}`, status === 'enabled' ? 'green' : 'red');
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Check if port is available
const checkPort = (port) => {
  return new Promise((resolve) => {
    const { exec } = require('child_process');
    exec(`netstat -an | find ":${port}"`, (error, stdout) => {
      resolve(!stdout.includes(`:${port}`));
    });
  });
};

// Install dependencies if needed
const installDependencies = async () => {
  log('🔍 Checking dependencies...', 'yellow');
  
  const packageJsonPath = path.join(__dirname, 'package.json');
  const nodeModulesPath = path.join(__dirname, 'node_modules');
  
  if (!fs.existsSync(nodeModulesPath)) {
    log('📦 Installing frontend dependencies...', 'yellow');
    
    return new Promise((resolve, reject) => {
      const install = spawn('npm', ['install'], { 
        stdio: 'inherit',
        shell: true,
        cwd: __dirname
      });
      
      install.on('close', (code) => {
        if (code === 0) {
          log('✅ Frontend dependencies installed successfully!', 'green');
          resolve();
        } else {
          log('❌ Failed to install frontend dependencies', 'red');
          reject(new Error('Dependency installation failed'));
        }
      });
    });
  } else {
    log('✅ Dependencies already installed', 'green');
  }
};

// Start backend server
const startBackend = async () => {
  log('🚀 Starting ByteGuardX Backend...', 'blue');
  
  const backendPath = path.join(__dirname, config.backend.path);
  
  if (!fs.existsSync(backendPath)) {
    log('⚠️  Backend directory not found, skipping backend startup', 'yellow');
    return null;
  }
  
  const backend = spawn('python', ['app.py'], {
    cwd: backendPath,
    stdio: 'pipe',
    shell: true
  });
  
  backend.stdout.on('data', (data) => {
    const output = data.toString().trim();
    if (output) {
      log(`[Backend] ${output}`, 'dim');
    }
  });
  
  backend.stderr.on('data', (data) => {
    const output = data.toString().trim();
    if (output && !output.includes('WARNING')) {
      log(`[Backend Error] ${output}`, 'red');
    }
  });
  
  // Wait for backend to start
  await sleep(3000);
  log('✅ Backend server started', 'green');
  
  return backend;
};

// Start frontend server
const startFrontend = async () => {
  log('🎨 Starting Enhanced Frontend...', 'magenta');
  
  const frontend = spawn('npm', ['run', 'dev'], {
    stdio: 'pipe',
    shell: true,
    cwd: __dirname
  });
  
  frontend.stdout.on('data', (data) => {
    const output = data.toString().trim();
    if (output) {
      log(`[Frontend] ${output}`, 'dim');
    }
  });
  
  frontend.stderr.on('data', (data) => {
    const output = data.toString().trim();
    if (output && !output.includes('WARNING')) {
      log(`[Frontend] ${output}`, 'yellow');
    }
  });
  
  // Wait for frontend to start
  await sleep(5000);
  log('✅ Enhanced frontend server started', 'green');
  
  return frontend;
};

// Display enhanced features
const displayEnhancedFeatures = () => {
  logHeader('🌟 BYTEGUARDX ENHANCED FEATURES');
  
  config.enhanced.features.forEach(feature => {
    logFeature(feature, 'enabled');
  });
  
  log('', 'white');
  log('🎯 Enhanced Dashboard URL:', 'cyan');
  log(`   ${config.enhanced.dashboardUrl}`, 'bright');
  log('', 'white');
};

// Open browser
const openBrowser = async () => {
  log('🌐 Opening Enhanced Dashboard...', 'cyan');
  
  try {
    await sleep(2000); // Wait a bit more for everything to load
    await open(config.enhanced.dashboardUrl);
    log('✅ Browser opened successfully', 'green');
  } catch (error) {
    log('⚠️  Could not open browser automatically', 'yellow');
    log(`   Please open: ${config.enhanced.dashboardUrl}`, 'white');
  }
};

// Cleanup function
const cleanup = (processes) => {
  log('\n🛑 Shutting down ByteGuardX Enhanced...', 'yellow');
  
  processes.forEach(process => {
    if (process && !process.killed) {
      process.kill('SIGTERM');
    }
  });
  
  log('✅ Cleanup completed', 'green');
  process.exit(0);
};

// Main startup function
const main = async () => {
  try {
    // Display startup banner
    logHeader('🚀 BYTEGUARDX ENHANCED STARTUP');
    log('Next-Generation Security Platform with Advanced UI/UX', 'bright');
    log('', 'white');
    
    // Check and install dependencies
    await installDependencies();
    
    // Check port availability
    const frontendPortAvailable = await checkPort(config.frontend.port);
    const backendPortAvailable = await checkPort(config.backend.port);
    
    if (!frontendPortAvailable) {
      log(`❌ Port ${config.frontend.port} is already in use`, 'red');
      log('   Please stop the existing process or change the port', 'white');
      process.exit(1);
    }
    
    // Start services
    const processes = [];
    
    // Start backend (optional)
    const backend = await startBackend();
    if (backend) processes.push(backend);
    
    // Start frontend
    const frontend = await startFrontend();
    processes.push(frontend);
    
    // Display enhanced features
    displayEnhancedFeatures();
    
    // Setup cleanup handlers
    process.on('SIGINT', () => cleanup(processes));
    process.on('SIGTERM', () => cleanup(processes));
    process.on('exit', () => cleanup(processes));
    
    // Open browser
    await openBrowser();
    
    // Display success message
    logHeader('🎉 BYTEGUARDX ENHANCED IS READY!');
    log('Enhanced Security Dashboard Features:', 'green');
    log('  • 3D Network Topology Visualization', 'white');
    log('  • AI-Powered Security Assistant', 'white');
    log('  • Spatial Design with Gesture Navigation', 'white');
    log('  • Universal Accessibility Features', 'white');
    log('  • Quantum Glassmorphism Effects', 'white');
    log('  • Real-time Performance Monitoring', 'white');
    log('', 'white');
    log('🔗 Access URLs:', 'cyan');
    log(`   Enhanced Dashboard: ${config.enhanced.dashboardUrl}`, 'bright');
    log(`   Standard Dashboard: ${config.frontend.url}/dashboard`, 'white');
    if (backend) {
      log(`   Backend API: ${config.backend.url}`, 'white');
    }
    log('', 'white');
    log('Press Ctrl+C to stop all services', 'dim');
    
    // Keep the process running
    process.stdin.resume();
    
  } catch (error) {
    log(`❌ Startup failed: ${error.message}`, 'red');
    process.exit(1);
  }
};

// Run the startup script
if (require.main === module) {
  main();
}

module.exports = { main, config };
