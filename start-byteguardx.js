#!/usr/bin/env node

/**
 * ByteGuardX Enterprise Security Platform Startup Script
 * Cross-platform Node.js version
 */

import { spawn, exec } from 'child_process';
import http from 'http';
import open from 'open';

console.log('\n========================================');
console.log('   ByteGuardX Enterprise Security Platform');
console.log('========================================\n');

// Set environment variables
process.env.FLASK_ENV = 'development';
process.env.NODE_ENV = 'development';
process.env.BYTEGUARDX_ENV = 'development';

let backendProcess = null;
let frontendProcess = null;

// Function to check if service is ready
function waitForService(url, serviceName, maxAttempts = 15) {
    return new Promise((resolve) => {
        let attempts = 0;

        const checkService = () => {
            attempts++;

            const req = http.get(url, (res) => {
                if (res.statusCode === 200 || res.statusCode === 404) {
                    console.log(`✅ ${serviceName} is ready!`);
                    resolve(true);
                } else {
                    if (attempts < maxAttempts) {
                        setTimeout(checkService, 1000);
                    } else {
                        console.log(`❌ ${serviceName} failed to start`);
                        resolve(false);
                    }
                }
            });

            req.on('error', () => {
                if (attempts < maxAttempts) {
                    process.stdout.write('.');
                    setTimeout(checkService, 1000);
                } else {
                    console.log(`\n❌ ${serviceName} failed to start`);
                    resolve(false);
                }
            });
        };

        console.log(`Waiting for ${serviceName} to be ready...`);
        checkService();
    });
}

// Function to kill processes on exit
function cleanup() {
    console.log('\nStopping ByteGuardX servers...');
    
    if (backendProcess) {
        backendProcess.kill('SIGTERM');
        console.log('✅ Backend server stopped');
    }
    
    if (frontendProcess) {
        frontendProcess.kill('SIGTERM');
        console.log('✅ Frontend server stopped');
    }
    
    // Kill any remaining processes
    if (process.platform === 'win32') {
        exec('taskkill /f /im python.exe 2>nul', () => {});
        exec('taskkill /f /im node.exe /fi "COMMANDLINE eq *vite*" 2>nul', () => {});
    } else {
        exec('pkill -f "python.*byteguardx"', () => {});
        exec('pkill -f "node.*vite"', () => {});
    }
    
    console.log('\nByteGuardX stopped successfully!');
    process.exit(0);
}

// Handle process termination
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
process.on('exit', cleanup);

async function startByteGuardX() {
    try {
        // Start backend server
        console.log('[1/3] Starting Backend API Server...');
        
        backendProcess = spawn('python', ['-m', 'byteguardx.api.app'], {
            stdio: ['ignore', 'pipe', 'pipe'],
            env: process.env
        });
        
        backendProcess.stdout.on('data', (data) => {
            if (data.toString().includes('Running on')) {
                console.log('Backend server output:', data.toString().trim());
            }
        });
        
        backendProcess.stderr.on('data', (data) => {
            const output = data.toString();
            if (!output.includes('WARNING') && !output.includes('INFO')) {
                console.error('Backend error:', output);
            }
        });
        
        // Wait for backend to be ready
        const backendReady = await waitForService('http://localhost:5000/health', 'Backend API');
        if (!backendReady) {
            console.log('Failed to start backend. Exiting...');
            process.exit(1);
        }
        
        // Start frontend server
        console.log('\n[2/3] Starting Frontend Development Server...');
        
        frontendProcess = spawn('npm', ['run', 'dev'], {
            stdio: ['ignore', 'pipe', 'pipe'],
            env: process.env,
            shell: true
        });
        
        let frontendReady = false;

        frontendProcess.stdout.on('data', (data) => {
            const output = data.toString();
            if (output.includes('Local:') || output.includes('ready in')) {
                console.log('Frontend server output:', output.trim());
                frontendReady = true;
            }
        });
        
        frontendProcess.stderr.on('data', (data) => {
            const output = data.toString();
            if (!output.includes('WARNING') && !output.includes('INFO')) {
                console.error('Frontend error:', output);
            }
        });
        
        // Wait for frontend to be ready (check Vite output)
        let attempts = 0;
        while (!frontendReady && attempts < 30) {
            await new Promise(resolve => setTimeout(resolve, 1000));
            attempts++;
        }

        if (frontendReady) {
            console.log('✅ Frontend Server is ready! (Vite started successfully)');
        } else {
            console.log('⚠️  Frontend may not be fully ready, but continuing...');
        }
        
        // Open application in browser
        console.log('\n[3/3] Opening ByteGuardX Application...');
        
        setTimeout(async () => {
            try {
                await open('http://localhost:3000');
            } catch (error) {
                console.log('Could not open browser automatically. Please visit: http://localhost:3000');
            }
        }, 2000);
        
        // Display success message
        console.log('\n========================================');
        console.log('   ByteGuardX is now running locally!');
        console.log('========================================\n');
        console.log('🌐 Frontend:  http://localhost:3000');
        console.log('🔧 Backend:   http://localhost:5000');
        console.log('📊 Health:    http://localhost:5000/health\n');
        console.log('🧪 Test Pages:');
        console.log('   • Main App:        http://localhost:3000');
        console.log('   • Connection Test: http://localhost:3000/test-connection.html');
        console.log('   • Signup Test:     http://localhost:3000/test-signup.html');
        console.log('   • CSRF Test:       http://localhost:3000/test-csrf.html\n');
        console.log('Press Ctrl+C to stop all servers...\n');
        
        // Keep the process running
        setInterval(() => {
            // Check if processes are still running
            if (backendProcess && backendProcess.killed) {
                console.log('❌ Backend process died unexpectedly');
                cleanup();
            }
            if (frontendProcess && frontendProcess.killed) {
                console.log('❌ Frontend process died unexpectedly');
                cleanup();
            }
        }, 5000);
        
    } catch (error) {
        console.error('Error starting ByteGuardX:', error);
        cleanup();
        process.exit(1);
    }
}

// Start the application
startByteGuardX();
