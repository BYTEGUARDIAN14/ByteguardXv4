#!/bin/bash
# ByteGuardX Unified Startup Script
# Validates environment and starts the complete stack

echo "🚀 ByteGuardX Unified Startup"
echo "=============================="

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "launch_stack.py" ]; then
    echo "❌ Please run this script from the ByteGuardX root directory"
    exit 1
fi

# Make scripts executable
chmod +x launch_stack.py
chmod +x validate_environment.py
chmod +x security_test_suite.py

echo "🔍 Validating environment..."
python3 validate_environment.py

if [ $? -ne 0 ]; then
    echo "❌ Environment validation failed"
    echo "Please fix the issues above and try again"
    exit 1
fi

echo "✅ Environment validation passed"
echo ""
echo "🚀 Starting ByteGuardX stack..."
echo "Press Ctrl+C to stop all services"
echo ""

# Start the unified stack
python3 launch_stack.py
