#!/bin/bash

echo "========================================"
echo "   ByteGuardX Local Development Runner"
echo "========================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python is not installed or not in PATH"
        echo "Please install Python 3.8+ from https://python.org"
        exit 1
    else
        PYTHON_CMD="python"
    fi
else
    PYTHON_CMD="python3"
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js is not installed or not in PATH"
    echo "Please install Node.js from https://nodejs.org"
    exit 1
fi

echo "Starting ByteGuardX Enhanced Scanning System..."
echo

# Make the script executable
chmod +x run_byteguardx_local.py

# Run the Python startup script
$PYTHON_CMD run_byteguardx_local.py
