#!/bin/bash

# ByteGuardX One-Click Setup Script
# This script sets up ByteGuardX with all dependencies and runs the first scan

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    if command_exists pip3; then
        pip3 install --upgrade pip
        pip3 install -r requirements.txt
    elif command_exists pip; then
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        print_error "pip not found. Please install Python and pip first."
        exit 1
    fi
}

# Function to install Node.js dependencies
install_node_deps() {
    print_status "Installing Node.js dependencies..."
    
    if command_exists npm; then
        npm install
    elif command_exists yarn; then
        yarn install
    else
        print_warning "npm/yarn not found. Skipping frontend dependencies."
        print_warning "You can install Node.js later to use the web interface."
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p data/{logs,audit_logs,secure,rate_limits,plugins,backups}
    mkdir -p reports/output
    mkdir -p temp
    
    print_success "Directories created successfully"
}

# Function to set up configuration
setup_config() {
    print_status "Setting up configuration..."
    
    # Copy environment file if it doesn't exist
    if [ ! -f .env ]; then
        if [ -f .env.backend.example ]; then
            cp .env.backend.example .env
            print_success "Environment configuration created from template"
        else
            print_warning "No environment template found. You may need to configure manually."
        fi
    fi
    
    # Generate secret keys if needed
    if command_exists python3; then
        python3 -c "
import secrets
import os

# Generate secret keys
secret_key = secrets.token_urlsafe(32)
jwt_key = secrets.token_urlsafe(32)
master_key = secrets.token_urlsafe(32)

# Update .env file
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        content = f.read()
    
    # Replace placeholder keys
    content = content.replace('your-super-secret-key-change-this-in-production', secret_key)
    content = content.replace('your-jwt-secret-key-change-this', jwt_key)
    content = content.replace('your-base64-encoded-master-key-32-bytes', master_key)
    
    with open('.env', 'w') as f:
        f.write(content)
    
    print('✅ Secret keys generated and configured')
else:
    print('⚠️  No .env file found to update')
"
    fi
}

# Function to run initial database setup
setup_database() {
    print_status "Setting up database..."
    
    if command_exists python3; then
        python3 -c "
try:
    from byteguardx.database.connection_pool import init_db
    init_db('sqlite:///data/byteguardx.db')
    print('✅ Database initialized successfully')
except Exception as e:
    print(f'⚠️  Database setup warning: {e}')
"
    fi
}

# Function to run a test scan
run_test_scan() {
    print_status "Running test scan to verify installation..."
    
    # Create a test file with a simple secret
    mkdir -p test_project
    cat > test_project/test_file.py << 'EOF'
# Test file for ByteGuardX
api_key = "sk_test_1234567890abcdef"
password = "my_secret_password"

def main():
    print("Hello, World!")

if __name__ == "__main__":
    main()
EOF

    # Run the scan
    if command_exists python3; then
        python3 -m byteguardx.cli.cli scan test_project --output test_results.json
        
        if [ -f test_results.json ]; then
            print_success "Test scan completed successfully!"
            print_status "Results saved to test_results.json"
            
            # Show summary
            python3 -c "
import json
try:
    with open('test_results.json', 'r') as f:
        results = json.load(f)
    
    total_findings = len(results.get('findings', []))
    print(f'📊 Found {total_findings} test findings (expected: 2)')
    
    if total_findings >= 2:
        print('✅ ByteGuardX is working correctly!')
    else:
        print('⚠️  Fewer findings than expected. Check configuration.')
        
except Exception as e:
    print(f'⚠️  Could not parse results: {e}')
"
        else
            print_warning "Test scan completed but no results file found"
        fi
    fi
    
    # Cleanup test files
    rm -rf test_project test_results.json
}

# Main installation function
main() {
    echo "🔐 ByteGuardX One-Click Setup"
    echo "=============================="
    echo ""
    
    # Detect OS
    OS=$(detect_os)
    print_status "Detected OS: $OS"
    
    # Check Python
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_status "Python version: $PYTHON_VERSION"
    elif command_exists python; then
        PYTHON_VERSION=$(python --version 2>&1 | cut -d' ' -f2)
        print_status "Python version: $PYTHON_VERSION"
    else
        print_error "Python not found. Please install Python 3.8+ first."
        exit 1
    fi
    
    # Check if we're in the right directory
    if [ ! -f "setup.py" ] || [ ! -f "requirements.txt" ]; then
        print_error "Please run this script from the ByteGuardX root directory"
        exit 1
    fi
    
    echo ""
    print_status "Starting ByteGuardX setup..."
    echo ""
    
    # Step 1: Create directories
    create_directories
    
    # Step 2: Install Python dependencies
    install_python_deps
    
    # Step 3: Install Node.js dependencies (optional)
    install_node_deps
    
    # Step 4: Setup configuration
    setup_config
    
    # Step 5: Setup database
    setup_database
    
    # Step 6: Install ByteGuardX package
    print_status "Installing ByteGuardX package..."
    if command_exists pip3; then
        pip3 install -e .
    else
        pip install -e .
    fi
    print_success "ByteGuardX package installed"
    
    # Step 7: Run test scan
    run_test_scan
    
    echo ""
    echo "🎉 ByteGuardX Setup Complete!"
    echo "=============================="
    echo ""
    echo "Next steps:"
    echo "1. Run 'byteguardx init' for guided setup"
    echo "2. Scan your first project: 'byteguardx scan /path/to/project'"
    echo "3. Start the web interface: 'python run.py'"
    echo "4. View API docs: 'byteguardx --help'"
    echo ""
    echo "For more information, visit: https://docs.byteguardx.com"
    echo ""
}

# Run main function
main "$@"
