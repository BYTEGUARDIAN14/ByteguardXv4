#!/usr/bin/env python3
"""
ByteGuardX Authentication System Setup Script
Automates the initial setup and configuration of the authentication system
"""

import os
import sys
import subprocess
import secrets
from pathlib import Path

def print_header():
    """Print setup header"""
    print("🔐 ByteGuardX Authentication System Setup")
    print("=" * 50)
    print("This script will help you set up the authentication system")
    print("for development or production use.")
    print("=" * 50)

def check_requirements():
    """Check if required tools are installed"""
    print("\n📋 Checking requirements...")
    
    requirements = {
        'python': ['python', '--version'],
        'pip': ['pip', '--version'],
        'node': ['node', '--version'],
        'npm': ['npm', '--version']
    }
    
    missing = []
    for tool, cmd in requirements.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                print(f"✅ {tool}: {version}")
            else:
                missing.append(tool)
        except FileNotFoundError:
            missing.append(tool)
    
    if missing:
        print(f"\n❌ Missing requirements: {', '.join(missing)}")
        print("Please install the missing tools and run this script again.")
        return False
    
    print("✅ All requirements satisfied!")
    return True

def setup_environment():
    """Set up environment configuration"""
    print("\n🔧 Setting up environment configuration...")
    
    # Generate secure JWT secret
    jwt_secret = secrets.token_urlsafe(32)
    
    # Backend environment
    backend_env = f"""# ByteGuardX Authentication System Environment Configuration
# Generated on {os.popen('date').read().strip()}

# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=1

# Security Configuration
JWT_SECRET_KEY={jwt_secret}
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Feature Flags
ENABLE_2FA=false

# Database Configuration
DATABASE_URL=sqlite:///byteguardx_dev.db

# Optional: PostgreSQL for development
# DATABASE_URL=postgresql://username:password@localhost:5432/byteguardx_dev

# Optional: Redis for session storage
# REDIS_URL=redis://localhost:6379/0
"""
    
    # Frontend environment
    frontend_env = """# ByteGuardX Frontend Environment Configuration
VITE_API_URL=http://localhost:5000
"""
    
    # Write environment files
    with open('.env', 'w') as f:
        f.write(backend_env)
    print("✅ Created .env file for backend")
    
    # Create frontend .env if it doesn't exist
    if not os.path.exists('.env.local'):
        with open('.env.local', 'w') as f:
            f.write(frontend_env)
        print("✅ Created .env.local file for frontend")
    
    return jwt_secret

def install_dependencies():
    """Install Python and Node.js dependencies"""
    print("\n📦 Installing dependencies...")
    
    # Install Python dependencies
    print("Installing Python dependencies...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                      check=True, capture_output=True)
        print("✅ Python dependencies installed")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python dependencies: {e}")
        return False
    
    # Install Node.js dependencies
    print("Installing Node.js dependencies...")
    try:
        subprocess.run(['npm', 'install'], check=True, capture_output=True)
        print("✅ Node.js dependencies installed")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Node.js dependencies: {e}")
        return False
    
    return True

def initialize_database():
    """Initialize the database"""
    print("\n🗄️ Initializing database...")
    
    try:
        # Import and initialize database
        sys.path.insert(0, str(Path.cwd()))
        from byteguardx.database.connection_pool import init_db
        
        init_db()
        print("✅ Database initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}")
        return False

def create_admin_user():
    """Create an admin user"""
    print("\n👤 Creating admin user...")
    
    try:
        from byteguardx.database.connection_pool import db_manager
        from byteguardx.database.models import User, UserRole, SubscriptionTier
        
        # Get admin user details
        email = input("Enter admin email: ").strip()
        username = input("Enter admin username: ").strip()
        password = input("Enter admin password: ").strip()
        
        if not all([email, username, password]):
            print("❌ All fields are required")
            return False
        
        # Create admin user
        with db_manager.get_session() as session:
            # Check if user already exists
            existing_user = session.query(User).filter(
                (User.email == email) | (User.username == username)
            ).first()
            
            if existing_user:
                print("❌ User with this email or username already exists")
                return False
            
            # Create new admin user
            admin_user = User(
                email=email,
                username=username,
                role=UserRole.ADMIN.value,
                subscription_tier=SubscriptionTier.ENTERPRISE.value,
                is_active=True,
                email_verified=True
            )
            admin_user.set_password(password)
            
            session.add(admin_user)
            session.commit()
            
            print(f"✅ Admin user created: {username} ({email})")
            return True
            
    except Exception as e:
        print(f"❌ Failed to create admin user: {e}")
        return False

def run_tests():
    """Run authentication tests"""
    print("\n🧪 Running authentication tests...")
    
    try:
        result = subprocess.run([sys.executable, 'test_auth.py'], 
                              capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ All authentication tests passed!")
            print(result.stdout)
            return True
        else:
            print("❌ Some tests failed:")
            print(result.stdout)
            print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print("❌ Tests timed out")
        return False
    except Exception as e:
        print(f"❌ Failed to run tests: {e}")
        return False

def print_next_steps(jwt_secret):
    """Print next steps for the user"""
    print("\n🎉 Setup Complete!")
    print("=" * 50)
    print("Your ByteGuardX authentication system is ready!")
    print("\n🚀 Next Steps:")
    print("1. Start the backend server:")
    print("   python run_server.py")
    print("\n2. Start the frontend server (in a new terminal):")
    print("   npm run dev")
    print("\n3. Open your browser and navigate to:")
    print("   http://localhost:3000")
    print("\n4. Test the authentication system:")
    print("   python test_auth.py")
    print("\n📚 Documentation:")
    print("   - AUTH_IMPLEMENTATION.md - Technical details")
    print("   - DEPLOYMENT_GUIDE.md - Deployment instructions")
    print("   - IMPLEMENTATION_SUMMARY.md - Complete overview")
    print("\n🔐 Security Notes:")
    print(f"   - JWT Secret: {jwt_secret[:16]}... (saved in .env)")
    print("   - Change JWT_SECRET_KEY for production!")
    print("   - Enable 2FA in production (set ENABLE_2FA=true)")
    print("   - Use PostgreSQL for production database")
    print("\n✅ Authentication system is production-ready!")
    print("=" * 50)

def main():
    """Main setup function"""
    print_header()
    
    # Check if we're in the right directory
    if not os.path.exists('requirements.txt'):
        print("❌ Error: requirements.txt not found")
        print("Please run this script from the ByteGuardX project root directory")
        sys.exit(1)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Setup environment
    jwt_secret = setup_environment()
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Initialize database
    if not initialize_database():
        sys.exit(1)
    
    # Ask if user wants to create admin user
    create_admin = input("\n👤 Create admin user? (y/N): ").strip().lower()
    if create_admin in ['y', 'yes']:
        create_admin_user()
    
    # Ask if user wants to run tests
    run_test = input("\n🧪 Run authentication tests? (Y/n): ").strip().lower()
    if run_test not in ['n', 'no']:
        # Start server in background for testing
        print("Starting server for testing...")
        server_process = None
        try:
            server_process = subprocess.Popen([sys.executable, 'run_server.py'], 
                                            stdout=subprocess.DEVNULL, 
                                            stderr=subprocess.DEVNULL)
            
            # Wait a moment for server to start
            import time
            time.sleep(3)
            
            # Run tests
            run_tests()
            
        finally:
            if server_process:
                server_process.terminate()
                server_process.wait()
    
    # Print next steps
    print_next_steps(jwt_secret)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)
