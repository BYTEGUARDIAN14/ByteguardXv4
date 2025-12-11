#!/usr/bin/env python3
"""
Install ByteGuardX pre-commit hooks
"""

import os
import shutil
import stat
from pathlib import Path

def install_pre_commit_hook():
    """Install the pre-commit hook"""
    try:
        # Get paths
        repo_root = Path(__file__).parent
        hook_source = repo_root / "hooks" / "pre-commit"
        git_hooks_dir = repo_root / ".git" / "hooks"
        hook_dest = git_hooks_dir / "pre-commit"
        
        # Check if .git directory exists
        if not git_hooks_dir.parent.exists():
            print("Error: Not a git repository")
            return False
        
        # Create hooks directory if it doesn't exist
        git_hooks_dir.mkdir(exist_ok=True)
        
        # Copy hook
        shutil.copy2(hook_source, hook_dest)
        
        # Make executable
        current_permissions = hook_dest.stat().st_mode
        hook_dest.chmod(current_permissions | stat.S_IEXEC)
        
        print(f"✅ Pre-commit hook installed at {hook_dest}")
        print("The hook will now run automatically before each commit.")
        print("\nTo bypass the hook (not recommended), use:")
        print("  git commit --no-verify")
        
        return True
        
    except Exception as e:
        print(f"Error installing pre-commit hook: {e}")
        return False

def main():
    """Main installation function"""
    print("🔧 Installing ByteGuardX Git Hooks")
    print("=" * 35)
    
    success = install_pre_commit_hook()
    
    if success:
        print("\n🎉 Installation complete!")
        print("\nThe pre-commit hook will:")
        print("• Scan staged files for security vulnerabilities")
        print("• Block commits with critical or high severity issues")
        print("• Show detailed findings and fix suggestions")
    else:
        print("\n❌ Installation failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
