#!/usr/bin/env python3
"""
ByteGuardX CLI - Command-line interface for vulnerability scanning
Main entry point for the CLI application
"""

import sys
from pathlib import Path

# Add the byteguardx package to the Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import and run the CLI
from byteguardx.cli.cli import cli

if __name__ == '__main__':
    cli()
