"""
ByteGuardX Engine Package

This package provides the CLI interface for the ByteGuardX scanning engine,
designed to be invoked by the Tauri desktop application via stdin/stdout IPC.
"""

from .cli import ByteGuardXEngine, main

__version__ = "1.0.0"
__all__ = ["ByteGuardXEngine", "main"]
