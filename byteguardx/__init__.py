"""
ByteGuardX - AI-Powered Vulnerability Scanner
============================================

A full-stack, offline-first vulnerability scanning platform for developers
and security teams.

Features:
- Hardcoded secrets detection
- Vulnerable dependencies scanning  
- AI-generated pattern analysis
- Fix suggestions engine
- PDF report generation
- CLI and REST API
"""

__version__ = "1.0.0"
__author__ = "ByteGuardX Team"
__license__ = "MIT"

# Core modules
from .core.file_processor import FileProcessor
from .core.event_bus import EventBus

# Scanners
from .scanners.secret_scanner import SecretScanner
from .scanners.dependency_scanner import DependencyScanner
from .scanners.ai_pattern_scanner import AIPatternScanner

# AI suggestions
from .ai_suggestions.fix_engine import FixEngine

# Reports
from .reports.pdf_report import PDFReportGenerator

__all__ = [
    "FileProcessor",
    "EventBus", 
    "SecretScanner",
    "DependencyScanner",
    "AIPatternScanner",
    "FixEngine",
    "PDFReportGenerator",
]
