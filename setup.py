"""
ByteGuardX Setup Configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = requirements_path.read_text().splitlines()

setup(
    name="byteguardx",
    version="1.0.0",
    description="AI-Powered Vulnerability Scanner for Developers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ByteGuardX Team",
    author_email="team@byteguardx.com",
    url="https://github.com/byteguardx/byteguardx",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "byteguardx": [
            "offline_db/*.json",
            "reports/templates/*.html",
        ]
    },
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "black>=23.9.1",
            "flake8>=6.1.0",
            "mypy>=1.6.0",
        ],
        "ai": [
            "transformers>=4.35.0",
            "torch>=2.1.0",
            "onnxruntime>=1.16.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "byteguardx=byteguardx.cli.cli:cli",
            "byteguardx-api=byteguardx.api.app:create_app",
            "byteguardx-hook=byteguardx.pre_commit:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    keywords=[
        "security",
        "vulnerability",
        "scanner",
        "static-analysis",
        "secrets",
        "dependencies",
        "ai",
        "devsecops",
        "sast",
    ],
    project_urls={
        "Bug Reports": "https://github.com/byteguardx/byteguardx/issues",
        "Source": "https://github.com/byteguardx/byteguardx",
        "Documentation": "https://docs.byteguardx.com",
    },
)
