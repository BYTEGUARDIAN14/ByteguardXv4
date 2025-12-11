"""
ByteGuardX Setup Configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Core requirements (minimal for basic functionality)
core_requirements = [
    "Flask>=2.3.0",
    "Flask-CORS>=4.0.0",
    "Flask-JWT-Extended>=4.5.0",
    "SQLAlchemy>=2.0.0",
    "cryptography>=41.0.0",
    "click>=8.1.0",
    "rich>=13.6.0",
    "httpx>=0.25.0",  # Lighter than requests
    "pyyaml>=6.0.0",
    "python-dotenv>=1.0.0",
    "psutil>=5.9.0",
    "validators>=0.22.0",
    "PyJWT>=2.8.0",
    "bcrypt>=4.1.0",
    "python-magic>=0.4.27",
    "jsonschema>=4.19.0",
    "pyotp>=2.9.0",  # For 2FA
    "passlib[bcrypt]>=1.7.4",  # Password hashing
]

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
    install_requires=core_requirements,
    extras_require={
        # Feature-specific dependencies (install only what you need)
        "pdf": [
            "WeasyPrint>=60.1",
            "Jinja2>=3.1.2",
        ],
        "database": [
            "psycopg2-binary>=2.9.9",  # PostgreSQL
            "pymysql>=1.1.0",  # MySQL
            "alembic>=1.12.1",  # Migrations
        ],
        "twofa": [
            "qrcode[pil]>=7.4.2",  # QR code generation
        ],
        "async": [
            "aiofiles>=23.2.1",
            "aiohttp>=3.9.1",
        ],
        "queue": [
            "redis>=4.6.0",
            "celery>=5.3.4",
        ],
        "enterprise": [
            "python-saml>=1.15.0",
            "xmlsec>=1.3.13",
            "ldap3>=2.9.1",
        ],
        "container": [
            "docker>=6.1.3",
        ],
        "ml-light": [
            "numpy>=1.24.3",
            "scikit-learn>=1.3.0",
        ],
        "ml-full": [
            "numpy>=1.24.3",
            "pandas>=2.0.3",
            "scikit-learn>=1.3.0",
            "matplotlib>=3.7.2",
            "seaborn>=0.12.2",
        ],
        "ai": [
            "transformers>=4.35.0",
            "torch>=2.1.0",  # CPU-only version
            "onnxruntime>=1.16.0",
        ],
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.1",
            "black>=23.9.1",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
            "bandit>=1.7.5",
            "safety>=2.3.5",
            "pre-commit>=3.5.0",
        ],
        "all": [
            # Common optional dependencies (not including heavy ML/AI)
            "WeasyPrint>=60.1",
            "Jinja2>=3.1.2",
            "psycopg2-binary>=2.9.9",
            "qrcode[pil]>=7.4.2",
            "redis>=4.6.0",
            "numpy>=1.24.3",
            "scikit-learn>=1.3.0",
        ],
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
