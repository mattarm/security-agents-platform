"""
Okta Identity Security Integration - Setup Configuration
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="okta-security-integration",
    version="1.0.0",
    author="Security Team",
    author_email="security@company.com",
    description="Comprehensive Okta identity security monitoring and response platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/company/okta-security-integration",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-mock>=3.12.0",
            "black>=23.11.0",
            "isort>=5.12.0",
            "mypy>=1.7.1",
            "flake8>=6.1.0",
            "coverage>=7.3.2",
        ],
        "monitoring": [
            "prometheus-client>=0.19.0",
            "sentry-sdk>=1.39.2",
            "grafana-api>=1.0.3",
        ],
        "ml": [
            "tensorflow>=2.14.0",
            "torch>=2.1.0",
            "scikit-learn>=1.3.2",
            "xgboost>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "okta-security=main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "okta_security": ["*.yml", "*.yaml", "*.json"],
        "config": ["*.yml", "*.yaml", "*.json"],
        "docs": ["*.md", "*.rst"],
    },
    project_urls={
        "Bug Reports": "https://github.com/company/okta-security-integration/issues",
        "Documentation": "https://docs.company.com/okta-security",
        "Source": "https://github.com/company/okta-security-integration",
    },
)