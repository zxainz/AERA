"""Packaging for AERA. Install with: pip install -e ."""
from setuptools import find_packages, setup

setup(
    name="aera",
    version="0.6.0",
    description="Autonomous Exploit Research Assistant (authorized research only)",
    packages=find_packages(include=["aera", "aera.*"]),
    python_requires=">=3.11",
    install_requires=[
        "docker>=7.0",
        "PyJWT>=2.8",
        "requests>=2.31",
        "python-dotenv>=1.0",
    ],
    extras_require={
        "dev": ["pytest>=8.0", "bandit>=1.7"],
    },
    entry_points={
        "console_scripts": [
            "aera=aera.cli:main",
        ],
    },
)
