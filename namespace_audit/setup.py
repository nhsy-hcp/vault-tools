"""Setup configuration for vault namespace audit tool."""
from setuptools import setup, find_packages

setup(
    name="vault-namespace-audit",
    version="1.0.0",
    description="A defensive security tool for auditing HashiCorp Vault clusters",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "hvac==2.2.0",
        "pandas==2.2.2",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "vault-audit=main:main",
        ]
    }
)