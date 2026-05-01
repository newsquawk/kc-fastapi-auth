"""Setup file for newsquawk-auth package."""
from setuptools import setup, find_packages

setup(
    name="newsquawk-auth",
    version="0.0.1",
    description="Shared authentication package for Newsquawk services using JWT/JWKS",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.100.0",
        "PyJWT>=2.8.0",
        "cryptography>=41.0.0",
    ],
)
