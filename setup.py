"""Setup file for newsquawk-auth package."""
from setuptools import setup, find_packages

setup(
    name="newsquawk-auth",
    version="0.3.1",
    description="Shared authentication package for Newsquawk services using JWT/JWKS",
    packages=find_packages(),
    package_data={"newsquawk_auth": ["*.yaml"]},
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.100.0",
        "PyJWT>=2.8.0",
        "cryptography>=41.0.0",
        "httpx>=0.24.0",
    ],
    extras_require={
        # Optional stub (fake-Keycloak) flow: newsquawk_auth.stub
        "stub": [
            "bcrypt>=3.1.0",
            "PyYAML>=6.0",
        ],
    },
)
