#!/usr/bin/env python3
"""
DONET - Network Analyzer
Setup script for pip installation
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith('#')]

setup(
    name="donet-network-analyzer",
    version="1.0.0",
    author="DONET Team",
    author_email="donet@example.com",
    description="Real-time packet threat detection with emoji indicators",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/donet/network-analyzer",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "donet=cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.txt", "*.md", "*.toml"],
    },
)
