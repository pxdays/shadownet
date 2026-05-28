#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="shadownet",
    version="1.0.0",
    description="Autonomous Red Team Engine - Penetration Testing & Reconnaissance Framework",
    author="pxdays",
    author_email="mulhollandjosh9@gmail.com",
    url="https://github.com/pxdays",
    packages=find_packages(),
    py_modules=["shadownet"],
    entry_points={
        "console_scripts": [
            "shadownet=shadownet:main",
            "sn=shadownet:main",
        ]
    },
    install_requires=[
        "dnspython>=2.0.0",
    ],
    extras_require={
        "full": [
            "dnspython>=2.0.0",
            "requests>=2.25.0",
        ],
        "dev": [
            "pytest",
            "flake8",
        ],
    },
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: Freeware",
    ],
)
