from setuptools import setup, find_packages

setup(
    name="rea-titan",
    version="1.0.0",
    description="Next-Gen Reverse Engineering Suite combining REA Agent Protocol and Headless Ghidra",
    author="Murat & Tris",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "rich>=12.0.0",
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "rea-titan=rea_titan.cli:cli",
        ],
    },
    python_requires=">=3.10",
)
