from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ai-agent-sandbox",
    version="0.1.0",
    author="Bastiaan",
    author_email="bastiaanrusch01@gmail.com",
    description="Security sandbox runtime for AI agents with policy-based access control",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/ai-agent-sandbox",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "flask>=2.0.0",
        "pydantic>=1.10.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "mypy>=0.950",
        ],
        "langchain": [
            "langchain>=0.0.100",
        ],
    },
    entry_points={
        "console_scripts": [
            "sandbox=sandbox.cli:main",
        ],
    },
)
