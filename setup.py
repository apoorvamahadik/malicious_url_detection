from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="malicious-url-detector",
    version="2.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Machine learning system for detecting malicious URLs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/malicious-url-detector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "url-detector=backend.app:main",
            "train-model=backend.train_model:main",
        ],
    },
)