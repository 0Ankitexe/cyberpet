"""CyberPet — A terminal-based cybersecurity daemon that behaves like a virtual pet."""

from setuptools import setup, find_packages

setup(
    name="cyberpet",
    version="2.0.0",
    description="A terminal-based cybersecurity daemon for Linux that behaves like a virtual pet",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Ankit Bharti",
    author_email="ankit.vspb@gmail.com",
    url="https://github.com/0Ankitexe/cyberpet",
    license="MIT",
    python_requires=">=3.11",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "cyberpet": ["../config/default_config.toml"],
    },
    data_files=[
        ("config", ["config/default_config.toml"]),
    ],
    install_requires=[
        "textual>=0.40.0",
        "psutil>=5.9.0",
        "toml>=0.10.2",
        "click>=8.1.0",
        "python-daemon>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "cyberpet=cyberpet.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
