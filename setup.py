# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from setuptools import setup, find_packages


# Function to read the requirements.txt file
def parse_requirements(filename):
    with open(filename, "r") as file:
        lines = file.readlines()
        # Filter out empty lines and comments
        requirements = [
            line.strip() for line in lines if line.strip() and not line.startswith("#")
        ]
    return requirements


setup(
    name="secgym",
    version="0.1",
    packages=find_packages(),
    include_package_data=True,
    description="A benchmark for security question answering",
    install_requires=parse_requirements("requirements.txt"),
    extras_require={"agentic": ["pydantic>=2.8,<3", "duckdb>=1.4.3,<2", "pytz>=2024.1", "sqlglot>=27,<28"]},
    package_data={"secgym.qagen.agentic": ["legacy_baseline.json"]},
    entry_points={
        "console_scripts": [
        ],
    },
    python_requires=">=3.10",
    zip_safe=False,  # Important for editable installs
)
