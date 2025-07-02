"""
Setup script for the easy_mongodb_auth_handler package.
"""


from setuptools import setup, find_packages


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="easy_mongodb_auth_handler",
    version="2.0.0",
    description="A user authentication and verification system using MongoDB.",
    author="Lukbrew25",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lukbrew25/easy-mongodb-auth-handler/",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "bcrypt>=4.0.0",
        "certifi>=2025.6.15",
        "pymongo>=4.6.3"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Internet",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: OS Independent"
    ],
    python_requires=">=3.8",
    license="AGPL-3.0-or-later",
)
