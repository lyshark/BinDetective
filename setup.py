import setuptools
from distutils.core import setup

packages = ['BinDetective']

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='BinDetective',
    version='1.0.1',
    author='lyshark',
    description='',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email='me@lyshark.com',
    url="http://detective.lyshark.com",
    python_requires=">=3.6.0",
    license="MIT Licence",
    packages=packages,
    include_package_data=True,
    platforms="any",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        # Add any dependencies here
    ],
)