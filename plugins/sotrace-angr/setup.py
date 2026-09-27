from setuptools import setup, find_packages

setup(
    name='sotrace-angr',
    version='0.1.0',
    description='angr plugin for sotrace-database — one-line trace collection from symbolic execution',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=['requests>=2.28.0'],
    extras_require={'angr': ['angr>=9.2.0']},
)
