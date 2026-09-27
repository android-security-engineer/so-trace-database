from setuptools import setup, find_packages

setup(
    name='sotrace-triton',
    version='0.1.0',
    description='Triton plugin for sotrace-database — concrete/symbolic trace collection',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=['requests>=2.28.0'],
    extras_require={
        'triton': ['triton'],
        'elf': ['lief', 'pyelftools'],
    },
)
