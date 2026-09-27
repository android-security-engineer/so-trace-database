from setuptools import setup, find_packages

setup(
    name='sotrace-qiling',
    version='0.1.0',
    description='Qiling plugin for sotrace-database — one-line trace collection',
    long_description=open('README.md').read() if __import__('os').path.exists('README.md') else '',
    long_description_content_type='text/markdown',
    author='sotrace-database contributors',
    url='https://github.com/your-org/so-trace-database',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        'requests>=2.28.0',
    ],
    extras_require={
        'qiling': ['qiling>=1.4.0'],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Software Development :: Debuggers',
    ],
)
