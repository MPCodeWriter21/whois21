# setup.py

from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    LONG_DESCRIPTION = f.read()

DESCRIPTION = 'A simple python package for sending whois requests and parsing the responses.'
VERSION = '1.0.0'
REQUIREMENTS = ['log21', 'importlib_resources', 'requests']

setup(
    name='whois21',
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    url='https://github.com/MPCodeWriter21/PACKAGE_NAME',
    author='CodeWriter21',
    author_email='CodeWriter21@gmail.com',
    license='Apache License 2.0',
    classifiers=[
        'Programming Language :: Python :: 3'
    ],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'whois21=whois21.__main__:main'
        ]
    },
    install_requires=REQUIREMENTS,
    keywords=['python', 'python3', 'CodeWriter21', 'WHOIS', 'whois21', 'RDAP', 'Registration Data Access Protocol',
              'DNS', 'ASN']
)
