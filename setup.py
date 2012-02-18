#!/usr/bin/env python

import os

try:
    from setuptools import setup
except:
    from distutils.core import setup

README = open(os.path.join(os.path.dirname(__file__), 'README')).read()

setup(
    name='wheezy.security',
    version='0.1',
    description='A lightweight security/cryptography library',
    long_description=README,
    url='https://bitbucket.org/akorn/wheezy.security',

    author='Andriy Kornatskyy',
    author_email='andriy.kornatskyy at live.com',

    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.4',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    keywords='security ticket encryption pycrypto',
    packages=['wheezy', 'wheezy.security', 'wheezy.security.crypto'],
    package_dir={'': 'src'},
    namespace_packages=['wheezy'],

    zip_safe=False,
    install_requires=[
    ],
    extras_require={
        'crypto': ['pycrypto'],
        'dev': [
            'coverage',
            'nose',
            'pytest',
            'pytest-pep8',
            'pytest-cov'
        ]
    },

    platforms='any'
)
