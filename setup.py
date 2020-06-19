#!/usr/bin/env python

import os

from setuptools import setup

extra = {}
try:
    from Cython.Build import cythonize
    p = os.path.join('src', 'wheezy', 'security')
    extra['ext_modules'] = cythonize(
        [os.path.join(p, '*.py'),
         os.path.join(p, 'crypto', '*.py')],
        exclude=[os.path.join(p, '__init__.py'),
                 os.path.join(p, 'crypto', '__init__.py')],
        nthreads=2, quiet=True)
except ImportError:
    pass

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

setup(
    name='wheezy.security',
    version='0.1',
    description='A lightweight security/cryptography library',
    long_description=README,
    long_description_content_type='text/markdown',
    url='https://github.com/akornatskyy/wheezy.security',

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
        'Programming Language :: Python :: 3.3',
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
        'pycrypto': ['pycrypto'],
        'pycryptodome': ['pycryptodome'],
        'pycryptodomex': ['pycryptodomex'],
        'cryptography': ['cryptography'],
        'dev': [
            'pytest',
            'pytest-pep8',
            'pytest-cov'
        ]
    },

    platforms='any',
    **extra
)
