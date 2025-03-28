#!/usr/bin/env python

import multiprocessing
import os
import re

from setuptools import setup

extra = {}
try:
    from Cython.Build import cythonize

    p = os.path.join("src", "wheezy", "security")
    extra["ext_modules"] = cythonize(
        [os.path.join(p, "*.py"), os.path.join(p, "crypto", "*.py")],
        exclude=[
            os.path.join(p, "__init__.py"),
            os.path.join(p, "crypto", "__init__.py"),
        ],
        # https://github.com/cython/cython/issues/3262
        nthreads=0 if multiprocessing.get_start_method() == "spawn" else 2,
        compiler_directives={"language_level": 3},
        quiet=True,
    )
except ImportError:
    pass

README = open(os.path.join(os.path.dirname(__file__), "README.md")).read()
VERSION = (
    re.search(
        r'__version__ = "(.+)"',
        open("src/wheezy/security/__init__.py").read(),
    )
    .group(1)
    .strip()
)

setup(
    name="wheezy.security",
    version=VERSION,
    python_requires=">=3.9",
    description="A lightweight security/cryptography library",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/akornatskyy/wheezy.security",
    author="Andriy Kornatskyy",
    author_email="andriy.kornatskyy@live.com",
    license="MIT",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="security ticket encryption pycrypto",
    packages=["wheezy", "wheezy.security", "wheezy.security.crypto"],
    package_dir={"": "src"},
    namespace_packages=["wheezy"],
    zip_safe=False,
    platforms="any",
    **extra
)
