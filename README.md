# wheezy.security

[![Build Status](https://travis-ci.org/akornatskyy/wheezy.security.svg?branch=master)](https://travis-ci.org/akornatskyy/wheezy.security)
[![Coverage Status](https://coveralls.io/repos/github/akornatskyy/wheezy.security/badge.svg?branch=master)](https://coveralls.io/github/akornatskyy/wheezy.security?branch=master)
[![Documentation Status](https://readthedocs.org/projects/wheezysecurity/badge/?version=latest)](https://wheezysecurity.readthedocs.io/en/latest/?badge=latest)
[![pypi version](https://badge.fury.io/py/wheezy.security.svg)](https://badge.fury.io/py/wheezy.security)

[wheezy.security](https://pypi.org/project/wheezy.security/) is a
[python](https://www.python.org) package written in pure Python code. It
is a lightweight security library that provides integration with:

- [pycrypto](https://www.dlitz.net/software/pycrypto) - The Python
  Cryptography Toolkit.
- [pycryptodome](https://www.pycryptodome.org) - PyCryptodome
  is a fork of PyCrypto. It brings several enhancements.
- [pycryptodomex](https://www.pycryptodome.org) - PyCryptodomex
  is a library independent of the PyCrypto.
- [cryptography](https://pypi.org/project/cryptography/) - cryptography
  is a package which provides cryptographic recipes and primitives to
  Python developers.

It is optimized for performance, well tested and documented.

Resources:

- [source code](https://github.com/akornatskyy/wheezy.security),
  and [issues](https://github.com/akornatskyy/wheezy.security/issues)
  tracker are available on
  [github](https://github.com/akornatskyy/wheezy.security)
- [documentation](https://wheezysecurity.readthedocs.io/en/latest/)

## Install

[wheezy.security](https://pypi.org/project/wheezy.security/) requires
[python](https://www.python.org) version 3.8+. It is independent of operating
system. You can install it from
[pypi](https://pypi.org/project/wheezy.security/) site:

```sh
pip install -U wheezy.security
```

If you would like take benefit of one of cryptography library that has
built-in support specify extra requirements:

```sh
pip install wheezy.security[pycrypto]
pip install wheezy.security[pycryptodome]
pip install wheezy.security[pycryptodomex]
pip install wheezy.security[cryptography]
```

If you run into any issue or have comments, go ahead and add on
[github](https://github.com/akornatskyy/wheezy.security).
