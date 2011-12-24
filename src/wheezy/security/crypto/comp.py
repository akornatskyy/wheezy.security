
""" ``comp`` module.
"""

import sys


PY3 = sys.version_info[0] >= 3

if PY3:  # pragma: nocover

    def ntob(n, encoding):
        """ Converts native string to bytes
        """
        return n.encode(encoding)

    def bton(b, encoding):
        """ Converts bytes to native string
        """
        return b.decode(encoding)

    chr = lambda i: bytes([i])
    ord = lambda b: b
    b = lambda s: s.encode('latin1')

    def n(s):
        if isinstance(s, bytes):
            return s.decode('latin1')
        else:
            return s

else:  # pragma: nocover

    def ntob(n, encoding):
        """ Converts native string to bytes
        """
        return n

    def bton(b, encoding):
        """ Converts bytes to native string
        """
        return b

    chr = chr
    ord = ord
    b = lambda s: s

    def n(s):
        if isinstance(s, unicode):
            return s.encode('latin1')
        else:
            return s


# Hash functions
try:  # pragma: nocover
    # Python 2.5+
    from hashlib import md5
    from hashlib import sha1
    digest_size = lambda d: d().digest_size
except ImportError:  # pragma: nocover
    import md5
    import sha as sha1
    digest_size = lambda d: d.digest_size


# Encryption interface
block_size = None
encrypt = None
decrypt = None

# Supported cyphers
aes128 = None
aes192 = None
aes256 = None

# Python Cryptography Toolkit (pycrypto)
try:  # pragma: nocover
    from Crypto.Cipher import AES

    # pycrypto interface
    block_size = lambda c: c.block_size
    encrypt = lambda c, v: c.encrypt(v)
    decrypt = lambda c, v: c.decrypt(v)

    # suppored cyphers
    def aes(key, key_size=32):
        key = key[-key_size:]
        iv = key[-16:]
        return lambda: AES.new(key, AES.MODE_CBC, iv)

    aes128 = lambda key: aes(key, 16)
    aes192 = lambda key: aes(key, 24)
    aes256 = lambda key: aes(key, 32)
except ImportError:  # pragma: nocover
    # TODO: add fallback to other encryption providers
    pass
