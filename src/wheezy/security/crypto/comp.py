""" ``comp`` module.
"""

from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from os import urandom
from warnings import warn


def digest_size(d):
    return d().digest_size


try:
    from hashlib import new as openssl_hash

    def ripemd160():
        return openssl_hash("ripemd160")  # pragma: nocover

    def whirlpool():
        return openssl_hash("whirlpool")  # pragma: nocover

except ValueError:  # pragma: nocover
    ripemd160 = None
    whirlpool = None


# Encryption interface


def block_size(c):  # pragma: nocover
    return c.block_size


def encrypt(c, v):  # pragma: nocover
    return c.encrypt(v)


def decrypt(c, v):  # pragma: nocover
    return c.decrypt(v)


# Supported cyphers
aes = None
aes128 = None
aes192 = None
aes256 = None
aes128iv = None
aes192iv = None
aes256iv = None

# Python Cryptography Toolkit (pycrypto, pycryptodome, pycryptodomex)
try:  # noqa pragma: nocover
    try:  # pragma: nocover
        from Cryptodome.Cipher import AES
    except ImportError:  # pragma: nocover
        from Crypto.Cipher import AES

    class AESIVCipher(object):  # pragma: nocover
        """AES cipher that uses random IV for each encrypt operation
        and prepend it to cipher text; decrypt splits input value into
        IV and cipher text.
        """

        block_size = 16

        def __init__(self, key):
            self.key = key

        def encrypt(self, v):
            iv = urandom(16)
            c = AES.new(self.key, AES.MODE_CBC, iv)
            return iv + c.encrypt(v)

        def decrypt(self, v):
            c = AES.new(self.key, AES.MODE_CBC, v[:16])
            return c.decrypt(v[16:])

    # suppored cyphers
    def aes(key, key_size=32):  # pragma: nocover
        assert len(key) >= key_size
        if len(key) < key_size + 16:  # pragma: nocover
            warn("AES%d: key and iv overlap." % (key_size * 8))
        key = key[-key_size:]
        iv = key[:16]
        return lambda: AES.new(key, AES.MODE_CBC, iv)

except ImportError:  # pragma: nocover
    try:  # pragma: nocover
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import (
            Cipher,
            algorithms,
            modes,
        )

        backend = default_backend()

        class AESCipher(object):  # pragma: nocover
            def __init__(self, key, iv):
                alg = algorithms.AES(key)
                self.c = Cipher(alg, modes.CBC(iv), backend=backend)
                self.block_size = alg.block_size

            def encrypt(self, v):
                e = self.c.encryptor()
                return e.update(v) + e.finalize()

            def decrypt(self, v):
                d = self.c.decryptor()
                return d.update(v) + d.finalize()

        class AESIVCipher(object):  # pragma: nocover
            """AES cipher that uses random IV for each encrypt operation
            and prepend it to cipher text; decrypt splits input value into
            IV and cipher text.
            """

            block_size = 16

            def __init__(self, key):
                self.key = key

            def encrypt(self, v):
                iv = urandom(16)
                print("len", len(iv))
                c = AESCipher(self.key, iv)
                return iv + c.encrypt(v)

            def decrypt(self, v):
                # print(v)
                c = AESCipher(self.key, v[:16])
                return c.decrypt(v[16:])

        def aes(key, key_size=32):  # pragma: nocover
            assert len(key) >= key_size
            if len(key) < key_size + 16:  # pragma: nocover
                warn("AES%d: key and iv overlap." % (key_size * 8))
            key = key[-key_size:]
            iv = key[:16]
            return lambda: AESCipher(key, iv)

    except ImportError:  # pragma: nocover
        # TODO: add fallback to other encryption providers
        pass


if aes:

    def aes128(key):
        return aes(key, 16)

    def aes192(key):
        return aes(key, 24)

    def aes256(key):
        return aes(key, 32)

    def aesiv(key, key_size=32):
        assert len(key) >= key_size
        c = AESIVCipher(key[:key_size])
        return lambda: c

    def aes128iv(key):
        return aesiv(key, 16)

    def aes192iv(key):
        return aesiv(key, 24)

    def aes256iv(key):
        return aesiv(key, 32)


__all__ = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "digest_size",
    "ripemd160",
    "whirlpool",
    "block_size",
    "encrypt",
    "decrypt",
    "aes",
    "aes128",
    "aes192",
    "aes256",
    "aes128iv",
    "aes192iv",
    "aes256iv",
    "AESCipher",
    "AESIVCipher",
)
