
""" ``crypto`` module.
"""

from base64 import b64decode
from base64 import b64encode
from hmac import new as hmac_new
from os import urandom
from struct import pack
from struct import unpack
from time import time

from wheezy.core.config import Config
from wheezy.security.crypto import config
from wheezy.security.crypto.comp import aes128
from wheezy.security.crypto.comp import b
from wheezy.security.crypto.comp import block_size
from wheezy.security.crypto.comp import btos
from wheezy.security.crypto.comp import decrypt
from wheezy.security.crypto.comp import digest_size
from wheezy.security.crypto.comp import encrypt
from wheezy.security.crypto.comp import sha1
from wheezy.security.crypto.padding import pad
from wheezy.security.crypto.padding import unpad

BASE64_ALTCHARS = b('-~')
EMPTY = b('')
EPOCH = 1317212745


def ensure_strong_key(key):
    """ Translates a given key to a computed strong key of length
        320 bit suitable for encryption.

        >>> from wheezy.security.crypto.comp import n
        >>> k = ensure_strong_key(b(''))
        >>> len(k)
        40
        >>> n(b64encode(k))
        '+9sdGxiqbAgyS31ktx+3Y3BpDh1fA7dyIanFu+fzE/Lc5EaX+NQGsA=='
        >>> n(b64encode(ensure_strong_key(b('abc'))))
        'zEfjwKoMKYRFRHbQYRCMCxEBd66sLMHe/H6umZFFQMixhLcp8jfwGQ=='
    """
    hmac = hmac_new(key, digestmod=sha1)
    key = hmac.digest()
    hmac.update(key)
    return key + hmac.digest()


class Ticket:
    """ Protects sensitive information (e.g. user id). Default policy
        applies verification and encryption. Verification is provided
        by ``hmac`` initialized with ``sha1`` digestmod. Encryption
        is provided if available, by default it attempts to use AES
        cypher.

        >>> from wheezy.security.crypto.comp import n
        >>> t = Ticket()
        >>> x = t.encode('hello')
        >>> text, time_left = t.decode(x)
        >>> n(text)
        'hello'
        >>> assert time_left >= 0

        If cypher is not available verification is still applied.

        >>> t = Ticket(cypher=None)
        >>> x = t.encode('hello')
        >>> text, time_left = t.decode(x)
        >>> n(text)
        'hello'
        >>> assert time_left >= 0
    """

    cypher = None

    def __init__(self, max_age=900, salt='', digestmod=None,
            cypher=aes128, options=None):
        self.max_age = max_age
        digestmod = digestmod or sha1
        c = Config(options, master=config)
        key = b(salt + c.CRYPTO_VALIDATION_KEY)
        key = ensure_strong_key(key)
        self.hmac = hmac_new(key, digestmod=digestmod)
        self.digest_size = digest_size(digestmod)
        if cypher:
            key = b(salt + c.CRYPTO_ENCRYPTION_KEY)
            key = ensure_strong_key(key)
            self.cypher = cypher(key)
            self.block_size = block_size(self.cypher())

    def encode(self, value, encoding='utf-8'):
        """ Encode ``value`` accoring to ticket policy.
        """
        value = b(value, encoding)
        expires = pack('<i', self.timestamp() + self.max_age)
        noise = urandom(12)
        value = EMPTY.join((
            noise[:4],
            expires,
            noise[4:8],
            value,
            noise[8:]
        ))
        cypher = self.cypher
        if cypher:
            cypher = cypher()
            value = encrypt(cypher, pad(value, self.block_size))
        return btos(b64encode(self.sign(value) + value, BASE64_ALTCHARS),
                'latin1')

    def decode(self, value, encoding='utf-8'):
        """ Decode ``value`` according to ticket policy.

            The ``value`` length is at least 56.

            >>> t = Ticket(cypher=None)
            >>> t.decode('abc')
            (None, None)

            Signature is not valid

            >>> value = 'cf-0eDoyN6VwP-IyZap4zTBjsHqqaZua4MkG'
            >>> value += 'AA11HGdoZWxsbxBSjyg='
            >>> t.decode(value)
            (None, None)

            Expired

            >>> value = '1ZRcHGsYENF~lzezpMKFFF9~QBCQkqPlIMoG'
            >>> value += 'AA11HGdoZWxsbxBSjyg='
            >>> t.decode(value)
            (None, None)
        """
        if len(value) < 56:
            return (None, None)
        value = b64decode(b(value), BASE64_ALTCHARS)
        signature = value[:self.digest_size]
        value = value[self.digest_size:]
        if signature != self.sign(value):
            return (None, None)
        cypher = self.cypher
        if cypher:
            cypher = cypher()
            value = unpad(decrypt(cypher, value), self.block_size)
        expires, value = value[4:8], value[12:-4]
        time_left = unpack('<i', expires)[0] - self.timestamp()
        if time_left < 0:
            return (None, None)
        return (btos(value, encoding), time_left)

    def timestamp(self):
        return int(time()) - EPOCH

    def sign(self, value):
        h = self.hmac.copy()
        h.update(value)
        return h.digest()
