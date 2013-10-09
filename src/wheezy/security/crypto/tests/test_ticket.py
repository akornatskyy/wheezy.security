
""" Unit tests for ``wheezy.security.principal``.
"""

import unittest


class TicketTestCase(unittest.TestCase):

    def test_ensure_strong_key(self):
        """ Ensure strong key
        """
        from base64 import b64encode
        from wheezy.security.crypto.comp import b
        from wheezy.security.crypto.comp import n
        from wheezy.security.crypto.ticket import ensure_strong_key

        k = ensure_strong_key(b(''))
        assert 40 == len(k)
        s = n(b64encode(k))
        assert '+9sdGxiqbAgyS31ktx+3Y3BpDh1fA7dyIanFu+fzE/Lc5EaX+NQGsA==' == s
        s = n(b64encode(ensure_strong_key(b('abc'))))
        assert 'zEfjwKoMKYRFRHbQYRCMCxEBd66sLMHe/H6umZFFQMixhLcp8jfwGQ==' == s

    def test_encode(self):
        """ Test ticket encode.
        """
        from wheezy.security.crypto.comp import n
        from wheezy.security.crypto.comp import sha1
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(digestmod=sha1)
        assert 72 == len(t.encode(''))

        x = t.encode('hello')
        text, time_left = t.decode(x)
        assert 'hello' == n(text)
        assert time_left >= 0

        # If cypher is not available verification is still applied.

        import warnings
        warnings.simplefilter('ignore')
        t = Ticket(cypher=None)
        warnings.simplefilter('default')
        assert 48 == len(t.encode(''))

        x = t.encode('hello')
        text, time_left = t.decode(x)
        assert 'hello' == n(text)
        assert time_left >= 0


class TicketDecodeTestCase(unittest.TestCase):

    def setUp(self):
        import warnings
        warnings.simplefilter('ignore')

    def tearDown(self):
        import warnings
        warnings.simplefilter('default')

    def test_invalid_length(self):
        """ The value is at least 48 in length.
        """
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket(cypher=None)
        assert (None, None) == t.decode('a' * 47)

    def test_invalid_base64_string(self):
        """ Invalid base64 string.
        """
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket(cypher=None)
        assert (None, None) == t.decode('D' * 57)

    def test_unicode_error(self):
        """ Unicode error.
        """
        from wheezy.security.crypto.comp import u
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket(cypher=None)
        value = t.encode(u('\u0430'))
        assert (None, None) == t.decode(value, 'ascii')

    def test_invalid_padding(self):
        """ Invalid padding.
        """
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket(cypher=None)
        value = t.encode('a' * 31)
        t = Ticket()
        assert (None, None) == t.decode(value)

    def test_signature_is_not_valid(self):
        """ Signature is not valid.
        """
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket(cypher=None)
        value = 'cf-0eDoyN6VwP-IyZap4zTBjsHqqaZua4MkGAA11HGdoZWxsbxBSjyg='
        assert (None, None) == t.decode(value)

    def test_expired(self):
        """ Expired.
        """
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket(cypher=None)
        value = '1ZRcHGsYENF~lzezpMKFFF9~QBCQkqPlIMoGAA11HGdoZWxsbxBSjyg='
        assert (None, None) == t.decode(value)

    def test_invalid_verification_key(self):
        """ Invalid verification key.
        """
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket()
        value = t.encode('test')
        t = Ticket(options={'CRYPTO_VALIDATION_KEY': 'x'})
        assert (None, None) == t.decode(value)

    def test_invalid_encryption_key(self):
        """ Invalid encryption key.
        """
        from wheezy.security.crypto.ticket import Ticket
        t = Ticket()
        value = t.encode('test')
        t = Ticket(options={'CRYPTO_ENCRYPTION_KEY': 'x'})
        assert (None, None) == t.decode(value)
