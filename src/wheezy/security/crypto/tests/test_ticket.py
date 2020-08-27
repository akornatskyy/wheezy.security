""" Unit tests for ``wheezy.security.principal``.
"""

import unittest


class TicketTestCase(unittest.TestCase):
    def test_ensure_strong_key(self):
        """Ensure strong key"""
        from base64 import b64encode

        from wheezy.security.crypto.comp import b, n, sha1
        from wheezy.security.crypto.ticket import ensure_strong_key

        k = ensure_strong_key(b(""), sha1)
        assert 60 == len(k)
        s = n(b64encode(k))
        assert (
            "+9sdGxiqbAgyS31ktx+3Y3BpDh1fA7dyIanFu+fzE/Lc5EaX+NQGs"
            + "KMipy3SvghXaQLqLrLZnSmqEkgv"
            == s
        )
        s = n(b64encode(ensure_strong_key(b("abc"), sha1)))
        assert (
            "WzM6OJtOmiNYrFOSvypk3GjjyUMAcO5Oj0mHXQLAZGmiYN8OZxdtj"
            + "NR1mYddYPy+lo/k53pSG+n7T8hB"
            == s
        )

    def test_encode(self):
        """Test ticket encode."""
        from wheezy.security.crypto.comp import (
            aes128,
            aes128iv,
            aes192,
            aes192iv,
            aes256,
            aes256iv,
        )

        for cypher in [aes128, aes128iv, aes192, aes192iv, aes256, aes256iv]:
            self.encode(cypher=cypher)

    def encode(self, cypher):
        from wheezy.security.crypto.comp import n, sha1
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(digestmod=sha1, cypher=cypher)
        if cypher:
            assert len(t.encode("")) >= 72
        else:  # pragma: nocover
            assert len(t.encode("")) == 48

        x = t.encode("hello")
        text, time_left = t.decode(x)
        assert "hello" == n(text)
        assert time_left >= 0

        # If cypher is not available verification is still applied.

        import warnings

        warnings.simplefilter("ignore")
        t = Ticket(cypher=None)
        warnings.simplefilter("default")
        assert 48 == len(t.encode(""))

        x = t.encode("hello")
        text, time_left = t.decode(x)
        assert "hello" == n(text)
        assert time_left >= 0


class TicketDecodeTestCase(unittest.TestCase):
    def setUp(self):
        import warnings

        warnings.simplefilter("ignore")

    def tearDown(self):
        import warnings

        warnings.simplefilter("default")

    def test_invalid_length(self):
        """The value is at least 48 in length."""
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(cypher=None)
        assert (None, None) == t.decode("a" * 47)

    def test_invalid_base64_string(self):
        """Invalid base64 string."""
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(cypher=None)
        assert (None, None) == t.decode("D" * 57)

    def test_unicode_error(self):
        """Unicode error."""
        from wheezy.security.crypto.comp import u
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(cypher=None)
        value = t.encode(u("\u0430"))
        assert (None, None) == t.decode(value, "ascii")

    def test_invalid_padding(self):
        """Invalid padding."""
        from wheezy.security.crypto.comp import aes128 as cypher
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(cypher=None)
        value = t.encode("a" * 31)
        if cypher:
            t = Ticket(cypher=cypher)
            assert (None, None) == t.decode(value)
            assert (None, None) == t.decode(
                "9zb2S-xu~M54KVqlcnXHzQAvYcMOyzLBWtQm9IQ2NNuWvsWALCU3"
                "-XSc~tZGWHiINGajQ1XpSanI8TJ8DcwuG0yPa9vp1QqZ8Cjruixu"
                "ARWDOkSXnQv5Jy8Ygqq3Yu6umJDH0Z~NdpZWp9HvJhcQrYKfbDaY"
                "IsW~~-DVv-AQDYW3cs7qgw-U0IOisN~wq~joW1XRQA=="
            )

    def test_expired(self):
        """Expired."""
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(cypher=None)
        value = t.encode("test")
        value = "skAtojnOg2DKO66h6m8ZM4IdFI2sF-HVh9~hA76Kl-t0ZXN019MGVQ=="
        assert (None, None) == t.decode(value)

    def test_invalid_verification_key(self):
        """Invalid verification key."""
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket()
        value = t.encode("test")
        t = Ticket(options={"CRYPTO_VALIDATION_KEY": "x"})
        assert (None, None) == t.decode(value)

    def test_invalid_encryption_key(self):
        """Invalid encryption key."""
        from wheezy.security.crypto.comp import aes128 as cypher
        from wheezy.security.crypto.ticket import Ticket

        t = Ticket(cypher=cypher)
        value = t.encode("test")
        t = Ticket(options={"CRYPTO_ENCRYPTION_KEY": "x"})
        if cypher:
            assert (None, None) == t.decode(value)
        else:  # pragma: nocover
            assert ("test", 900) == t.decode(value)
