""" Unit tests for ``wheezy.security.crypto.padding``.
"""

import unittest


class PaddingTestCase(unittest.TestCase):
    def test_pad(self):
        """Test pad."""
        from binascii import hexlify

        from wheezy.security.crypto.comp import b, n
        from wheezy.security.crypto.padding import pad

        s = n(hexlify(pad(b("workbook"), 8)))
        assert "776f726b626f6f6b0000000000000008" == s
        s = n(hexlify(pad(b("for"), 8)))
        assert "666f720000000005" == s
        s = n(hexlify(pad(b(""), 8)))
        assert "0000000000000008" == s

    def test_unpad(self):
        """Test unpad."""
        from binascii import unhexlify

        from wheezy.security.crypto.comp import b, n
        from wheezy.security.crypto.padding import unpad

        s = unhexlify(b("666f720000000005"))
        s = n(unpad(s, 8))
        assert "for" == s
        s = unhexlify(b("776f726b626f6f6b0000000000000008"))
        s = n(unpad(s, 8))
        assert "workbook" == s
        assert unpad("", 8) is None
        # incorrect padding
        assert unpad(unhexlify(b("666f720000000005")), 4) is None
        assert unpad("abc", 8) is None
        assert unpad("abcd", 8) is None
