""" Unit tests for ``wheezy.security.crypto.padding``.
"""

import unittest
from binascii import hexlify, unhexlify

from wheezy.security.crypto.padding import pad, unpad


class PaddingTestCase(unittest.TestCase):
    def test_pad(self):
        """Test pad."""
        s = hexlify(pad(b"workbook", 8)).decode()
        assert "776f726b626f6f6b0000000000000008" == s
        s = hexlify(pad(b"for", 8)).decode()
        assert "666f720000000005" == s
        s = hexlify(pad(b"", 8)).decode()
        assert "0000000000000008" == s

    def test_unpad(self):
        """Test unpad."""
        s = unhexlify(b"666f720000000005")
        s = unpad(s, 8).decode()
        assert "for" == s
        s = unhexlify(b"776f726b626f6f6b0000000000000008")
        s = unpad(s, 8).decode()
        assert "workbook" == s
        assert unpad("", 8) is None
        # incorrect padding
        assert unpad(unhexlify(b"666f720000000005"), 4) is None
        assert unpad("abc", 8) is None
        assert unpad("abcd", 8) is None
