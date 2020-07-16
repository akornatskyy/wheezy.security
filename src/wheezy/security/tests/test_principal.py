""" Unit tests for ``wheezy.security.principal``.
"""

import unittest


class PrincipalTestCase(unittest.TestCase):
    def test_dump(self):
        """ Ensure the principal object is dumped correctly
            with delimiters.
        """
        from wheezy.security.principal import Principal

        p = Principal()
        s = p.dump()
        assert 3 == len(s)
        assert "\x1f\x1f\x1f" == s

        p = Principal(
            id="79053", roles=("a", "b"), alias="John", extra="anything"
        )
        s = p.dump()
        assert "79053\x1fa;b\x1fJohn\x1fanything" == s

    def test_load(self):
        """
        """
        from wheezy.security.principal import Principal

        p = Principal.load("\x1f\x1f\x1f")
        assert p
        assert "" == p.id
        assert ("",) == p.roles
        assert "" == p.alias
        assert "" == p.extra

        p = Principal.load("79053\x1fa;b\x1fJohn\x1fanything")
        assert "79053" == p.id
        assert ("a", "b") == p.roles
        assert "John" == p.alias
        assert "anything" == p.extra
