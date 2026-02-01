import unittest

from wheezy.security.authorization import authorized
from wheezy.security.errors import SecurityError
from wheezy.security.principal import Principal


class MyService(object):
    principal = None

    @authorized
    def op_a(self):
        return True

    @authorized(roles=("operator",))
    def op_b(self):
        return True


class AuthorizedTestCase(unittest.TestCase):
    def test_access_by_anonymous(self):
        """Ensure anonymous has no access."""
        s = MyService()

        self.assertRaises(SecurityError, lambda: s.op_a())
        self.assertRaises(SecurityError, lambda: s.op_b())

    def test_access_by_authenticated(self):
        """Ensure authenticated principal has access to `op_a` but
        not to `op_b`.
        """
        s = MyService()

        s.principal = Principal()
        assert s.op_a()
        self.assertRaises(SecurityError, lambda: s.op_b())

    def test_access_by_authorized(self):
        """Ensure principal with role `operator` has access to `op_b`."""
        s = MyService()

        s.principal = Principal(roles=("user", "operator"))
        assert s.op_a()
        assert s.op_b()
