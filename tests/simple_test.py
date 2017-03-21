import unittest

from ipa_health_checker import checker

class ParseArgsTest(unittest.TestCase):

    def test_example(self):
        self.assertEquals("checking", checker.parse_args([]))

