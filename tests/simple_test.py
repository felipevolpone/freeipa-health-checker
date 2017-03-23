import unittest

from ipa_health_checker.checker import HealthChecker
from ipa_health_checker import checker
from collections import namedtuple


class TestHealthChecker(unittest.TestCase):

    def test_list_nssdb_certs(self):
        hc = HealthChecker(sys_args=['checker.py', 'list_nssdb_certs', 'path'])

        Namespace = namedtuple('Namespace', 'path cert_name')
        args = Namespace('path', None)

        fake_output = '\nCertificate Nickname Trust Attributes\n SSL,S/MIME,\
JAR/XPI\n\n'

        def fake_run(command):
            return fake_output

        checker.execute = fake_run
        self.assertEquals(fake_output, hc.list_nssdb_certs(args))
