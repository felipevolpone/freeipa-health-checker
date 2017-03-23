import unittest

from ipa_health_checker.checker import HealthChecker
from ipa_health_checker import checker
from datetime import datetime


class TestHealthChecker(unittest.TestCase):

    def test_list_certs(self):
        hc = HealthChecker(sys_args=['list_certs', 'path'])

        def fake_run(command):
            certs = """
\nCertificate Nickname                                         Trust Attributes\n                                                             SSL,S/MIME,JAR/XPI\n\ncaSigningCert cert-pki-ca                                    CTu,Cu,Cu\nServer-Cert cert-pki-ca                                      u,u,u\nauditSigningCert cert-pki-ca                                 u,u,Pu\nocspSigningCert cert-pki-ca                                  u,u,u\nsubsystemCert cert-pki-ca                                    u,u,u\n
            """
            return (certs, None)

        checker.execute = fake_run
        certs_list = [('caSigningCert cert-pki-ca', 'CTu,Cu,Cu'),
                      ('Server-Cert cert-pki-ca', 'u,u,u'),
                      ('auditSigningCert cert-pki-ca', 'u,u,Pu'),
                      ('ocspSigningCert cert-pki-ca', 'u,u,u'),
                      ('subsystemCert cert-pki-ca', 'u,u,u')]

        self.assertEquals(certs_list, hc.list_certs())

    def test_check_cert_is_valid(self):

        cert_data = """Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 3 (0x3)
            Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption
            Issuer: "CN=Certificate Authority,O=LOCALHOST"
            Validity:
                Not Before: Wed Mar 22 21:35:13 {}
                Not After : Tue Mar 12 21:35:13 {}
        """

        current_year = datetime.today().year
        expiration_year = current_year + 2

        cert_data_to_succeed = cert_data.format(current_year, expiration_year)
        cert_data_to_succeed = cert_data_to_succeed.splitlines()

        hc = HealthChecker(sys_args=['list_certs', 'path'])
        self.assertEquals(True, hc._check_cert_is_valid(cert_data_to_succeed))

        cert_data_to_failure = cert_data.format(current_year,
                                                expiration_year - 2)
        cert_data_to_failure = cert_data_to_failure.splitlines()

        self.assertEquals(False, hc._check_cert_is_valid(cert_data_to_failure))
