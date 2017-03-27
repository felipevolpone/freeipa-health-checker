import unittest
import os
import json
from ipa_health_checker.checker import HealthChecker
from datetime import datetime


class TestHealthChecker(unittest.TestCase):
    """
    These unit tests are actually integreation tests that run
    without mocks. So, it's expected that the certutil
    command is installed on the system.
    """

    mock_certs_path = os.getcwd() + '/tests/mock_files/'

    def test_list_certs(self):
        hc = HealthChecker(sys_args=['list_certs', self.mock_certs_path])

        certs_list = [('caSigningCert cert-pki-ca', 'CTu,Cu,Cu'),
                      ('Server-Cert cert-pki-ca', 'u,u,u'),
                      ('auditSigningCert cert-pki-ca', 'u,u,Pu'),
                      ('ocspSigningCert cert-pki-ca', 'u,u,u'),
                      ('subsystemCert cert-pki-ca', 'u,u,u')]

        self.assertEqual(certs_list, hc.list_certs())

    def test_check_cert_is_valid(self):
        hc = HealthChecker(sys_args=['list_certs', self.mock_certs_path])

        cert_data = hc._get_cert(self.mock_certs_path,
                                 'Server-Cert cert-pki-ca')
        self.assertEqual(True, hc._check_cert_is_valid(cert_data))

        last_year = datetime.now().year - 1
        cert_data[8] = 'Not After : Tue Mar 12 21:35:13 {}'.format(last_year)
        self.assertEqual(False, hc._check_cert_is_valid(cert_data))

    def test_certs_are_valid(self):
        hc = HealthChecker(sys_args=['certs_are_valid', self.mock_certs_path])

        expected = [('caSigningCert cert-pki-ca', True),
                    ('Server-Cert cert-pki-ca', True),
                    ('auditSigningCert cert-pki-ca', True),
                    ('ocspSigningCert cert-pki-ca', True),
                    ('subsystemCert cert-pki-ca', True)]

        self.assertEqual(expected, hc.certs_are_valid())

    def test_all_certificates_were_created(self):
        hc = HealthChecker(sys_args=['all_certs_created'])
        mock_file_path = self.mock_certs_path + 'certs_list_mock.csv'

        certs_names = ["Server-Cert cert-pki-ca",
                       "caSigningCert cert-pki-ca",
                       "auditSigningCert cert-pki-ca",
                       "ocspSigningCert cert-pki-ca",
                       "subsystemCert cert-pki-ca"]

        content = "path,cert_name\n"

        for name in certs_names:
            content += "{path},{name}\n".format(path=self.mock_certs_path,
                                                name=name)

        with open(mock_file_path, 'w+') as f:
            f.writelines(content)

        self.assertEqual(True,
                         hc.all_certs_created(cert_list_file=mock_file_path))

        content = "/etc/pki/nssdb,subsystemCert cert-pki-ca"

        with open(mock_file_path, 'a') as f:
            f.writelines(content)

        self.assertEqual(False,
                         hc.all_certs_created(cert_list_file=mock_file_path))
