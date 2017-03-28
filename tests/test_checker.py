import unittest
import os
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

    def test_check_cert_date(self):
        hc = HealthChecker(sys_args=['list_certs', self.mock_certs_path])

        cert_data = hc._get_cert(self.mock_certs_path,
                                 'Server-Cert cert-pki-ca')
        self.assertEqual(True, hc._check_cert_date(cert_data))

        last_year = datetime.now().year - 1
        cert_data[8] = 'Not After : Tue Mar 12 21:35:13 {}'.format(last_year)
        self.assertEqual(False, hc._check_cert_date(cert_data))

    def test_certs_expired(self):
        hc = HealthChecker(sys_args=['certs_are_valid', self.mock_certs_path])

        expected = [('caSigningCert cert-pki-ca', True),
                    ('Server-Cert cert-pki-ca', True),
                    ('auditSigningCert cert-pki-ca', True),
                    ('ocspSigningCert cert-pki-ca', True),
                    ('subsystemCert cert-pki-ca', True)]

        self.assertEqual(expected, hc.certs_expired())

    def test_all_certificates_were_created(self):
        hc = HealthChecker(sys_args=['check_certs_in_right_path'])
        mock_file_path = self.mock_certs_path + 'certs_list_mock.csv'

        certs = [('caSigningCert cert-pki-ca', 'CTu,Cu,Cu'),
                 ('Server-Cert cert-pki-ca', 'u,u,u'),
                 ('auditSigningCert cert-pki-ca', 'u,u,Pu'),
                 ('ocspSigningCert cert-pki-ca', 'u,u,u'),
                 ('subsystemCert cert-pki-ca', 'u,u,u')]

        def create_content(certs):
            content = "path;name;flags\n"

            for name, flags in certs:
                content += ("{path};{name};{flags}\n".format(flags=flags, name=name,
                                                             path=self.mock_certs_path))
            return content

        content = create_content(certs)

        with open(mock_file_path, 'w+') as f:
            f.writelines(content)

        self.assertEqual(True, hc.check_certs_path_and_flags(cert_list_file=mock_file_path))
        # checking in case that the cert is not found
        content = "/etc/pki/nssdb;subsystemCert cert-pki-ca;"

        with open(mock_file_path, 'a') as f:
            f.writelines(content)

        self.assertEqual(False, hc.check_certs_path_and_flags(cert_list_file=mock_file_path))

        # checking the case that the cert has the wrong trust flags
        certs[0] = ('caSigningCert cert-pki-ca', 'u,u,u')
        content = create_content(certs)

        with open(mock_file_path, 'w+') as f:
            f.writelines(content)

        self.assertEqual(False, hc.check_certs_path_and_flags(cert_list_file=mock_file_path))
