import unittest
import os
from freeipa_health_checker.checker import HealthChecker
from freeipa_health_checker import checker_helper as helper, settings
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

    def test_certs_expired(self):
        hc = HealthChecker(sys_args=['certs_expired', self.mock_certs_path])

        expected = [('caSigningCert cert-pki-ca', True),
                    ('Server-Cert cert-pki-ca', True),
                    ('auditSigningCert cert-pki-ca', True),
                    ('ocspSigningCert cert-pki-ca', True),
                    ('subsystemCert cert-pki-ca', True)]

        self.assertEqual(expected, hc.certs_expired())

    def test_all_certificates_were_created(self):
        mock_file_path = self.mock_certs_path + 'certs_list_mock.csv'
        hc = HealthChecker(sys_args=['ck_path_and_flags', '--csv_file', mock_file_path])

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

        self.assertEqual(True, hc.ck_path_and_flags())

        # checking in case that the cert is not found
        content = "/etc/pki/nssdb;subsystemCert cert-pki-ca;"

        with open(mock_file_path, 'a') as f:
            f.writelines(content)

        self.assertEqual(False, hc.ck_path_and_flags())

        # checking the case that the cert has the wrong trust flags
        certs[0] = ('caSigningCert cert-pki-ca', 'u,u,u')
        content = create_content(certs)

        with open(mock_file_path, 'w+') as f:
            f.writelines(content)

        self.assertEqual(False, hc.ck_path_and_flags())

    def test_ck_kra_setup(self):
        kra_path = self.mock_certs_path + 'kra'

        # removing possible stuff leave behind
        if os.path.exists(kra_path):
            os.rmdir(kra_path)
        os.mkdir(kra_path)

        settings.KRA_DEFAULT_DIR_PATH = kra_path
        settings.KRA_DEFAULT_CERT_PATH = self.mock_certs_path

        cert_data = [('caSigningCert cert-pki-ca', 'CTu,Cu,Cu'),
                     ('Server-Cert cert-pki-ca', 'u,u,u'),
                     ('auditSigningCert cert-pki-ca', 'u,u,Pu'),
                     ('ocspSigningCert cert-pki-ca', 'u,u,u'),
                     ('subsystemCert cert-pki-ca', 'u,u,u'),
                     ('subsystemCert cert-kra-ca', 'u,u,u')]  # mock data

        def fake_execute_and_get_certs(command):
            return cert_data

        hc = HealthChecker(sys_args=['ck_kra_setup'])
        hc._execute_and_get_certs = fake_execute_and_get_certs

        # testing when kra is present and it has dir
        result_expected = {'kra_in_expected_path': True, 'kra_cert_present': True}
        self.assertEqual(result_expected, hc.ck_kra_setup())

        os.rmdir(kra_path)

        # testing when kra is not present and it hasn't the dir
        del cert_data[-1]
        result_expected = {'kra_in_expected_path': False, 'kra_cert_present': False}
        self.assertEqual(result_expected, hc.ck_kra_setup())


class TestHelper(unittest.TestCase):

    mock_certs_path = os.getcwd() + '/tests/mock_files/'

    def test_check_cert_date(self):
        hc = HealthChecker(sys_args=['list_certs', self.mock_certs_path])

        cert_data = hc._get_cert(self.mock_certs_path, 'Server-Cert cert-pki-ca')

        self.assertEqual(True, helper.compare_cert_date(cert_data))

        last_year = datetime.now().year - 1
        cert_data[8] = 'Not After : Tue Mar 12 21:35:13 {}'.format(last_year)
        self.assertEqual(False, helper.compare_cert_date(cert_data))
