import unittest
import os
import yaml
from datetime import datetime
from freeipa_health_checker.checker import HealthChecker
from freeipa_health_checker import checker_helper
from freeipa_health_checker import settings


class TestHealthChecker(unittest.TestCase):
    """
    These unit tests are actually integreation tests that run
    without mocks. So, it's expected that the certutil
    command is installed on the system.
    """

    maxDiff = None
    path_mock_files = os.getcwd() + '/tests/mock_files/'

    def test_list_certs(self):
        hc = HealthChecker(sys_args=['list_certs', self.path_mock_files])

        certs_list = [('caSigningCert cert-pki-ca', 'CTu,Cu,Cu'),
                      ('Server-Cert cert-pki-ca', 'u,u,u'),
                      ('auditSigningCert cert-pki-ca', 'u,u,Pu'),
                      ('ocspSigningCert cert-pki-ca', 'u,u,u'),
                      ('subsystemCert cert-pki-ca', 'u,u,u')]

        self.assertEqual(certs_list, hc.list_certs())

    def test_certs_expired(self):

        # mocking data and methods
        current_year = datetime.now().year
        cert = ['Certificate:', 'Data:', 'Version: 3 (0x2)', 'Serial Number: 10 (0xa)',
                'Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption',
                'Issuer: "CN=Certificate Authority,O=IPA.EXAMPLE"',
                'Validity:',
                'Not Before: Sun Apr 02 14:53:02 ' + str(current_year - 1),
                'Not After : Fri Apr 02 14:53:02 ' + str(current_year + 2)]

        def fake_get_cert(x, y):
            return cert

        def fake_list_cert():
            return [('caSigningCert cert-pki-ca', 'u,u,u,u')]

        # a valid path is not used, because the method to get the certs from
        # the path will be mocked
        hc = HealthChecker(sys_args=['certs_expired', 'anything'])
        hc._get_cert = fake_get_cert
        hc.list_certs = fake_list_cert

        # testing when is valid
        expected = [('caSigningCert cert-pki-ca', True)]
        self.assertEqual(expected, hc.certs_expired())

        # testing when the certificate is not valid yet
        cert[7] = 'Not Before: Sun Apr 02 14:53:02 ' + str(current_year + 2)
        expected = [('caSigningCert cert-pki-ca', False)]
        self.assertEqual(expected, hc.certs_expired())

        # testing when the certificate expired
        cert[8] = 'Not After: Sun Apr 02 14:53:02 ' + str(current_year - 2)
        expected = [('caSigningCert cert-pki-ca', False)]
        self.assertEqual(expected, hc.certs_expired())

    def test_full_check(self):
        mock_file_path = self.path_mock_files + 'certs_list_mock.yaml'
        hc = HealthChecker(sys_args=['full_check', '--csv-file', mock_file_path])

        original_certs = {'certs': [
            {'path': self.path_mock_files,
             'monitored': False,
             'name': 'caSigningCert cert-pki-ca',
             'trustflags': 'CTu,Cu,Cu'},
            {'path': self.path_mock_files,
             'monitored': False,
             'name': 'Server-Cert cert-pki-ca',
             'trustflags': 'u,u,u'},
            {'path': self.path_mock_files,
             'monitored': True,
             'name': 'auditSigningCert cert-pki-ca',
             'trustflags': 'u,u,Pu'},
            {'path': self.path_mock_files,
             'monitored': True,
             'name': 'ocspSigningCert cert-pki-ca',
             'trustflags': 'u,u,u'},
            {'path': self.path_mock_files,
             'monitored': False,
             'name': 'subsystemCert cert-pki-ca',
             'trustflags': 'u,u,u'}
        ]}

        def create_config_file(certs):
            with open(mock_file_path, 'w+') as f:
                yaml.dump(certs, f)

        # the success case. nothing fails
        create_config_file(original_certs)
        self.assertEqual(1, len(hc.full_check().logs))

        # checking in case when the cert is not found
        import copy
        certs = copy.deepcopy(original_certs)
        certs['certs'][0]['path'] = '/tmp'
        create_config_file(certs)
        self.assertEqual(3, len(hc.full_check().logs))

        # checking the case that the cert has the wrong trust flags
        certs = copy.deepcopy(original_certs)
        certs['certs'][0]['trustflags'] = 'u,u,u'
        create_config_file(certs)
        self.assertEqual(3, len(hc.full_check().logs))

        # checking when the cert is not in the getcert monitoring
        def fake_getcert_list_result():
            with open(self.path_mock_files + 'getcert_list_result.txt') as f:
                return checker_helper.process_getcert_data(f.read())

        certs = copy.deepcopy(original_certs)
        certs['certs'][0]['monitored'] = True
        create_config_file(certs)

        hc = HealthChecker(sys_args=['full_check', '--csv-file', mock_file_path])
        checker_helper.getcert_list = fake_getcert_list_result

        self.assertEqual(3, len(hc.full_check().logs))

    def test_ck_kra_setup(self):
        kra_path = self.path_mock_files + 'kra'

        # removing possible stuff leave behind
        if os.path.exists(kra_path):
            os.rmdir(kra_path)
        os.mkdir(kra_path)

        settings.KRA_DEFAULT_DIR_PATH = kra_path
        settings.KRA_DEFAULT_CERT_PATH = self.path_mock_files

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
        result_expected = {'kra_in_expected_path': True,
                           'kra_cert_present': True}
        self.assertEqual(result_expected, hc.ck_kra_setup())

        os.rmdir(kra_path)

        # testing when kra is not present and it hasn't the dir
        del cert_data[-1]
        result_expected = {'kra_in_expected_path': False, 'kra_cert_present': False}
        self.assertEqual(result_expected, hc.ck_kra_setup())

    # @unittest.skipIf(os.environ.get('IS_TRAVIS'), 'travis does not have freeipa installed')
    @unittest.skip('refactoring checker')
    def test_ck_ra_cert_serialnumber(self):
        from freeipa_health_checker import settings, ldap_helper
        expected_serialnumber = 3

        def fake_ldap():
            return expected_serialnumber

        ldap_helper.get_ra_cert_serialnumber = fake_ldap

        hc = HealthChecker(sys_args=['ck_ra_cert_serialnumber', '--nssdb-dir',
                           self.path_mock_files])
        self.assertEqual(True, hc.ck_ra_cert_serialnumber('Server-Cert cert-pki-ca'))

        expected_serialnumber = 7
        self.assertEqual(False, hc.ck_ra_cert_serialnumber('Server-Cert cert-pki-ca'))
