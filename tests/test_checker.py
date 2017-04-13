import unittest, os, yaml
from datetime import datetime
from freeipa_health_checker import checker
from freeipa_health_checker.cli import HealthChecker
from freeipa_health_checker.parser import BaseCertificate


class TestHealthChecker(unittest.TestCase):

    maxDiff = None
    path_to_mock_files = os.getcwd() + '/tests/mock_files/'
    mock_config_certs_file = path_to_mock_files + 'certs_list_mock.yaml'

    def create_config_file(self, certs):
        with open(self.mock_config_certs_file, 'w+') as f:
            yaml.dump(certs, f)

    def test_certs_expired(self):

        today = datetime.today()
        from_date = datetime(today.year - 2, today.month, today.day)
        until_date = datetime(today.year + 2, today.month, today.day)

        certificate = BaseCertificate(valid_not_before=from_date, valid_not_after=until_date)
        self.assertIsNone(checker.check_is_expired(certificate))

        next_year = datetime(today.year + 1, today.month, today.day)
        certificate = BaseCertificate(valid_not_before=next_year, valid_not_after=until_date,
                                      name='anything')
        self.assertEqual('not_valid_yet', checker.check_is_expired(certificate))

        until_date = datetime(today.year - 1, today.month, today.day)
        certificate = BaseCertificate(valid_not_before=from_date, valid_not_after=until_date,
                                      name='anything')
        self.assertEqual('expired', checker.check_is_expired(certificate))

    def test_ck_kra_setup(self):
        kra_path = self.path_to_mock_files + 'kra'

        # removing possible stuff leave behind
        if os.path.exists(kra_path):
            os.rmdir(kra_path)

        # creating the dir to make the test pass
        os.mkdir(kra_path)

        # creating fake data
        certs_config_data = {'kra_setup': {'kra_dir': kra_path,
                                           'cert_path': self.path_to_mock_files}}
        self.create_config_file(certs_config_data)

        cert_data = [('caSigningCert cert-pki-ca', 'CTu,Cu,Cu'),
                     ('auditSigningCert cert-pki-ca', 'u,u,Pu'),
                     ('ocspSigningCert cert-pki-ca', 'u,u,u'),
                     ('subsystemCert cert-pki-ca', 'u,u,u'),
                     ('subsystemCert cert-kra-ca', 'u,u,u')]  # mock data

        def fake_execute_and_get_certs(command):
            return cert_data

        hc = HealthChecker(sys_args=['ck_kra_setup', '--config-file', self.mock_config_certs_file])
        hc.list_certs = fake_execute_and_get_certs

        # testing when kra is present and it has dir
        result_expected = {'kra_in_expected_path': True,
                           'kra_cert_present': True}
        self.assertEqual(result_expected, result_expected, checker.check_kra_setup(
            kra_path, self.path_to_mock_files, cert_data))

        # removing fake data
        os.rmdir(kra_path)

        # testing when kra is not present and it hasn't the dir
        del cert_data[-1]
        result_expected = {'kra_in_expected_path': False, 'kra_cert_present': False}
        self.assertEqual(result_expected, result_expected, checker.check_kra_setup(
            kra_path, self.path_to_mock_files, cert_data))

    @unittest.skipIf(os.environ.get('IS_TRAVIS') is not None,
                     'travis does not have freeipa installed')
    def test_ck_ra_cert_serialnumber(self):
        from freeipa_health_checker import ldap_helper
        expected_serialnumber = 3

        def fake_ldap():
            return expected_serialnumber

        # mocking the ldap call
        ldap_helper.get_ra_cert_serialnumber = fake_ldap

        # creating fake data
        certs_config_data = {'ck_ra_cert': {'pem_dir': '', 'nssdb_dir': self.path_to_mock_files}}

        cert_serial_number, ldap_serialnumber = checker.check_ra_cert(certs_config_data,
                                                                      'Server-Cert cert-pki-ca')
        self.assertEqual((3, 3), (cert_serial_number, ldap_serialnumber))

        expected_serialnumber = 7
        cert_serial_number, ldap_serialnumber = checker.check_ra_cert(certs_config_data,
                                                                      'Server-Cert cert-pki-ca')
        self.assertEqual((3, 7), (cert_serial_number, ldap_serialnumber))
