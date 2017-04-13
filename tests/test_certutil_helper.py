
import unittest, os
from freeipa_health_checker import commands_helper


class TestCertUtil(unittest.TestCase):

    maxDiff = None
    path_to_mock_files = os.getcwd() + '/tests/mock_files/'
    mock_config_certs_file = path_to_mock_files + 'certs_list_mock.yaml'

    def test_list_certs(self):
        certs_list = [('caSigningCert cert-pki-ca', 'CTu,Cu,Cu'),
                      ('Server-Cert cert-pki-ca', 'u,u,u'),
                      ('auditSigningCert cert-pki-ca', 'u,u,Pu'),
                      ('ocspSigningCert cert-pki-ca', 'u,u,u'),
                      ('subsystemCert cert-pki-ca', 'u,u,u')]

        self.assertEqual(certs_list, commands_helper.list_certs(self.path_to_mock_files))
