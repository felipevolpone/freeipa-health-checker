
from . import messages, checker, parser, base, commands_helper


class HealthChecker(base.BaseCLI):

    def full_check(self):
        """
        Method to check if the certificates listed on file certs_list.yaml:
            * exists in the provided path
            * if they have the right trust flags
            * if they are expired or not valid yet
        """

        config_data = self._read_certs_config_file()
        for row in config_data['certs']:

            if row['type'] == 'nssdb':
                cert = self.__parse_nssdb_cert(row)

            elif row['type'] == 'crt':
                cert = self.__parse_crt_or_pem_cert(row)

            elif row['type'] == 'pem':
                cert = self.__parse_crt_or_pem_cert(row)

            if cert:
                self.__apply_all_checks(cert, row)

        self.logger.info(messages.check_done())

    def __apply_all_checks(self, certificate, row):
        checker.check_is_expired(certificate)
        checker.check_is_monitoring(certificate.name)

        if row.get('trustflags'):
            checker.check_trust_flags(certificate, row['trustflags'])

    def __parse_nssdb_cert(self, row):
        cert_text = commands_helper.get_cert(row['path'], row['name'])
        trust_flags = commands_helper.get_certs_trust_flags(row['path'], row['name'])

        certdb = parser.nssdb_cert_to_basecertificate(cert_text)
        certificate = parser.certdb_to_basecertificate(certdb, row['name'], trust_flags)
        return certificate

    def __parse_crt_or_pem_cert(self, row):
        from ipalib import x509

        cert = None
        try:
            cert = x509.load_certificate_from_file(row['path'])
        except IOError:
            self.logger.error(messages.cert_not_in_path("", row['path']))
            return None

        trust_flags = None
        cert_name = row.get('name')

        if cert_name:
            trust_flags = commands_helper.get_certs_trust_flags(row['path'], cert_name)

        return parser.certdb_to_basecertificate(cert, cert_name, trust_flags)

    def ck_kra_setup(self):
        """
        Method to check if the environment has the KRA module installed. If
        it has, the tool checks if the certificate was created.

        Returns: A dict of status; eg:
            {'kra_in_expected_path': False, 'kra_cert_present': False}
        """

        config_data = self._read_certs_config_file()
        path_to_kra = config_data['kra_setup']['kra_dir']
        cert_nssdb_path = config_data['kra_setup']['cert_path']
        certs_from_path = commands_helper.list_certs(cert_nssdb_path)

        result = checker.check_kra_setup(path_to_kra, cert_nssdb_path, certs_from_path)

        self.logger.info(messages.kra_status(result['kra_in_expected_path'],
                         result['kra_cert_present']))

        self.logger.info(messages.check_done())
        return result

    def ck_ra_cert(self):
        """
        A method to check if PKI certificates in IPA NSS
        databases map correctly to PKI user in PKI LDAP database.
        """

        config_data = self._read_certs_config_file()
        cert_serial_number, ldap_serialnumber = checker.check_ra_cert(config_data)

        if not cert_serial_number == ldap_serialnumber:
            self.logger.error(messages.ra_cert_different(cert_serial_number, ldap_serialnumber))

        self.logger.info(messages.local_cert_serialnumber(cert_serial_number))
        self.logger.info(messages.ldap_cert_serialnumber(ldap_serialnumber))
        self.logger.info(messages.check_done())

        return cert_serial_number == ldap_serialnumber
