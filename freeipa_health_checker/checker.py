
import argparse, sys, os, re, yaml
from datetime import datetime

from .utils import get_logger, execute, create_logger, get_file_full_path
from .checker_helper import Log
from . import settings, messages, checker_helper as helper


class HealthChecker(object):

    def __init__(self, sys_args=None):
        self.sys_args = sys_args if sys_args else sys.argv[1:]
        self.logger = get_logger()

        self.parser = self.__register_cli()
        self.parsed_args = self.parser.parse_args(self.sys_args)

    def __register_cli(self):
        """
        Register all CLI commands and their arguments
        """
        parser = argparse.ArgumentParser(description="IPA Health Checker")

        parent_parser = argparse.ArgumentParser(add_help=False)
        parent_parser.add_argument('--config-file')

        subparsers = parser.add_subparsers(dest='command')

        list_nssdb = subparsers.add_parser('list_certs', parents=[parent_parser])
        list_nssdb.add_argument('path')

        subparsers.add_parser('certs_expired', parents=[parent_parser])

        subparsers.add_parser('full_check', parents=[parent_parser])

        ck_ra_cert = subparsers.add_parser('ck_ra_cert_serialnumber', parents=[parent_parser])
        ck_ra_cert.add_argument('--pem-dir', help='Path of pem file')
        ck_ra_cert.add_argument('--nssdb-dir', help='Path of NSS database')

        subparsers.add_parser('ck_kra_setup', parents=[parent_parser])

        return parser

    def run_cli(self):
        args = self.parser.parse_args(self.sys_args)
        if not hasattr(self, args.command):
            self.logger.error('command not found')
            return

        from_func = getattr(self, args.command)()
        if isinstance(from_func, Log):
            for message, status in from_func.logs:
                getattr(self.logger, status)(message)
            return from_func.logs

        return from_func

    def list_certs(self, path=None):
        """
        Method to list the certificates in a given path.

        Returns:
            A list of tuples where which tuple has the name of the
            certificate and its properties.

            eg: [('subsystemCert cert-pki-ca', 'u,u,u')]
        """

        path = path if path else self.parsed_args.path
        command = 'certutil -d {} -L'
        command = command.format(path)

        self.logger.debug('Running command: $ {}'.format(command))

        cert_list = self._execute_and_get_certs(command)

        self.logger.debug('Certificates found: {}'.format(cert_list))

        return cert_list

    def _execute_and_get_certs(self, command):
        certs = execute(command)

        cert_list = []
        for cert in certs:
            extracted = helper.extract_cert_name(cert)
            if extracted:
                cert_list.append(extracted)

        return cert_list

    def _get_cert(self, path, cert_name):
        command = 'certutil -d {} -L -n \"{}\"'
        command = command.format(path, cert_name)

        self.logger.debug('Running command: $ {}'.format(command))

        return execute(command)

    def __read_certs_config_file(self):
        config_data = None

        full_path = None

        if self.parsed_args.config_file:
            full_path = self.parsed_args.config_file
        else:
            full_path = get_file_full_path(settings.CERTS_CONFIG_FILE)

        with open(full_path) as f:
            config_data = yaml.load(f.read())
        return config_data

    def certs_expired(self):
        """
        Method to check if the certificates are expired or are not valid yet.
        This is done looking for the certs_expired field in the certs_list.yaml file.

        Returns:
            A list of tuples where which tuple has the name of the
            certificate and its status.

            eg: [('subsystemCert cert-pki-ca', True),
                 ('Server-Cert cert-pki-ca', False)]
        """

        certs_status = []
        config_data = self.__read_certs_config_file()

        for item in config_data['certs_expired']:
            certs_status += self.__check_certs_validity_in_path(item['path'])

        self.logger.info(messages.check_done())
        return certs_status

    def __check_certs_validity_in_path(self, path):

        certs_status = []
        cert_list = self.list_certs(path=path)

        for cert_name, _ in cert_list:
            cert_details = self._get_cert(path, cert_name)
            from_date, until_date = helper.parse_date_field(cert_details)

            today = datetime.today()
            status = False

            if today > until_date:
                self.logger.error(messages.certificate_expired(cert_name, from_date, until_date))

            elif today < from_date:
                self.logger.error(messages.certificate_not_valid_yet(cert_name, from_date,
                                  until_date))
            else:
                status = True

            certs_status.append((cert_name, status))

        return certs_status

    def full_check(self):
        """
        Method to check if the certificates listed on file certs_list.yaml
        exists where they should exist and if they have the right trust flags.

        Returns: A list of logs that will be printed on the run_cli function
        """
        logs = Log()

        config_data = self.__read_certs_config_file()

        for row in config_data['certs']:

            if row['type'] == 'nssdb':
                self.__process_nssdb(logs, row)

                # elif row['type'] == 'crt':
                #     self.__process_crt_certs(logs, row)

        logs.info(messages.check_done())
        return logs

    def __process_crt_certs(self, logs, row):
        try:
            x509.load_certificate_from_file(row['path'])
        except:
            self.logger.error(messages.cert_not_in_path(None, row['path']))

    def __process_nssdb(self, logs, row):
        certs_from_path = self.list_certs(row['path'])
        certs_names = [cert[0] for cert in certs_from_path]

        is_in_path = helper.check_path(logs, row, certs_names)

        if is_in_path:
            helper.check_flags(logs, row, certs_names, certs_from_path)

        helper.check_is_monitoring(logs, row)

    def ck_kra_setup(self):
        """
        Method to check if the environment has the KRA module installed. If
        it has, the tool checks if the certificate was created.

        Returns: A dict of status; eg:
            {'kra_in_expected_path': False, 'kra_cert_present': False}
        """

        result = {'kra_in_expected_path': False, 'kra_cert_present': False}

        config_data = self.__read_certs_config_file()
        path_to_kra = config_data['kra_setup']['kra_dir']
        cert_nssdb_path = config_data['kra_setup']['cert_path']

        if os.path.exists(path_to_kra) and os.path.isdir(path_to_kra):
            result['kra_in_expected_path'] = True

        certs_from_path = self.list_certs(cert_nssdb_path)
        certs_names = [cert[0] for cert in certs_from_path]

        kra_certs = filter(lambda cert: 'kra' in cert.lower(), certs_names)

        if any(kra_certs):
            result['kra_cert_present'] = True

        self.logger.info(messages.kra_status(result['kra_in_expected_path'],
                         result['kra_cert_present']))
        return result

    def ck_ra_cert_serialnumber(self, cert_name='ipaCert'):
        from . import ldap_helper
        from ipalib import x509

        cert_serial_number = None

        if self.parsed_args.pem_dir:
            pem_cert_dir = self.parsed_args.pem_dir
            certificate = x509.load_certificate_from_file(pem_cert_dir)
            cert_serial_number = certificate.serial_number

        if self.parsed_args.nssdb_dir:
            cert_data = self._get_cert(self.parsed_args.nssdb_dir, cert_name)
            cert_serial_number = int(re.findall('\d+', cert_data[3])[0])

        ldap_serialnumber = ldap_helper.get_ra_cert_serialnumber()
        are_equal = cert_serial_number == ldap_serialnumber

        if not are_equal:
            self.logger.error(messages.ra_cert_different(cert_serial_number, ldap_serialnumber))
        else:
            self.logger.info(messages.check_done())

        return are_equal


if __name__ == '__main__':
    create_logger()
    HealthChecker().run_cli()
