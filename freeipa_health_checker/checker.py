
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

        subparsers = parser.add_subparsers(dest='command')

        list_nssdb = subparsers.add_parser('list_certs')
        list_nssdb.add_argument('path')

        subparsers.add_parser('certs_expired')

        ck_path_certs = subparsers.add_parser('full_check')
        ck_path_certs.add_argument('--config-file', help='A YAML file with info of path and name \
of the certs. Check the docs for more info')

        ck_ra_cert = subparsers.add_parser('ck_ra_cert_serialnumber')
        ck_ra_cert.add_argument('--pem-dir', help='Path of pem file')
        ck_ra_cert.add_argument('--nssdb-dir', help='Path of NSS database')

        ck_kra = subparsers.add_parser('ck_kra_setup')
        ck_kra.add_argument('--dir', help='Where the kra dir should be found',
                            default=settings.KRA_DEFAULT_DIR_PATH)
        ck_kra.add_argument('--cert', help='Where the kra cert should be found',
                            default=settings.KRA_DEFAULT_CERT_PATH)

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

        full_path = get_file_full_path(settings.CERTS_CONFIG_FILE)

        config_data = None
        with open(full_path) as f:
            config_data = yaml.load(f.read())

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

        full_path = (self.parsed_args.config_file if self.parsed_args.config_file
                     else get_file_full_path(settings.CERTS_CONFIG_FILE))

        certs_data = None
        with open(full_path) as f:
            certs_data = yaml.load(f.read())

        for row in certs_data['certs']:
            certs_from_path = self.list_certs(row['path'])
            certs_names = [cert[0] for cert in certs_from_path]

            is_in_path = helper.check_path(logs, row, certs_names)

            if is_in_path:
                helper.check_flags(logs, row, certs_names, certs_from_path)

            helper.check_is_monitoring(logs, row)

        logs.info(messages.check_done())
        return logs

    def ck_kra_setup(self):
        """
        Method to check if the environment has the KRA module installed. If
        it has, the tool checks if the certificate was created.

        Returns: A dict of status; eg:
            {'kra_in_expected_path': False, 'kra_cert_present': False}
        """

        path_to_kra = self.parsed_args.dir

        result = {'kra_in_expected_path': False, 'kra_cert_present': False}

        if os.path.exists(path_to_kra) and os.path.isdir(path_to_kra):
            result['kra_in_expected_path'] = True

        certs_from_path = self.list_certs(self.parsed_args.cert)
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

        return cert_serial_number == ldap_helper.get_ra_cert_serialnumber()


if __name__ == '__main__':
    create_logger()
    HealthChecker().run_cli()
