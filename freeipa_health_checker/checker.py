
import csv, argparse, sys, os
from .utils import get_logger, execute, create_logger, get_file_full_path
from . import checker_helper as helper
from . import settings


class HealthChecker(object):

    def __init__(self, sys_args=None):
        self.sys_args = sys_args if sys_args else sys.argv[1:]
        self.logger = get_logger()

        self.parser = argparse.ArgumentParser(description="IPA Health Checker")
        subparsers = self.parser.add_subparsers(dest='command')

        list_nssdb = subparsers.add_parser('list_certs')
        list_nssdb.add_argument('path')

        certs_valid = subparsers.add_parser('certs_expired')
        certs_valid.add_argument('path')

        subparsers.add_parser('ck_path_and_flags')
        subparsers.add_parser('ck_kra_setup')

        self.parsed_args = self.parser.parse_args(self.sys_args)

    def run_cli(self):
        args = self.parser.parse_args(self.sys_args)
        if not hasattr(self, args.command):
            self.logger.error('command not found')
            return

        getattr(self, args.command)()

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
        Method to check if the certificates in a given path
        expired  (if they expiration date are valid).

        Returns:
            A list of tuples where which tuple has the name of the
            certificate and its status.

            eg: [('subsystemCert cert-pki-ca', True),
                 ('Server-Cert cert-pki-ca', False)]
        """

        cert_list = self.list_certs()

        certs_status = []

        for cert_name, _ in cert_list:
            cert_details = self._get_cert(self.parsed_args.path, cert_name)
            is_valid = helper.compare_cert_date(cert_details)

            certs_status.append((cert_name, is_valid))

            self.logger.info('Certificate \"{}\" is expired: {}'.format(
                cert_name, not is_valid))

        return certs_status

    def ck_path_and_flags(self, cert_list_file=None):
        """
        Method to check if the certificates listed on file certs_list.csv
        exists where they should exist and if they have the right trust flags.

        Args:
            cert_list_file: if it is not None, will not use the
            cert_list.csv file.

        Returns: True or False
        """

        certs_list_path = cert_list_file if cert_list_file else settings.CERTS_LIST_FILE
        full_path = get_file_full_path(certs_list_path)

        with open(full_path) as f:

            certs_from_path, old_path = None, None

            for row in csv.DictReader(f, delimiter=';'):

                if row['path'] != old_path:
                    certs_from_path = self.list_certs(row['path'])

                certs_names = [cert[0] for cert in certs_from_path]

                if row['name'] not in certs_names:
                    helper.treat_cert_not_found(self.logger, row)
                    return False

                cert_index = certs_names.index(row['name'])
                cert_flags = certs_from_path[cert_index][1]

                if row['flags'] != cert_flags:
                    helper.treat_cert_with_wrong_flags(self.logger, row, cert_flags)
                    return False

                old_path = row['path']

        self.logger.info('Certificates checked successfully.')
        return True

    def ck_kra_setup(self):
        path_to_kra = settings.KRA_DEFAULT_DIR_PATH

        result = {'kra_in_expected_path': False, 'kra_cert_present': False}

        if os.path.exists(path_to_kra) and os.path.isdir(path_to_kra):
            result['kra_in_expected_path'] = True

        certs_from_path = self.list_certs(settings.KRA_DEFAULT_CERT_PATH)
        certs_names = [cert[0] for cert in certs_from_path]

        kra_certs = filter(lambda cert: 'kra' in cert.lower(), certs_names)

        if any(kra_certs):
            result['kra_cert_present'] = True

        message = 'KRA is installed: {installed}. Cert was found: {cert_found}'
        message = message.format(installed=result['kra_in_expected_path'],
                                 cert_found=result['kra_cert_present'])

        self.logger.info(message)

        return result


if __name__ == '__main__':
    create_logger()
    HealthChecker().run_cli()
