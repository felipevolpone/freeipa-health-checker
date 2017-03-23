
import argparse
import sys
import re
from datetime import datetime
from .utils import get_logger, execute, create_logger


class HealthChecker(object):

    CERT_DATE_FORMAT = '%a %b %d %H:%M:%S %Y'

    def __init__(self, sys_args=None):
        self.sys_args = sys_args if sys_args else sys.argv[1:]
        self.logger = get_logger()

        self.parser = argparse.ArgumentParser(description="IPA Health Checker")
        subparsers = self.parser.add_subparsers(dest='command')

        list_nssdb = subparsers.add_parser('list_certs')
        list_nssdb.add_argument('path')

        certs_valid = subparsers.add_parser('certs_are_valid')
        certs_valid.add_argument('path')

        self.parsed_args = self.parser.parse_args(self.sys_args)

    def run_cli(self):
        args = self.parser.parse_args(self.sys_args)
        if not hasattr(self, args.command):
            self.logger.error('command not found')
            return

        getattr(self, args.command)()

    def list_certs(self):
        """
        Method to list the certificates in a given path.

        Returns:
            A list of tuples where which tuple has the name of the
            certificate and its properties.

            eg: [('subsystemCert cert-pki-ca', 'u,u,u')]
        """

        command = 'certutil -d {} -L'
        command = command.format(self.parsed_args.path)

        self.logger.debug('Running command: $ {}'.format(command))
        output = execute(command)
        certs = output[0].splitlines()

        cert_list = []
        for cert in certs:
            extracted = self._extract_cert_name(cert)
            if extracted:
                cert_list.append(extracted)

        self.logger.info('Certificates found: {}'.format(cert_list))
        return cert_list

    def _extract_cert_name(self, cert):
        match = re.match(r'^(.+?)\s+(\w*,\w*,\w*)\s*$', cert)
        if match:
            return match.groups()

    def __get_cert(self, path, cert_name):
        command = 'certutil -d {} -L -n \"{}\"'
        command = command.format(path, cert_name)

        self.logger.debug('Running command: $ {}'.format(command))

        output = execute(command)
        output = output[0].splitlines()
        return output

    def _check_cert_is_valid(self, cert_details):
        valid_from, valid_until = cert_details[7], cert_details[8]

        valid_from = valid_from.split(': ')[1]
        valid_until = valid_until.split(': ')[1]

        from_date = datetime.strptime(valid_from, self.CERT_DATE_FORMAT)
        until_date = datetime.strptime(valid_until, self.CERT_DATE_FORMAT)
        now = datetime.today()

        return from_date < now and now < until_date

    def certs_are_valid(self):
        """
        Method to check if the certificates in a given path
        are valid  (if they expiration date are valid).

        Returns:
            A list of tuples where which tuple has the name of the
            certificate and its status.

            eg: [('subsystemCert cert-pki-ca', True),
                 ('Server-Cert cert-pki-ca', False)]
        """

        cert_list = self.list_certs()

        certs_status = []

        for cert in cert_list:
            cert_name = cert[0]
            cert_details = self.__get_cert(self.parsed_args.path, cert_name)
            is_valid = self._check_cert_is_valid(cert_details)

            certs_status.append((cert_name, is_valid))

            self.logger.info('Certificate \"{}\" is expired: {}'.format(
                cert_name, not is_valid))

        return certs_status


if __name__ == '__main__':
    create_logger()
    HealthChecker().run_cli()
