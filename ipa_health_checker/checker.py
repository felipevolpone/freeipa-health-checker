
import argparse
import sys
import subprocess
from subprocess import Popen
import logging


def create_logger():
    root = logging.getLogger('ipa-hc')
    root.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s\
     - %(message)s')
    console_handler.setFormatter(formatter)

    root.addHandler(console_handler)


def get_logger():
    return logging.getLogger('ipa-hc')


class Runner(object):

    def _run(self, command):
        processor = Popen(command, stderr=None, stdout=subprocess.PIPE,
                          shell=True)
        return processor.communicate()


class HealthChecker(Runner):

    def __init__(self):
        self.logger = get_logger()

        parser = argparse.ArgumentParser(description="IPA Health Checker")
        subparsers = parser.add_subparsers(dest='command')

        list_nssdb = subparsers.add_parser('list_nssdb_certs')

        command = sys.argv[1]
        if not hasattr(self, command):
            self.logger.error('command not found')
            parser.print_help()
            return

        getattr(self, command)(list_nssdb)

    def list_nssdb_certs(self, subparser):
        subparser.add_argument('path')
        subparser.add_argument('--cert_name', help='certifacate name')
        args = subparser.parse_args(sys.argv[2:])

        command = 'certutil -d {} -L'
        command = command.format(args.path)

        if args.cert_name:
            command += ' -n "{}"'.format(args.cert_name)

        self.logger.debug('Running command {}'.format(command))
        output = self._run(command)
        self.logger.info(output)


if __name__ == '__main__':
    create_logger()
    HealthChecker()
