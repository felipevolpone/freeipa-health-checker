
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


def execute(command):
    processor = Popen(command, stderr=None, stdout=subprocess.PIPE,
                      shell=True)
    return processor.communicate()


class HealthChecker(object):

    def __init__(self, sys_args=None):
        self.sys_args = sys_args if sys_args else sys.argv
        self.logger = get_logger()

        self.parser = argparse.ArgumentParser(description="IPA Health Checker")
        subparsers = self.parser.add_subparsers(dest='command')

        list_nssdb = subparsers.add_parser('list_nssdb_certs')
        list_nssdb.add_argument('path')
        list_nssdb.add_argument('--cert_name', help='certifacate name')
        self.parsed_args = list_nssdb.parse_args(self.sys_args[2:])

    def run(self):
        command = self.sys_args[1]
        if not hasattr(self, command):
            self.logger.error('command not found')
            self.parser.print_help()
            return

        getattr(self, command)(self.parsed_args)

    def list_nssdb_certs(self, args):
        command = 'certutil -d {} -L'
        command = command.format(args.path)

        if args.cert_name:
            command += ' -n "{}"'.format(args.cert_name)

        self.logger.debug('Running command {}'.format(command))
        output = execute(command)

        self.logger.info(output)
        return output


if __name__ == '__main__':
    create_logger()
    HealthChecker().run()
