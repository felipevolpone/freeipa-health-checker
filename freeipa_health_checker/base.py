
import argparse, sys, yaml
from .utils import get_file_full_path, create_logger


class BaseCLI(object):

    CERTS_CONFIG_FILE = 'certs_config.yaml'

    def __init__(self, sys_args=None):
        self.sys_args = sys_args if sys_args else sys.argv[1:]
        self.logger = create_logger()

        self.parser = self.__register_cli()
        self.parsed_args = self.parser.parse_args(self.sys_args)

    def run_cli(self, classes=[]):
        args = self.parser.parse_args(self.sys_args)

        for clazz in classes:
            instance = clazz()
            if hasattr(instance, args.command):
                return getattr(instance, args.command)()

        self.logger.error('command not found')

    def __register_cli(self):
        """
        Register all CLI commands and their arguments
        """
        parser = argparse.ArgumentParser(description="IPA Health Checker")

        parent_parser = argparse.ArgumentParser(add_help=False)
        parent_parser.add_argument('--config-file')

        subparsers = parser.add_subparsers(dest='command')

        subparsers.add_parser('full_check', parents=[parent_parser])

        listcerts = subparsers.add_parser('list_certs')
        listcerts.add_argument('path', help='Path of a nss database')

        subparsers.add_parser('ck_ra_cert', parents=[parent_parser])
        subparsers.add_parser('ck_kra_setup', parents=[parent_parser])

        return parser

    def _read_certs_config_file(self):
        config_data = None

        full_path = None

        if self.parsed_args.config_file:
            full_path = self.parsed_args.config_file
        else:
            full_path = get_file_full_path(self.CERTS_CONFIG_FILE)

        with open(full_path) as f:
            config_data = yaml.load(f.read())
        return config_data
