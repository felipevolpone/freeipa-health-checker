
import sys, os, logging


def create_logger():
    root = logging.getLogger('ipa-hc')
    root.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)

    if not any(root.handlers):
        root.addHandler(console_handler)

    return logging.getLogger('ipa-hc')


def get_file_full_path(file_path):
    return os.path.join(os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))),
                        file_path)


def get_logger():
    return logging.getLogger('ipa-hc')

