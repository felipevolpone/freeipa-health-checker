
import subprocess
from subprocess import Popen
from . import utils, parser

logger = utils.get_logger()


def __execute(command, split=True):
    processor = Popen(command, stderr=None, stdout=subprocess.PIPE, shell=True)
    content = processor.communicate()[0].decode()
    return content.splitlines() if split else content


def get_cert(path, cert_name):
    """
    Method to get a certificate in a nss database path
    """
    command = 'certutil -d {} -L -n \"{}\" -a'
    command = command.format(path, cert_name)

    logger.debug('Running command: $ {}'.format(command))

    return __execute(command, split=False)


def get_certs_trust_flags(path, name):
    all_certs = list_certs(path)
    for cert_name, flags in all_certs:
        if cert_name == name:
            return flags

    return None


def list_certs(path):
    """
    Method to list the certificates in a given nss database path.

    Returns:
        A list of tuples where which tuple has the name of the
        certificate and its properties.

        eg: [('subsystemCert cert-pki-ca', 'u,u,u')]
    """

    command = 'certutil -d {} -L'.format(path)

    logger.debug('Running command: $ {}'.format(command))

    certs = __execute(command)

    cert_list = []
    for cert in certs:
        extracted = parser.extract_cert_name(cert)
        if extracted:
            cert_list.append(extracted)

    logger.debug('Certificates found: {}'.format(cert_list))

    return cert_list


def getcert_list():
    command = 'getcert list'
    output = __execute(command)
    all_text = '\n'.join(output)
    return process_getcert_data(all_text)


def process_getcert_data(data):
    data = data.replace('\t', '').splitlines()
    certs_list = []
    item = {}
    first_line = True

    for line in data:

        if first_line:
            first_line = False
            continue

        line = line.strip()

        if not line:
            continue

        if line.startswith('Request ID'):
            # eg: "Request ID '20170331122405':"

            if any(item):
                certs_list.append(item)

            item = {}
            item['Request ID'] = (line.split('Request ID')[1].strip().replace("'", "")
                                      .replace(':', ''))
            continue

        line_splitted = line.split(':')
        key = line_splitted[0].strip()
        value = ''.join(line_splitted[1:]).replace("'", "")
        item[key] = value.strip()

    certs_list.append(item)

    return certs_list
