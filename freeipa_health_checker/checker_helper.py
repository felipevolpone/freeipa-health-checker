
import re
from datetime import datetime
from . import settings, utils, messages
from collections import namedtuple


def extract_cert_name(cert):
    match = re.match(b'^(.+?)\s+(\w*,\w*,\w*)\s*$', cert.encode())
    if match:
        match_tuple = match.groups()
        return (match_tuple[0].decode(), match_tuple[1].decode())

    return None


def parse_date_field(cert_details):
    valid_from, valid_until = cert_details[7], cert_details[8]

    valid_from = valid_from.split(': ')[1]
    valid_until = valid_until.split(': ')[1]

    from_date = datetime.strptime(valid_from, settings.CERT_DATE_FORMAT)
    until_date = datetime.strptime(valid_until, settings.CERT_DATE_FORMAT)

    return from_date, until_date


def check_path(logs, row, certs_names):
    if row['name'] not in certs_names:
        logs.error(messages.cert_not_in_path(row['name'], row['path']))
        return False

    return True


def check_flags(logs, row, certs_names, certs_from_path):
    cert_index = certs_names.index(row['name'])
    cert_flags = certs_from_path[cert_index][1]

    if row['trustflags'] != cert_flags:
        message = messages.without_trustflags(row['name'], row['path'], row['trustflags'],
                                              cert_flags)
        logs.error(message)
        return False

    return True


def check_is_monitoring(logs, row):
    if row.get('monitored'):
        getcert_data = getcert_list()
        is_monitoring = False

        for cert in getcert_data:
            if row['name'] in cert['certificate']:
                is_monitoring = True
                break

        if not is_monitoring:
            logs.error(messages.monitored_by_certmonger(row['name']))
            return


def getcert_list():
    command = 'getcert list'
    output = utils.execute(command)
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


Cert = namedtuple('Cert', 'from_date until_date')


def parse_cert_text(cert_text):
    return Cert(from_date=cert_text[7], until_date=cert_text[8])


class Log(object):

    def __init__(self):
        self.logs = []

    def info(self, item):
        self.__append(item, 'info')

    def debug(self, item):
        self.__append(item, 'debug')

    def error(self, item):
        self.__append(item, 'error')

    def __append(self, item, status):
        self.logs.append((item, status))
