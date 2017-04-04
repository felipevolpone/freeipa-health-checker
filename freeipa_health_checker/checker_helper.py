
import re
from datetime import datetime
from . import settings, utils


def extract_cert_name(cert):
    match = re.match(b'^(.+?)\s+(\w*,\w*,\w*)\s*$', cert.encode())
    if match:
        match_tuple = match.groups()
        return (match_tuple[0].decode(), match_tuple[1].decode())

    return None


def compare_cert_date(cert_details):
    valid_from, valid_until = cert_details[7], cert_details[8]

    valid_from = valid_from.split(': ')[1]
    valid_until = valid_until.split(': ')[1]

    from_date = datetime.strptime(valid_from, settings.CERT_DATE_FORMAT)
    until_date = datetime.strptime(valid_until, settings.CERT_DATE_FORMAT)
    now = datetime.today()

    return from_date < now and now < until_date


def check_path(logger, row, certs_names):
    if row['name'] not in certs_names:
        message = 'Certificate \"{name}\" should be on: {path}. '
        message += 'It was found there: False. '

        message = message.format(name=row['name'], path=row['path'])

        logger.error(message)
        return False

    return True


def check_flags(logger, row, certs_names, certs_from_path):
    cert_index = certs_names.index(row['name'])
    cert_flags = certs_from_path[cert_index][1]

    if row['flags'] != cert_flags:
        message = "Certificate \"{name}\" from expected path {path}, do not has \
these flags: {expected}; but these: {cur_flags}"

        message = message.format(name=row['name'], path=row['path'],
                                 expected=row['flags'], cur_flags=cert_flags)

        logger.error(message)
        return False

    return True


def check_is_monitoring(logger, row, getcert_data):
    if row['monitored'] == 'true' or row['monitored'] == 'True':

        if getcert_data is None:
            getcert_data = getcert_list()

        is_monitoring = False
        for cert in getcert_data:
            if row['name'] in cert['certificate']:
                is_monitoring = True
                break

        if not is_monitoring:
            logger.error('The cert {name} should being monitored by certmonger'
                         .format(name=row['name']))
            return False, getcert_data

    return True, getcert_data


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
