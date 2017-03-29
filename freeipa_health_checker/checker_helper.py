
import re
from datetime import datetime
from . import settings


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


def treat_cert_not_found(logger, row):
    message = 'Certificate \"{name}\" should be on: {path}. '
    message += 'Was found there: False. '

    message = message.format(name=row['name'], path=row['path'])

    logger.error(message)


def treat_cert_with_wrong_flags(logger, row, cert_flags):
    message = "Certificate \"{name}\" from expected path {path}, do not has \
these flags: {expected}; but these: {cur_flags}"

    message = message.format(name=row['name'], path=row['path'],
                             expected=row['flags'], cur_flags=cert_flags)

    logger.error(message)
