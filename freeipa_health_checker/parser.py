
import base64, re
from datetime import datetime


class BaseCertificate(object):

    def __init__(self, valid_not_after=None, valid_not_before=None, name=None,
                 serial_number=None, trust_flags=None):

        self.valid_not_after = valid_not_after
        self.valid_not_before = valid_not_before
        self.trust_flags = trust_flags
        self.serial_number = serial_number
        self.name = name


def nssdb_cert_to_basecertificate(cert_text):
    from ipapython import certdb
    from ipalib import x509

    cert, _ = certdb.find_cert_from_txt(cert_text, start=0)
    cert = x509.strip_header(cert)
    cert = base64.b64decode(cert)
    cert = x509.load_certificate(cert, x509.DER)
    return cert


def certdb_to_basecertificate(cert, cert_name, trust_flags):
    from_date = datetime.fromtimestamp(cert.valid_not_before / 1e6)
    until_date = datetime.fromtimestamp(cert.valid_not_after / 1e6)

    cert_name = cert_name if cert_name else str(cert.subject_common_name)
    certificate = BaseCertificate(valid_not_before=from_date, valid_not_after=until_date,
                                  name=cert_name, trust_flags=trust_flags)
    return certificate


def extract_cert_name(cert):
    match = re.match(b'^(.+?)\s+(\w*,\w*,\w*)\s*$', cert.encode())
    if match:
        match_tuple = match.groups()
        return (match_tuple[0].decode(), match_tuple[1].decode())

    return None

