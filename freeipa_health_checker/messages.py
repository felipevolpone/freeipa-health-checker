
def cert_not_in_path(name, path):
    message = 'Certificate \"{name}\" should be on: {path}, but was not found there.'
    return message.format(name=name, path=path)


def without_trustflags(name, path, trustflags, cert_flags):
    message = "Certificate \"{name}\" from expected path {path}, do not has \
these flags: {expected}; but these: {cur_flags}"
    return message.format(name=name, path=path, expected=trustflags, cur_flags=cert_flags)


def monitored_by_certmonger(name):
    return 'The cert {name} should being monitored by certmonger'.format(name=name)


def check_done():
    return 'Check done'


def certificate_expired(cert_name, from_date, until_date):
    return 'Certificate \"{}\" is expired. Period {} to {}'.format(cert_name, from_date, until_date)


def certificate_not_valid_yet(cert_name, from_date, until_date):
    return 'Certificate \"{}\" not valid yet. Period {} to {}'.format(cert_name,
                                                                      from_date, until_date)


def kra_status(kra_in_expected_path, kra_cert_present):
    return 'KRA is installed: {installed}. Cert was found: {cert_found}'.format(
           installed=kra_in_expected_path, cert_found=kra_cert_present)


def ra_cert_different(cert_serial_number, ldap_serialnumber):
    return ('Serial Number from RA Cert is \"{}\" in the local certificate and \"{}\" in LDAP'
            .format(cert_serial_number, ldap_serialnumber))
