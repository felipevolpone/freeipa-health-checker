
def cert_not_in_path(name, path):
    message = 'Certificate \"{name}\" should be on: {path}, but was not found there.'
    return message.format(name=name, path=path)


def should_be_monitored_by_certmonger(name):
    return 'The cert {name} should be being monitored by certmonger'.format(name=name)


def monitored_by_certmonger(name):
    return 'The cert {} is being monitored by certmonger'.format(name)


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


def local_cert_serialnumber(cert_serial_number):
    return 'Serial Number of the local certificate: {}'.format(cert_serial_number)


def ldap_cert_serialnumber(ldap_serialnumber):
    return 'Serial Number of the certificate in LDAP: {}'.format(ldap_serialnumber)


def ra_cert_from(certname, path):
    return 'Using {} certificate foud in {}'.format(certname, path)


def cert_hasnt_trust_flags(certificate, expected_flags):
    return 'Certificate {} expects to have {} trust flags, found {}'.format(
        certificate.name, expected_flags, certificate.trust_flags)


def cert_has_trust_flags(certificate):
    return 'Certificate {} has the expected trust flags'.format(certificate.name)


def certificate_valid(certificate_name):
    return 'Certificate {} is valid (not expired)'.format(certificate_name)
