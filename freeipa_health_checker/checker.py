import os
from datetime import datetime
from . import messages, commands_helper, parser, utils


logger = utils.get_logger()


def check_is_monitoring(certname):
    getcert_data = commands_helper.getcert_list()
    is_monitoring = False

    for cert in getcert_data:
        if certname in cert['certificate']:
            is_monitoring = True
            break

    if not is_monitoring:
        return False
        logger.error(messages.should_be_monitored_by_certmonger(certname))

    logger.info(messages.monitored_by_certmonger(certname))

    return True


def check_trust_flags(certificate, expected_flags):
    are_equal = certificate.trust_flags == expected_flags

    if are_equal:
        logger.info(messages.cert_has_trust_flags(certificate))
    else:
        logger.info(messages.cert_hasnt_trust_flags(certificate, expected_flags))

    return are_equal


def check_is_expired(certificate):
    today = datetime.today()

    if today > certificate.valid_not_after:
        logger.error(messages.certificate_expired(certificate.name, certificate.valid_not_after,
                                                  certificate.valid_not_before))
        return 'expired'

    if today < certificate.valid_not_before:
        logger.error(messages.certificate_not_valid_yet(certificate.name,
                                                        certificate.valid_not_after,
                                                        certificate.valid_not_before))
        return 'not_valid_yet'

    logger.info(messages.certificate_valid(certificate.name))


def check_kra_setup(path_to_kra, cert_nssdb_path, certs_from_path):
    result = {'kra_in_expected_path': False, 'kra_cert_present': False}

    if os.path.exists(path_to_kra) and os.path.isdir(path_to_kra):
        result['kra_in_expected_path'] = True

    certs_names = [cert[0] for cert in certs_from_path]

    kra_certs = filter(lambda cert: 'kra' in cert.lower(), certs_names)

    if any(kra_certs):
        result['kra_cert_present'] = True

    return result


def check_ra_cert(config_data, cert_name='ipaCert'):
    from freeipa_health_checker import ldap_helper

    nssdb_dir = config_data['ck_ra_cert']['nssdb_dir']
    pem_dir = config_data['ck_ra_cert']['pem_dir']

    if os.path.exists(nssdb_dir):
        cert_data = commands_helper.get_cert(nssdb_dir, cert_name)
        cert = parser.nssdb_cert_to_basecertificate(cert_data)
        certificate = parser.BaseCertificate(serial_number=cert.serial_number)

        cert_serialnumber = certificate.serial_number
        cert_derdata = cert.der_data

        logger.info(messages.ra_cert_from(cert_name, nssdb_dir))

    elif os.path.exists(pem_dir):
        from ipalib import x509
        certificate = x509.load_certificate_from_file(pem_dir)

        cert_serialnumber = certificate.serial_number
        cert_derdata = certificate.der_data

        logger.info(messages.ra_cert_from(cert_name, pem_dir))

    ldap_serialnumber, usercertificate = ldap_helper.get_ra_cert()

    certificates_are_same = usercertificate == cert_derdata
    logger.info(messages.certificate_der_data_are_equal(certificates_are_same))

    return cert_serialnumber, ldap_serialnumber
