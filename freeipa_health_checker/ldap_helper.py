
from ipaserver.plugins import ldap2
from ipapython.dn import DN
from ipalib import api
from ipaplatform.paths import paths


def get_ra_cert_serialnumber():
    api.bootstrap(in_server=True, context='restart', confdir=paths.ETC_IPA)
    api.finalize()

    base_dn = DN(('uid', 'ipara'), ('ou', 'people'), ('o', 'ipaca'))
    conn = ldap2.ldap2(api)
    conn.connect()

    entry = conn.get_entry(base_dn, ['description'])
    description = entry['description'][0]
    serial_number = description.split(';')[1]

    return int(serial_number)
