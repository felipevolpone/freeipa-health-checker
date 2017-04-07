
import unittest
import os
from freeipa_health_checker import checker_helper as helper


class TestHelper(unittest.TestCase):

    path_mock_files = os.getcwd() + '/tests/mock_files/'
    maxDiff = None

    def test_process_getcert_data(self):

        raw_data = """
Request ID '20170331122404':
    status: MONITORING
    stuck: no
    key pair storage: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='auditSigningCert cert-pki-ca',token='NSS Certificate DB',pin set
    certificate: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='auditSigningCert cert-pki-ca',token='NSS Certificate DB'
    CA: dogtag-ipa-ca-renew-agent
    issuer: CN=Certificate Authority,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM
    subject: CN=CA Audit,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM
    expires: 2019-03-21 13:23:14 UTC
    key usage: digitalSignature,nonRepudiation
    pre-save command: /usr/libexec/ipa/getcert/stop_pkicad
    post-save command: /usr/libexec/ipa/getcert/renew_ca_cert "auditSigningCert cert-pki-ca"
    track: yes
    auto-renew: yes
Request ID '20170331122405':
    status: MONITORING
    stuck: no
    key pair storage: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='ocspSigningCert cert-pki-ca',token='NSS Certificate DB',pin set
    certificate: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='ocspSigningCert cert-pki-ca',token='NSS Certificate DB'
    CA: dogtag-ipa-ca-renew-agent
    issuer: CN=Certificate Authority,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM
    subject: CN=OCSP Subsystem,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM
    expires: 2019-03-21 13:23:13 UTC
    key usage: digitalSignature,nonRepudiation,keyCertSign,cRLSign
    eku: id-kp-OCSPSigning
    pre-save command: /usr/libexec/ipa/getcert/stop_pkicad
    post-save command: /usr/libexec/ipa/getcert/renew_ca_cert "ocspSigningCert cert-pki-ca"
    track: yes
    auto-renew: yes
        """

        expected = [
            {'status': 'MONITORING', 'auto-renew': 'yes', 'pre-save command': '/usr/libexec/ipa/getcert/stop_pkicad', 'certificate': 'type=NSSDB,location=/etc/pki/pki-tomcat/alias,nickname=auditSigningCert cert-pki-ca,token=NSS Certificate DB', 'track': 'yes', 'CA': 'dogtag-ipa-ca-renew-agent', 'expires': '2019-03-21 132314 UTC', 'Request ID': '20170331122404', 'stuck': 'no', 'key pair storage': 'type=NSSDB,location=/etc/pki/pki-tomcat/alias,nickname=auditSigningCert cert-pki-ca,token=NSS Certificate DB,pin set', 'key usage': 'digitalSignature,nonRepudiation', 'post-save command': '/usr/libexec/ipa/getcert/renew_ca_cert "auditSigningCert cert-pki-ca"', 'subject': 'CN=CA Audit,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM', 'issuer': 'CN=Certificate Authority,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM'},
            {'status': 'MONITORING', 'auto-renew': 'yes', 'pre-save command': '/usr/libexec/ipa/getcert/stop_pkicad', 'certificate': 'type=NSSDB,location=/etc/pki/pki-tomcat/alias,nickname=ocspSigningCert cert-pki-ca,token=NSS Certificate DB', 'track': 'yes', 'CA': 'dogtag-ipa-ca-renew-agent', 'expires': '2019-03-21 132313 UTC', 'Request ID': '20170331122405', 'stuck': 'no', 'key pair storage': 'type=NSSDB,location=/etc/pki/pki-tomcat/alias,nickname=ocspSigningCert cert-pki-ca,token=NSS Certificate DB,pin set', 'key usage': 'digitalSignature,nonRepudiation,keyCertSign,cRLSign', 'eku': 'id-kp-OCSPSigning', 'subject': 'CN=OCSP Subsystem,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM', 'post-save command': '/usr/libexec/ipa/getcert/renew_ca_cert "ocspSigningCert cert-pki-ca"', 'issuer': 'CN=Certificate Authority,O=DOM-058-188.ABC.IDM.LAB.ENG.BRQ.REDHAT.COM'}]

        self.assertEqual(expected, helper.process_getcert_data(raw_data))
