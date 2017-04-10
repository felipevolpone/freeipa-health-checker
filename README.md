
# freeipa-health-checker

[![Build Status](https://travis-ci.org/felipevolpone/freeipa-health-checker.svg?branch=master)](https://travis-ci.org/felipevolpone/freeipa-health-checker)
![Python Version](https://img.shields.io/badge/python-2.7-green.svg)

### What is the purpose of this tool
The main goal of this tool is to provide verifications that can be done on a [FreeIPA](http://freeipa.org) or [Dogtag](http://pki.fedoraproject.org) environment; in order to help the users of these projects to have a feedback if some parts of the installation were done correctly.

### Main features until now
* Check if the certificates expired (or are not valid yet)
* Check if the certificates are on the right path, if they have the expected
trust flags and check if certmonger is monitoring the certs.
* If the environment has the KRA module, check if it has the right certificate.
* Check if PKI certificates in IPA NSS databases map correctly to PKI user in PKI LDAP DB

### How to use it
1. Clone the project
```bash
git clone https://github.com/felipevolpone/freeipa-health-checker.git
cd freeipa-health-checker
```

2. Install [certutil](https://fedoraproject.org/wiki/NSS_Tools_:_certutil)
```bash
apt-get install libnss3-tools
yum install libnss3-tools
```

PS: All commands has the `config-file` optional argument. With it, you can provide
a YAML file that overrides the default configurations. [Check it here to more details](https://github.com/felipevolpone/freeipa-health-checker/blob/master/freeipa_health_checker/certs_config.yaml).

3. Start using it:
```bash
python -m freeipa_health_checker.checker -h [--config-file]
python -m freeipa_health_checker.checker ck_kra_setup
python -m freeipa_health_checker.checker full_check
python -m freeipa_health_checker.checker list_certs <path>
python -m freeipa_health_checker.checker certs_expired
python -m freeipa_health_checker.checker ck_ra_cert_serialnumber [--pem-dir | --nssdb-dir]
```

### Testing it
It is relevant to say that the unit tests do not use any mock. So, it's
necessary to have the certutil command installed on the machine. Check the
`How to use it` section.

How to run the tests:
```bash
python -m unittest discover tests -p '*.py'
```

## Next steps
Please check the [issues](https://github.com/felipevolpone/freeipa-health-checker/issues)
