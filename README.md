
# freeipa-health-checker

[![Build Status](https://travis-ci.org/felipevolpone/freeipa-health-checker.svg?branch=master)](https://travis-ci.org/felipevolpone/freeipa-health-checker)
![Python Version](https://img.shields.io/badge/python-2.7-green.svg)

### What is the purpose of this tool
The main goal of this tool is to provide verifications that can be done on a [FreeIPA](http://freeipa.org) environment;
in order to help the users of the projects to have a feedback about the certificates.

### Main features until now
* Check if the certificates expired (or are not valid yet)
* Check if the certificates are on the right path
* Check if they have the expected trust flags
* Check if certmonger is monitoring the certs
* If the environment has the KRA module, check if it has the right certificate.
* Check if PKI certificates in IPA NSS databases map correctly to PKI user in PKI LDAP DB

### How to use it
1. Clone the project
```bash
git clone https://github.com/felipevolpone/freeipa-health-checker.git
cd freeipa-health-checker
```

2. Start using it:
PS: All commands has the `config-file` optional argument. With it, you can provide
a YAML file that overrides the default configurations.
[Check it here to more details](https://github.com/felipevolpone/freeipa-health-checker/blob/master/freeipa_health_checker/certs_config.yaml).

```bash
python -m freeipa_health_checker.checker -h
python -m freeipa_health_checker.checker ck_kra_setup [--config-file]
python -m freeipa_health_checker.checker full_check [--config-file]
python -m freeipa_health_checker.checker ck_ra_cert [--pem-dir | --nssdb-dir]
```

### API Documentation
Please, check the [Wiki in the GitHub page](https://github.com/felipevolpone/freeipa-health-checker/wiki).

### Communication
Since this is part of the FreeIPA project, you can join us in the #freeipa channel on freenode.

### Status of the project
This project actually is a prove of concept (PoC), which means that things can
change really quickly and without any previous warning.

### Testing it
It is relevant to say that the unit tests do not use any mock. So, it's
necessary to have the certutil command installed on the machine. Check the
`How to use it` section.

How to run the tests:
```bash
python -m unittest discover tests -p '*.py'
```

### Next steps
Please check the [issues](https://github.com/felipevolpone/freeipa-health-checker/issues)
