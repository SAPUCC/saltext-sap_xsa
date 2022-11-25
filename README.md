# SaltStack SAP HANA XSA extension
This SaltStack extensions allows managing SAP HANA XSA systems.

**THIS PROJECT IS NOT ASSOCIATED WITH SAP IN ANY WAY**

## Installation
Run the following to install the SaltStack SAP Host Agent extension:
```bash
salt-call pip.install saltext.sap-xsa
```
Keep in mind that this package must be installed on every minion that should utilize the states and execution modules.

Alternatively, you can add this repository directly over gitfs
```yaml
gitfs_remotes:
  - https://github.com/SAPUCC/saltext-sap_xsa.git:
    - root: src/saltext/sap_xsa
```
In order to enable this, logical links under `src/saltext/sap_xsa/` from `_<dir_type>` (where the code lives) to `<dir_type>` have been placed, e.g. `_states` -> `states`. This will double the source data during build, but:
 * `_states` is required for integrating the repo over gitfs
 * `states` is required for the salt loader to find the modules / states

## Usage
A state using the SAP Host Agent extension looks like this:
```jinja
CA certificate is present in XSA HDB:
  sap_xsa.trusted_certificate_present:
    - name: MY_CA
    - certfile: /etc/pki/trust/anchors/ca.crt
    - api_url: https://api.hdb.my.domain:443
    - password: __slot__:salt:vault.read_secret(path="xsa/HDB", key="XSA_ADMIN")
    - username: XSA_ADMIN
    - sid: HDB
    - org: SAP
    - bin: /hana/shared/HDB/xs/bin/xs
    - space: SAP
    - verify: False
```

## Docs
See https://saltext-sap-xsa.readthedocs.io/ for the documentation.

## Contributing
We would love to see your contribution to this project. Please refer to `CONTRIBUTING.md` for further details.

## License
This project is licensed under GPLv3. See `LICENSE.md` for the license text and `COPYRIGHT.md` for the general copyright notice.
