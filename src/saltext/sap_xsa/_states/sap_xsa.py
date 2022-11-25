"""
SaltStack extension for SAP HANA XSA
Copyright (C) 2022 SAP UCC Magdeburg

SAP HANA XSA state module
=========================
SaltStack module that implements SAP HANA XSA states.

:maintainer:    Benjamin Wegener, Alexander Wilke
:maturity:      new
:depends:       dateutil
:platform:      Linux

This module implements SAP HANA XSA states based on the ``xs`` command line
tools that SAP provides for managing the XS Advanced Engine.

.. note::
    This module can only run on linux platforms.
"""
import glob
import logging
from datetime import datetime as dt
from datetime import timezone

import salt.utils.platform

try:
    import dateutil.parser

    HAS_DATEUTIL = True
except ImportError:
    HAS_DATEUTIL = False

# Globals
log = logging.getLogger(__name__)

__virtualname__ = "sap_xsa"


def __virtual__():
    if not HAS_DATEUTIL:
        return False, "Python library dateutil is not installed"
    if salt.utils.platform.is_windows():
        return False, "This module doesn't work on Windows."
    return __virtualname__


def _login(api_url, password, org, xs_path, username="XSA_ADMIN", space="SAP", verify=True):
    """
    Login to SAP HANA XSA. This will store a token in ``~/.xsconfig``.

    api_url
        URL to the API, e.g. ``https://api.hdb.my.domain:443``.

    password
        Password for the provided user.

    org
        Organisation to use for logon.

    xs_path
        Path to the ``xs`` executable.

    username
        Username used for logon, e.g. ``XSA_ADMIN``

    space
        SPACE to use, default is ``SAP``.

    verify
        ``False`` if SSL validation should be skipped, default is ``True``.
    """
    skip_ssl = "" if verify else "--skip-ssl-validation"
    cmd = f"{xs_path} login -a '{api_url}' -u {username} -p '{password}' -o {org} -s {space} {skip_ssl}"
    result = __salt__["cmd.run_all"](cmd=cmd)
    log.trace(f"Raw result: {result}")
    if result["retcode"] != 0:
        log.error(f"Could not login to XSA:\n{result['stdout']}\n\n{result['stderr']}")
        return False
    return True


def _logout(xs_path):
    """
    Logout from SAP HANA XSA.

    xs_path
        Path to the ``xs`` executable
    """
    cmd = f"{xs_path} logout"
    result = __salt__["cmd.run_all"](cmd=cmd)
    log.trace(f"Raw result: {result}")
    if result["retcode"] != 0:
        log.error(f"Could not logout from XSA:\n{result['stdout']}\n\n{result['stderr']}")
        return False
    return True


def _parse_cert(type_, name, cert_data):
    """
    Parses the certificate output of ``xs ...`` and returns a dictionary with:
        * subject
        * issuer
        * valid from
        * valid to

    type
        Can either be ``Alias`` or ``Domain``

    name
        Name of the alias or the domain.

    cert_data
        ``xs`` output with certificate data.
    """
    log.debug("Running function")
    if type_ not in ["Alias", "Domain"]:
        msg = f"Invalid type {type_}"
        log.error(msg)
        raise Exception(msg)
    xsa_cert = {
        "subject": None,
        "issuer": None,
        "valid_from": None,
        "valid_until": None,
    }
    lines = cert_data.splitlines()
    log.trace(f"Processing {len(lines)} lines")
    for i in range(0, len(lines)):  # pylint: disable=consider-using-enumerate
        log.trace(f"Processing line #{i}:{lines[i]}")
        if len(lines) < i or not lines[i]:
            continue
        if lines[i] == f"{type_}: {name}":
            i += 1
            log.trace(" -> Found correct name")
            while i < len(lines):
                log.trace(f"Processing line #{i}: {lines[i]}")
                if ":" in lines[i]:
                    key, value = lines[i].split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if key.startswith(type_):
                        # the next certificate began
                        break
                    if key.startswith("Subject"):
                        log.trace(" -> Found subject")
                        xsa_cert["subject"] = value
                    elif key.startswith("Issuer"):
                        log.trace(" -> Found issuer")
                        xsa_cert["issuer"] = value
                    elif key.startswith("Valid from"):
                        log.trace(" -> Found valid_from")
                        xsa_cert["valid_from"] = dateutil.parser.parse(value)
                    elif key.startswith("Valid until"):
                        log.trace(" -> Found valid_until")
                        xsa_cert["valid_until"] = dateutil.parser.parse(value)
                i += 1
            break
    return xsa_cert


# pylint: disable=unused-argument
def trusted_certificate_present(
    name,
    certfile,
    api_url,
    password,
    org,
    sid,
    username="XSA_ADMIN",
    bin_path="/hana/shared/{SID}/xs/bin/",
    space="SAP",
    verify=True,
    **kwargs,
):
    """
    Ensure that a certificate is trusted.

    name
        Alias name of the certificate.

    certfile
        Certificate file that should be trusted.

    api_url
        URL to the API, e.g. ``https://api.hdb.my.domain:443``

    password
        Password for the provided user.

    org
        Organisation to use for logon.

    username
        Username to logon to XSA, default is ``XSA_ADMIN``.

    sid
        SID of the system.

    bin_path
        Path to the XSA executables, default is ``/hana/shared/{SID}/xs/bin/``

    space
        SPACE to use, default is ``SAP``

    verify
        ``False`` if SSL validation should be skipped, default is ``True``.

    Example:

    .. code-block:: jinja

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
    """
    log.debug("Running function")
    ret = {"name": name, "comment": "", "changes": {}, "result": False}
    if "{SID}" in bin_path:
        bin_path = bin_path.format(SID=sid)
    if bin_path[-1] != "/":
        bin_path += "/"

    log.debug("Logging in to XSA")
    if not _login(
        api_url=api_url,
        username=username,
        password=password,
        org=org,
        xs_path=f"{bin_path}xs",
        space=space,
        verify=verify,
    ):
        ret["comment"] = "Cannot login to SAP HANA XSA"
        ret["result"] = False
        return ret

    try:
        log.debug("Listing existing trusted certificates")
        cmd = f"{bin_path}xs trusted-certificates"
        result = __salt__["cmd.run_all"](cmd=cmd)
        log.trace(f"Raw result: {result}")
        if result["retcode"] != 0:
            msg = "Could not read existing trusted certificates"
            log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
            ret["comment"] = msg
            ret["result"] = False
            return ret
        xsa_cert = _parse_cert("Alias", name, result["stdout"])
        log.debug(f"Parsed certificate:\n{xsa_cert}")
        add_cert = False

        if xsa_cert["subject"]:
            log.debug("Certificate alias already exists, comparing")
            # all datetimes in XSA are UTC
            log.debug("Calculating UTC offset")
            utc_offset = dt.now(timezone.utc).astimezone().utcoffset()

            log.debug(f"Reading certificate {certfile}")
            file_cert = __salt__["x509.read_certificate"](certfile)
            file_subject = ",".join([f"{k}={v}" for k, v in file_cert["Subject"].items()])
            file_issuer = ",".join([f"{k}={v}" for k, v in file_cert["Issuer"].items()])
            file_valid_from = dateutil.parser.parse(file_cert["Not Before"]) + utc_offset
            file_valid_until = dateutil.parser.parse(file_cert["Not After"]) + utc_offset

            # because XSA truncates the seconds, we need to get rid of it as well
            file_valid_from = file_valid_from.replace(second=0)
            file_valid_until = file_valid_until.replace(second=0)

            log.debug("Comparing file and XSA certificate")
            log.trace(f"XSA subject: {xsa_cert['subject']}")
            log.trace(f"X509 subject:{file_subject}")
            log.trace(f"XSA issuer: {xsa_cert['issuer']}")
            log.trace(f"X509 issuer:{file_issuer}")
            log.trace(f"XSA valid_from: {xsa_cert['valid_from']}")
            log.trace(f"X509 valid_from:{file_valid_from}")
            log.trace(f"XSA valid_until: {xsa_cert['valid_until']}")
            log.trace(f"X509 valid_until:{file_valid_until}")
            if (
                xsa_cert["subject"] != file_subject
                or xsa_cert["issuer"] != file_issuer
                or xsa_cert["valid_from"] != file_valid_from
                or xsa_cert["valid_until"] != file_valid_until
            ):
                log.debug("Data does not match, removing and re-adding")
                if __opts__["test"]:
                    log.debug("Would remove the trusted certificates")
                else:
                    result = trusted_certificate_absent(
                        name=name,
                        api_url=api_url,
                        username=username,
                        password=password,
                        org=org,
                        sid=sid,
                        bin_path=bin_path,
                        space=space,
                        verify=verify,
                        logout=False,
                    )
                    if not isinstance(result, dict) or not result.get("result", False):
                        log.error(f"Could not remove certificate alias {name}")
                        return result

                add_cert = True
            else:
                log.debug(f"Certificate file {certfile} and XSA data match")
        else:
            log.debug("Certificate alias does not exist and will be created")
            add_cert = True

        if add_cert:
            log.debug("Adding certificate")
            if __opts__["test"]:
                log.debug("Would add trusted certificate")
                ret["comment"] = "Would have maintained trusted certificate"
            else:
                cmd = f"{bin_path}xs trust-certificate {name} -c {certfile}"
                result = __salt__["cmd.run_all"](cmd=cmd)
                log.trace(f"Raw result: {result}")
                if result["retcode"] != 0:
                    msg = "Could not add trusted certificate"
                    log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
                    ret["comment"] = msg
                    ret["result"] = False
                    return ret
                ret["comment"] = "Maintained trusted certificate"
            ret["changes"] = {"old": None, "new": name}
            ret["result"] = True if not __opts__["test"] else None
        else:
            log.debug("Nothing to add")
            ret["result"] = True
            ret["comment"] = "No changes required"
    except Exception as ex:  # pylint: disable=broad-except
        log.error(f"An exception occured:\n{ex}")
        ret["comment"] = "An exception occured"
        ret["result"] = False
    finally:
        log.debug("Logging out from XSA")
        if not _logout(xs_path=f"{bin_path}xs"):
            ret["comment"] = "Cannot log out from SAP HANA XSA"
            ret["result"] = False

    log.debug(f"Returning:\n{ret}")

    return ret


# pylint: disable=unused-argument
def trusted_certificate_absent(
    name,
    api_url,
    password,
    org,
    sid,
    username="XSA_ADMIN",
    bin_path="/hana/shared/{SID}/xs/bin/",
    space="SAP",
    verify=True,
    auth_required=True,
    **kwargs,
):
    """
    Ensure that a certificate is absent.

    name
        Alias name of the certificate.

    api_url
        URL to the API, e.g. ``https://api.hdb.my.domain:443``

    password
        Password for the provided user.

    org
        Organisation to use for logon.

    username
        Username to logon to XSA, default is ``XSA_ADMIN``.

    sid
        SID of the system.

    bin_path
        Path to the XSA executables, default is ``/hana/shared/{SID}/xs/bin/``

    space
        SPACE to use, default is ``SAP``

    verify
        ``False`` if SSL validation should be skipped, default is ``True``.

    auth_required
        ``False`` if system should not login/logout, default is ``True``.

    Example:

    .. code-block:: jinja

        CA certificate is present in XSA HDB:
          sap_xsa.trusted_certificate_absent:
            - name: MY_CA
            - api_url: https://api.hdb.my.domain:443
            - password: __slot__:salt:vault.read_secret(path="xsa/HDB", key="XSA_ADMIN")
            - username: XSA_ADMIN
            - sid: HDB
            - org: SAP
    """
    log.debug("Running function")
    ret = {"name": name, "comment": "", "changes": {}, "result": False}
    if "{SID}" in bin_path:
        bin_path = bin_path.format(SID=sid)
    if bin_path[-1] != "/":
        bin_path += "/"

    if auth_required:
        log.debug("Logging in to XSA")
        if not _login(
            api_url=api_url,
            username=username,
            password=password,
            org=org,
            xs_path=f"{bin_path}xs",
            space=space,
            verify=verify,
        ):
            ret["comment"] = "Cannot login to SAP HANA XSA"
            ret["result"] = False
            return ret
    try:
        log.debug("Listing existing trusted certificates")
        cmd = f"{bin_path}xs trusted-certificates"
        result = __salt__["cmd.run_all"](cmd=cmd)
        log.trace(f"Raw result: {result}")
        if result["retcode"] != 0:
            msg = "Could not read existing trusted certificates"
            log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
            ret["comment"] = msg
            ret["result"] = False
            return ret
        xsa_cert = _parse_cert("Alias", name, result["stdout"])

        if xsa_cert["subject"]:
            log.debug(f"Trusted certificate {name} exists and will be removed")
            if __opts__["test"]:
                log.debug("Would remove trusted certificate")
                ret["comment"] = f"Would untrust certificate {name}"
            else:
                cmd = f"{bin_path}xs untrust-certificate {name}"
                result = __salt__["cmd.run_all"](cmd=cmd)
                log.trace(f"Raw result: {result}")
                if result["retcode"] != 0:
                    msg = f"Could not untrusted certificate {name}"
                    log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
                    ret["comment"] = msg
                    ret["result"] = False
                    return ret
                ret["comment"] = f"Untrusted certificate {name}"
            ret["changes"] = {"old": name, "new": None}
            ret["result"] = True if not __opts__["test"] else None
        else:
            log.debug("Certificate is already untrusted")
            ret["comment"] = "No changes required"
            ret["changes"] = {}
            ret["result"] = True
    except Exception as ex:  # pylint: disable=broad-except
        log.error(f"An exception occured:\n{ex}")
        ret["comment"] = "An exception occured"
        ret["result"] = False
    finally:
        if auth_required:
            log.debug("Logging out from XSA")
            if not _logout(xs_path=f"{bin_path}xs"):
                ret["comment"] = "Cannot log out from SAP HANA XSA"
                ret["result"] = False

    return ret


# pylint: disable=unused-argument
def certificate_present(
    name,
    keyfile,
    certfile,
    api_url,
    password,
    org,
    sid,
    username="XSA_ADMIN",
    bin_path="/hana/shared/{SID}/xs/bin/",
    space="SAP",
    verify=True,
    **kwargs,
):
    """
    Ensure that a certificate is present for a domain.

    name
        Name of domain

    keyfile
        Filepath of the ``*.key`` file.

    certfile
        Filepath of the ``*.crt`` file.

    api_url
        URL to the API, e.g. ``https://api.hdb.my.domain:443``

    password
        Password for the provided user.

    org
        Organisation to use for logon.

    username
        Username to logon to XSA, default is ``XSA_ADMIN``.

    sid
        SID of the system.

    bin_path
        Path to the XSA executables, default is ``/hana/shared/{SID}/xs/bin/``

    space
        SPACE to use, default is ``SAP``

    verify
        ``False`` if SSL validation should be skipped, default is ``True``.

    Example:

    .. code-block:: jinja

        Certificate is present in XSA S4H:
          sap_xsa.certificate_present:
            - name: hdb.my.domain
            - keyfile: /etc/pki/hdb.my.domain.key
            - certfile: /etc/pki/hdb.my.domain.crt
            - api_url: https://api.hdb.my.domain:443
            - password: __slot__:salt:vault.read_secret(path="xsa/HDB", key="XSA_ADMIN")
            - username: XSA_ADMIN
            - sid: HDB
            - org: SAP
    """
    log.debug("Running function")
    ret = {"name": name, "comment": "", "changes": {}, "result": False}
    if "{SID}" in bin_path:
        bin_path = bin_path.format(SID=sid)
    if bin_path[-1] != "/":
        bin_path += "/"

    log.debug("Logging in to XSA")
    if not _login(
        api_url=api_url,
        username=username,
        password=password,
        org=org,
        xs_path=f"{bin_path}xs",
        space=space,
        verify=verify,
    ):
        ret["comment"] = "Cannot login to SAP HANA XSA"
        ret["result"] = False
        return ret

    try:
        log.debug("Listing existing certificates")
        cmd = f"{bin_path}xs domain-certificates"
        result = __salt__["cmd.run_all"](cmd=cmd)
        log.trace(f"Raw result: {result}")
        if result["retcode"] != 0:
            msg = "Could not read existing domain certificates"
            log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
            ret["comment"] = msg
            ret["result"] = False
            return ret
        xsa_cert = _parse_cert("Domain", name, result["stdout"])
        add_cert = False

        if xsa_cert["subject"]:
            log.debug("Certificate already exists, comparing")

            # all datetimes in XSA are UTC
            log.debug("Calculating UTC offset")
            utc_offset = dt.now(timezone.utc).astimezone().utcoffset()

            log.debug(f"Reading certificate {certfile}")
            file_cert = __salt__["x509.read_certificate"](certfile)
            file_subject = ",".join([f"{k}={v}" for k, v in file_cert["Subject"].items()])
            file_issuer = ",".join([f"{k}={v}" for k, v in file_cert["Issuer"].items()])
            file_valid_from = dateutil.parser.parse(file_cert["Not Before"]) + utc_offset
            file_valid_until = dateutil.parser.parse(file_cert["Not After"]) + utc_offset

            # because XSA truncates the seconds, we need to get rid of it as well
            file_valid_from = file_valid_from.replace(second=0)
            file_valid_until = file_valid_until.replace(second=0)

            log.debug("Comparing file and XSA certificate")
            log.trace(f"XSA subject: {xsa_cert['subject']}")
            log.trace(f"X509 subject:{file_subject}")
            log.trace(f"XSA issuer: {xsa_cert['issuer']}")
            log.trace(f"X509 issuer:{file_issuer}")
            log.trace(f"XSA valid_from: {xsa_cert['valid_from']}")
            log.trace(f"X509 valid_from:{file_valid_from}")
            log.trace(f"XSA valid_until: {xsa_cert['valid_until']}")
            log.trace(f"X509 valid_until:{file_valid_until}")

            if (
                xsa_cert["subject"] != file_subject
                or xsa_cert["issuer"] != file_issuer
                or xsa_cert["valid_from"] != file_valid_from
                or xsa_cert["valid_until"] != file_valid_until
            ):
                log.debug("Data does not match, removing and re-adding")
                if __opts__["test"]:
                    log.debug(f"Would remove certificate {name}")
                else:
                    result = certificate_absent(
                        name=name,
                        api_url=api_url,
                        username=username,
                        password=password,
                        sid=sid,
                        org=org,
                        bin_path=bin_path,
                        space=space,
                        verify=verify,
                        logout=False,
                    )
                    if not result["result"]:
                        log.error(f"Could not remove certificate alias {name}")
                        return result
                add_cert = True
            else:
                log.debug(f"Certificate {certfile} and XSA data match")
        else:
            log.debug("Certificate does not exist and will be created")
            add_cert = True

        if add_cert:
            keyfile_pkcs8 = f"{keyfile}.pkcs8"
            log.debug(f"Removing {keyfile_pkcs8}")
            if __opts__["test"]:
                log.debug(f"Would remove {keyfile_pkcs8} and regenerate file")
            else:
                __salt__["file.remove"](keyfile_pkcs8)
                log.debug(f"Regenerating PKCS8 key {keyfile_pkcs8} from {keyfile}")
                cmd = f"openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in {keyfile} -out {keyfile_pkcs8}"
                result = __salt__["cmd.run_all"](cmd=cmd)
                log.trace(f"Raw result: {result}")
                if result["retcode"] != 0:
                    msg = "Could not generate {keyfile_pkcs8}"
                    log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
                    ret["comment"] = msg
                    ret["result"] = False
                    return ret

            log.debug("Adding certificate")
            if __opts__["test"]:
                log.debug(f"Would add certificate {name}")
                ret["comment"] = "would have maintained certificate"
            else:
                cmd = f"{bin_path}xs set-certificate {name} -k {keyfile_pkcs8} -c {certfile}"
                result = __salt__["cmd.run_all"](cmd=cmd)
                log.trace(f"Raw result: {result}")
                if result["retcode"] != 0:
                    msg = "Could not add certificate"
                    log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
                    ret["comment"] = msg
                    ret["result"] = False
                    return ret
                ret["comment"] = "Maintained certificate"
            ret["changes"] = {"old": None, "new": name}
            ret["result"] = True if not __opts__["test"] else None
        else:
            log.debug("Certificate is already present")
            ret["comment"] = "No changes required"
            ret["changes"] = {}
            ret["result"] = True
    except Exception as ex:  # pylint: disable=broad-except
        log.error(f"An exception occured:\n{ex}")
        ret["comment"] = "An exception occured"
        ret["result"] = False
    finally:
        log.debug("Logging out from XSA")
        if not _logout(xs_path=f"{bin_path}xs"):
            ret["comment"] = "Cannot log out from SAP HANA XSA"
            ret["result"] = False

    return ret


# pylint: disable=unused-argument
def certificate_absent(
    name,
    api_url,
    password,
    org,
    sid,
    username="XSA_ADMIN",
    bin_path="/hana/shared/{SID}/xs/bin/",
    space="SAP",
    verify=True,
    auth_required=True,
    **kwargs,
):
    """
    Ensure that a certificate is absent for a domain.

    name
        Name of domain

    api_url
        URL to the API, e.g. ``https://api.hdb.my.domain:443``

    password
        Password for the provided user.

    org
        Organisation to use for logon.

    username
        Username to logon to XSA, default is ``XSA_ADMIN``.

    sid
        SID of the system.

    bin_path
        Path to the XSA executables, default is ``/hana/shared/{SID}/xs/bin/``

    space
        SPACE to use, default is ``SAP``

    verify
        ``False`` if SSL validation should be skipped, default is ``True``.

    auth_required
        ``False`` if system should not login/logout, default is ``True``.

    Example:

    .. code-block:: jinja

        Certificate is absent in XSA S4H:
          sap_xsa.certificate_absent:
            - name: hdb.my.domain
            - api_url: https://api.hdb.my.domain:443
            - password: __slot__:salt:vault.read_secret(path="xsa/HDB", key="XSA_ADMIN")
            - username: XSA_ADMIN
            - sid: HDB
            - org: SAP
    """
    log.debug("Running function")
    ret = {"name": name, "comment": "", "changes": {}, "result": False}
    if "{SID}" in bin_path:
        bin_path = bin_path.format(SID=sid)
    if bin_path[-1] != "/":
        bin_path += "/"

    if auth_required:
        log.debug("Logging in to XSA")
        if not _login(
            api_url=api_url,
            username=username,
            password=password,
            org=org,
            xs_path=f"{bin_path}xs",
            space=space,
            verify=verify,
        ):
            ret["comment"] = "Cannot login to SAP HANA XSA"
            ret["result"] = False
            return ret

    try:
        log.debug("Listing existing certificates")
        cmd = f"{bin_path}xs domain-certificates"
        result = __salt__["cmd.run_all"](cmd=cmd)
        log.trace(f"Raw result: {result}")
        if result["retcode"] != 0:
            msg = "Could not read existing domain certificates"
            log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
            ret["comment"] = msg
            ret["result"] = False
            return ret
        xsa_cert = _parse_cert("Domain", name, result["stdout"])

        if xsa_cert["subject"]:
            log.debug(f"Removing certificate {name}")
            if __opts__["test"]:
                log.debug(f"Would remove certificate {name}")
                ret["comment"] = "Would have removed certificate"
            else:
                cmd = f"{bin_path}xs delete-certificate {name}"
                result = __salt__["cmd.run_all"](cmd=cmd)
                log.trace(f"Raw result: {result}")
                if result["retcode"] != 0:
                    msg = "Could not remove certificate"
                    log.error(f"{msg}:\n{result['stdout']}\n\n{result['stderr']}")
                    ret["comment"] = msg
                    ret["result"] = False
                    return ret
                ret["comment"] = "Removed certificate"
            ret["changes"] = {"old": name, "new": None}
            ret["result"] = True if not __opts__["test"] else None
        else:
            log.debug("Certificate already does not exist")
            ret["comment"] = "No changes required"
            ret["changes"] = {}
            ret["result"] = True
    except Exception as ex:  # pylint: disable=broad-except
        log.error(f"An exception occured:\n{ex}")
        ret["comment"] = "An exception occured"
        ret["result"] = False
    finally:
        if auth_required:
            log.debug("Logging out from XSA")
            if not _logout(xs_path=f"{bin_path}xs"):
                ret["comment"] = "Cannot log out from SAP HANA XSA"
                ret["result"] = False

    return ret


# pylint: disable=unused-argument
def restarted(name, bin_path="/hana/shared/{SID}/xs/bin/", **kwargs):
    """
    Restart XSA.

    name
        SID of the system.

    bin_path
        Path to the XSA executables, default is ``/hana/shared/{SID}/xs/bin/``.

    Example:

    .. code-block:: jinja

        XSA HDB is restarted:
          sap_xsa.restarted:
            - name: HDB
            - bin_path: /hana/shared/HDB/xs/bin/
    """
    log.debug("Running function")
    ret = {"name": name, "comment": "", "changes": {}, "result": False}
    sid = name.upper()
    if "{SID}" in bin_path:
        bin_path = bin_path.format(SID=sid)
    if bin_path[-1] != "/":
        bin_path += "/"

    # get glob path
    glob_path = bin_path[: bin_path.find(sid)] + f"{sid}/HDB*/hdbenv.csh"
    hdbenv = glob.glob(glob_path)[0]

    cmd = f"sudo su - {sid.lower()}adm -c 'source {hdbenv} && {bin_path}XSA restart'"
    if __opts__["test"]:
        ret["comment"] = "Would have restarted XSA"
    else:
        result = __salt__["cmd.run_all"](cmd=cmd)
        log.trace(f"Raw result: {result}")
        if result["retcode"] != 0:
            msg = "Could not restart XSA"
            log.error(f"{msg}:\n{result['retcode']}")
            ret["comment"] = msg
            ret["result"] = False
            return ret
        ret["comment"] = "Restarted XSA"
    ret["result"] = True if not __opts__["test"] else None

    return ret
