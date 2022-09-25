from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from typing import Any, Dict, List, Optional

from asn1crypto import pem
from asn1crypto import x509
from asn1crypto.x509 import Certificate as x509Cert
from .keychain import get_certificates_as_pem


@dataclass
class KeychainCertificate:
    """Keychain Certificate."""
    version: str = field(default=None)
    serial_number: str = field(default=None)
    not_before: datetime = field(default=None)
    not_after: datetime = field(default=None)
    not_before_str: str = field(default=None)
    not_before_local_str: str = field(default=None)
    not_after_str: str = field(default=None)
    not_after_local_str: str = field(default=None)
    country_name: str = field(default=None)
    state_or_province: str = field(default=None)
    locality: str = field(default=None)
    organization: str = field(default=None)
    organization_unit: str = field(default=None)
    issuer_country: str = field(default=None)
    issuer_organization: str = field(default=None)
    issuer_organization_unit: str = field(default=None)
    common_name: str = field(default=None)
    signature_algorithm: str = field(default=None)
    sha1: str = field(default=None)
    sha256: str = field(default=None)


def _localtime(dt: datetime) -> datetime:
    """Converts a UTC datetime object into local time."""
    # tz = datetime.now(timezone.utc).astimezone().tzinfo
    return dt.astimezone()


def _get_certificate_attributes(cert: x509Cert,
                                date_fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> Optional[Dict[Any, Any]]:
    """Get attributes about a certificate."""
    result = dict()
    core_attr_keys = ["version",
                      "serial_number"]
    sub_attr_keys = {"validity": ["not_after",
                                  "not_before"],
                     "subject": {"country_name": "country_name",
                                 "state_or_province_name": "state_or_province",
                                 "locality_name": "locality",
                                 "organization_name": "organization",
                                 "organizational_unit_name": "organization_unit",
                                 "common_name": "common_name"},
                     "issuer": {"country_name": "issuer_country",
                                "organization_name": "issuer_organization",
                                "organization_unit_name": "issuer_organization_unit"}}

    certificate = cert.native.get("tbs_certificate")
    signature_alg = cert.native.get("signature_algorithm").get("algorithm")
    sha1_val = cert.sha1_fingerprint
    sha256_val = cert.sha256_fingerprint

    for attr in core_attr_keys:
        if certificate.get(attr):
            result[attr] = certificate.get(attr)

    for key, attrs in sub_attr_keys.items():
        if isinstance(attrs, list):
            for attr in attrs:
                result[attr] = certificate.get(key).get(attr)
        elif isinstance(attrs, dict):
            for attr, new_attr in attrs.items():
                result[new_attr] = certificate.get(key).get(attr)

    result["signature_algorithm"] = signature_alg
    result["sha1"] = "".join(sha1_val) if sha1_val else None
    result["sha256"] = "".join(sha256_val) if sha256_val else None

    if result.get("not_before"):
        result["not_before_str"] = result["not_before"].strftime(date_fmt)
        result["not_before_local_str"] = _localtime(result["not_before"]).strftime(date_fmt)
    else:
        result["not_before_str"] = None
        result["not_before_local_str"] = None

    if result.get("not_after"):
        result["not_after_str"] = result["not_after"].strftime(date_fmt)
        result["not_after_local_str"] = _localtime(result["not_after"]).strftime(date_fmt)
    else:
        result["not_after_str"] = None
        result["not_after_local_str"] = None

    # Sometimes the 'common_name' attribute does not exist in the certificate, so fallback
    # to the same behaviour as macOS Keychain Access utlity, which appears to preferr
    # the issuer organizational name followed by the subject organization name values
    if not result.get("common_name"):
        alt_name1 = certificate["issuer"].get("organizational_unit_name")
        alt_name2 = certificate["subject"].get("organization_name")
        result["common_name"] = alt_name1 or alt_name2

    # Some of the int values can cause an 'OverflowError' when writing to property list,
    # such as the 'serial_number' value, so fix these up by converting to string.
    for k, v in result.copy().items():
        if isinstance(v, int):
            result[k] = str(v)

    return result


def get_certificates() -> List[KeychainCertificate]:
    """Gets the certificates."""
    _certificates = get_certificates_as_pem()

    # Only operate if we have a list of certificates and it is a valid PEM
    # data format. This will return multiple certificates as a single byte
    # string, so the 'unarmor' method must have the 'multiple=True' param
    # passed to parse the data correctly.
    # See https://github.com/wbond/asn1crypto/blob/master/docs/pem.md for
    # further information.
    if _certificates and pem.detect(_certificates):
        result = list()
        unarmoured = pem.unarmor(_certificates, multiple=True)

        # 'unarmor' will return a tuple of three values:
        #   - certificate type
        #   - pem headers
        #   - certificate contents
        for cert_type, pem_headers, contents in unarmoured:
            cert = x509.Certificate.load(contents)
            converted_cert = _get_certificate_attributes(cert=cert)

            if converted_cert:
                result.append(KeychainCertificate(**converted_cert))

        return result
