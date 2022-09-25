"""Gets certificates from the default keychain; this includes current user keychain
and the system keychain."""
from typing import List, Optional

from Security import errSecSuccess
from Security import kSecClass
from Security import kSecReturnRef
from Security import kSecMatchLimit
from Security import kSecMatchLimitAll
from Security import kSecClassCertificate
from Security import kSecMatchTrustedOnly
from Security import kSecFormatUnknown
from Security import SecCertificateRef
from Security import SecItemCopyMatching
from Security import SecItemExport
from Security import SecTrustCopyAnchorCertificates


def _get_non_system_certificates(trusted_only: bool = False) -> Optional[List[SecCertificateRef]]:
    """Get all certificates in the default keychain. This includes the current user keychain and the system
    keychain.

    :param trusted_only: boolean value to pass to 'kSecMatchTrustedOnly' to limit scope to trusted certs only"""
    q = {kSecClass: kSecClassCertificate,
         kSecReturnRef: True,
         kSecMatchLimit: kSecMatchLimitAll,
         kSecMatchTrustedOnly: trusted_only}

    returncode, result = SecItemCopyMatching(q, None)

    if returncode == errSecSuccess:
        return [cert for cert in result]
    else:
        return list()


def _get_system_root_certificates() -> Optional[List[SecCertificateRef]]:
    """Get all system root certificates."""
    returncode, result = SecTrustCopyAnchorCertificates(None)

    if returncode == errSecSuccess:
        return [cert for cert in result]
    else:
        return list()


def get_certificates_as_pem():
    """Get all certificates as a PEM encoded value."""
    certificates = _get_non_system_certificates() + _get_system_root_certificates()
    returncode, converted_certs = SecItemExport(certificates, kSecFormatUnknown, 0, None, None)

    if returncode == errSecSuccess:
        return bytes(converted_certs)
