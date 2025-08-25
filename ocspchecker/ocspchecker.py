""" A full cert chain is required to make a proper OCSP request. However,
 the ssl module for python 3.x does not support the get_peer_cert_chain()
 method. get_peer_cert_chain() is in flight: https://github.com/python/cpython/pull/17938

 For a short-term fix, I will use nassl to grab the full cert chain. """

from socket import gaierror, timeout, socket, SOCK_STREAM, AF_INET
from typing import List, Optional, Tuple, Union
from urllib.parse import urlparse
from urllib import request, error
from pathlib import Path

from nassl.ssl_client import (
    ClientCertificateRequested,
    OpenSslVersionEnum,
    OpenSslVerifyEnum,
    SslClient,
)
from cryptography.x509 import load_pem_x509_certificate, ocsp, ExtensionNotFound
from nassl.cert_chain_verifier import CertificateChainVerificationFailed
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509.oid import ExtensionOID
from nassl._nassl import OpenSSLError
import certifi

from ocspchecker.utils.http_proxy_connect import http_proxy_connect


class InitialConnectionError(Exception):
    """Custom exception class to differentiate between
    initial connection errors and OpenSSL errors"""

class OcspError(Exception):
    """Base exception for all OCSP-related errors"""


class OcspResponderError(OcspError):
    """Custom exception class to identify errors obtaining a response from a CA'a Responder"""


class OCSPResponseError(OcspError):
    """OCSP Response Status Codes - RFC 6960"""

    def __init__(self, status_code, message: Optional[str] = None):
        self.status_code = status_code
        self.message = message or self._get_status_message(status_code)
        super().__init__(f"OCSP Response Error: {self.message}")

    def _get_status_message(self, status_code):
        messages = {
            1: "Malformed Request",
            2: "Internal Error",
            3: "Try Later",
            # Note: 4 is not used in the RFC
            5: "Signature Required",
            6: "Unauthorized"
        }
        return messages.get(status_code, "Unknown Error")


openssl_errors: dict = {
    # https://github.com/openssl/openssl/issues/6805
    "1408F10B": "The remote host is not using SSL/TLS on the port specified."
    # TLS Fatal Alert 40 - sender was unable to negotiate an acceptable set of security
    # parameters given the options available
    ,
    "14094410": "SSL/TLS Handshake Failure."
    # TLS Fatal Alert 112 - the server understood the ClientHello but did not recognize
    # the server name per: https://datatracker.ietf.org/doc/html/rfc6066#section-3
    ,
    "14094458": "Unrecognized server name provided. Check your target and try again."
    # TLS Fatal Alert 50 - a field was out of the specified range
    # or the length of the message was incorrect
    ,
    "1417B109": "Decode Error. Check your target and try again."
    # TLS Fatal Alert 80 - Internal Error
    ,
    "14094438": "TLS Fatal Alert 80 - Internal Error."
    # Unable to find public key parameters
    ,
    "140070EF": "Unable to find public key parameters.",
}


def get_ocsp_status(
    host: str,
    port: int = 443,
    proxy: Union[None, Tuple[str, int]] = None,
    request_timeout: float = 3.0,
) -> List[str]:
    """Main function with three inputs: host, port and proxy"""

    results: List[str] = []
    results.append(f"Host: {host}:{port}")

    # pylint: disable=W0703
    # All of the exceptions in this function are passed-through

    # Sanitize host
    try:
        host = verify_host(host)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    try:
        # Get the remote certificate chain
        cert_chain = get_certificate_chain(host, port, proxy=proxy, request_timeout=request_timeout)

        # Extract OCSP URL from leaf certificate
        ocsp_url = extract_ocsp_url(cert_chain)

        # Build OCSP request
        ocsp_request = build_ocsp_request(cert_chain)

        # Send OCSP request to responder and get result
        ocsp_response = get_ocsp_response(
            ocsp_url, ocsp_request, proxy=proxy, request_timeout=request_timeout
        )

        # Extract OCSP result from OCSP response
        ocsp_result = extract_ocsp_result(ocsp_response)

    except Exception as err:
        results.append("Error: " + str(err))
        return results

    results.append(f"OCSP URL: {ocsp_url}")
    results.append(f"{ocsp_result}")

    return results


def get_certificate_chain(
    host: str,
    port: int = 443,
    proxy: Union[None, Tuple[str, int]] = None,
    request_timeout: float = 3.0,
    path_to_ca_certs: Path = Path(certifi.where()),
) -> List[str]:
    """Connect to the host on the port and obtain certificate chain"""

    func_name: str = "get_certificate_chain"

    cert_chain: list = []

    soc = socket(AF_INET, SOCK_STREAM, proto=0)
    soc.settimeout(request_timeout)

    try:
        if path_to_ca_certs.is_file():
            pass
    except FileNotFoundError:
        raise OSError(f"ca cert file {path_to_ca_certs} not found") from None

    try:
        if proxy is not None:
            http_proxy_connect((host, port), proxy=proxy, soc=soc)
        else:
            soc.connect((host, port))

    except gaierror:
        raise InitialConnectionError(
            f"{func_name}: {host}:{port} is invalid or not known."
        ) from None

    except timeout:
        soc.close()
        raise InitialConnectionError(
            f"{func_name}: Connection to {host}:{port} timed out."
        ) from None

    except ConnectionRefusedError:
        raise InitialConnectionError(f"{func_name}: Connection to {host}:{port} refused.") from None

    except (IOError, OSError) as err:
        raise InitialConnectionError(
            f"{func_name}: Unable to reach the host {host}. {str(err)}"
        ) from None

    except (OverflowError, TypeError):
        raise InitialConnectionError(
            f"{func_name}: Illegal port: {port}. Port must be between 0-65535."
        ) from None

    ssl_client = SslClient(
        ssl_version=OpenSslVersionEnum.SSLV23,
        underlying_socket=soc,
        ssl_verify=OpenSslVerifyEnum.NONE,
        ssl_verify_locations=path_to_ca_certs,
    )

    # Add Server Name Indication (SNI) extension to the Client Hello
    ssl_client.set_tlsext_host_name(host)

    try:
        ssl_client.do_handshake()
        cert_chain = ssl_client.get_verified_chain()

    except IOError:
        raise ValueError(f"{func_name}: {host} did not respond to the Client Hello.") from None

    except CertificateChainVerificationFailed:
        raise ValueError(f"{func_name}: Certificate Verification failed for {host}.") from None

    except ClientCertificateRequested:
        raise ValueError(f"{func_name}: Client Certificate Requested for {host}.") from None

    except OpenSSLError as err:
        for key, value in openssl_errors.items():
            if key in err.args[0]:
                raise ValueError(f"{func_name}: {value}") from None

        raise ValueError(f"{func_name}: {err}") from None

    finally:
        # shutdown() will also close the underlying socket
        ssl_client.shutdown()

    return cert_chain


def extract_ocsp_url(cert_chain: List[str]) -> str:
    """Parse the leaf certificate and extract the access method and
    access location AUTHORITY_INFORMATION_ACCESS extensions to
    get the ocsp url"""

    func_name: str = "extract_ocsp_url"

    ocsp_url: str = ""

    # Convert to a certificate object in cryptography.io
    certificate = load_pem_x509_certificate(str.encode(cert_chain[0]), default_backend())

    # Check to ensure it has an AIA extension and if so, extract ocsp url
    try:
        aia_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value

        # pylint: disable=protected-access
        for aia_method in iter((aia_extension)):
            if aia_method.__getattribute__("access_method")._name == "OCSP":
                ocsp_url = aia_method.__getattribute__("access_location").value

        if ocsp_url == "":
            raise ValueError(f"{func_name}: OCSP URL missing from Certificate AIA Extension.")

    except ExtensionNotFound:
        raise ValueError(
            f"{func_name}: Certificate AIA Extension Missing. Possible MITM Proxy."
        ) from None

    return ocsp_url


def build_ocsp_request(cert_chain: List[str]) -> bytes:
    """Build an OCSP request out of the leaf and issuer pem certificates
    see: https://cryptography.io/en/latest/x509/ocsp/#cryptography.x509.ocsp.OCSPRequestBuilder
    for more information"""

    func_name: str = "build_ocsp_request"

    try:
        leaf_cert = load_pem_x509_certificate(str.encode(cert_chain[0]), default_backend())
        issuer_cert = load_pem_x509_certificate(str.encode(cert_chain[1]), default_backend())

    except ValueError:
        raise Exception(f"{func_name}: Unable to load x509 certificate.") from None

    # Build OCSP request
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, issuer_cert, SHA1())
    ocsp_data = builder.build()
    ocsp_request_data = ocsp_data.public_bytes(serialization.Encoding.DER)

    return ocsp_request_data


def get_ocsp_response(
    ocsp_url: str,
    ocsp_request_data: bytes,
    proxy: Union[None, Tuple[str, int]] = None,
    request_timeout: float = 3.0,
):
    """Send OCSP request to ocsp responder and retrieve response"""

    func_name: str = "get_ocsp_response"
    ocsp_response = None

    try:
        ocsp_request = request.Request(
            ocsp_url,
            data=ocsp_request_data,
            headers={"Content-Type": "application/ocsp-request"},
        )
        if proxy is not None:
            host, port = proxy
            ocsp_request.set_proxy(f"{host}:{port}", "http")

        with request.urlopen(ocsp_request, timeout=request_timeout) as resp:
            ocsp_response = resp.read()

    except error.URLError as err:
        if isinstance(err.reason, timeout):
            raise OcspResponderError(f"{func_name}: Request timeout for {ocsp_url}")

        if isinstance(err.reason, gaierror):
            raise OcspResponderError(f"{func_name}: {ocsp_url} is invalid or not known.")

        raise OcspResponderError(f"{func_name}: Connection Error to {ocsp_url}. {str(err)}")

    except ValueError as err:
        raise OcspResponderError(f"{func_name}: Connection Error to {ocsp_url}. {str(err)}")

    except timeout:
        raise OcspResponderError(f"{func_name}: Request timeout for {ocsp_url}")

    return ocsp_response


def extract_ocsp_result(ocsp_response):
    """Extract the OCSP result from the provided ocsp_response"""

    func_name: str = "extract_ocsp_result"

    try:
        ocsp_response = ocsp.load_der_ocsp_response(ocsp_response)
        # A status of 0 == OCSPResponseStatus.SUCCESSFUL
        if ocsp_response.response_status.value != 0:
            raise OCSPResponseError(ocsp_response.response_status.value)

        certificate_status = str(ocsp_response.certificate_status)
        certificate_status = certificate_status.split(".")
        return f"OCSP Status: {certificate_status[1]}"

    except ValueError as err:
        return f"{func_name}: {str(err)}"


def verify_host(host: str) -> str:
    """Parse a DNS name to ensure it does not contain http(s)"""
    parsed_name = urlparse(host)

    # The below parses out http(s) from a name
    host_candidate = parsed_name.netloc
    if host_candidate == "":
        host_candidate = parsed_name.path

    return host_candidate
