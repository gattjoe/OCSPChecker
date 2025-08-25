""" Tests """

from unittest.mock import MagicMock

import pytest

from ocspchecker.ocspchecker import (
    get_certificate_chain,
    extract_ocsp_result,
    build_ocsp_request,
    get_ocsp_response,
    extract_ocsp_url,
    get_ocsp_status,
)
from . import certs


def test_get_cert_chain_bad_host(monkeypatch):
    """Pass bad host to get_certificate_chain"""

    mock_get_certificate_chain = MagicMock(side_effect=Exception('get_certificate_chain: nonexistenthost.com:443 is invalid or not known.'))

    monkeypatch.setattr("ocspchecker.ocspchecker.get_certificate_chain", mock_get_certificate_chain)

    result = get_ocsp_status("nonexistenthost.com", 443)

    assert result == ['Host: nonexistenthost.com:443', 'Error: get_certificate_chain: nonexistenthost.com:443 is invalid or not known.']


def test_get_cert_chain_host_timeout(monkeypatch):
    """Pass bad port to get_certificate_chain to force the
    connection to time out"""

    mock_get_certificate_chain = MagicMock(side_effect=Exception('get_certificate_chain: Connection to espn.com:65534 timed out.'))

    monkeypatch.setattr("ocspchecker.ocspchecker.get_certificate_chain", mock_get_certificate_chain)

    result = get_ocsp_status("espn.com", 65534)

    assert result == ['Host: espn.com:65534', 'Error: get_certificate_chain: Connection to espn.com:65534 timed out.']


def test_get_cert_chain_bad_port(monkeypatch):
    """Validate the issuer for microsoft.com with ms_pem"""

    mock_get_certificate_chain = MagicMock(side_effect=Exception('get_certificate_chain: Illegal port:80000. Port must be between 0-65535.'))

    monkeypatch.setattr("ocspchecker.ocspchecker.get_certificate_chain", mock_get_certificate_chain)

    result = get_ocsp_status("github.com", 80000)

    assert result == ['Host: github.com:80000', 'Error: get_certificate_chain: Illegal port:80000. Port must be between 0-65535.']


def test_invalid_certificate():
    """edellroot.badssl.com is invalid"""

    func_name: str = "get_certificate_chain"

    host = "edellroot.badssl.com"
    error = f"{func_name}: Certificate Verification failed for {host}."

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, 443)

    assert str(excinfo.value) == error


def test_extract_ocsp_url_success():
    """test a successful extract_ocsp_url function invocation"""

    cert_chain = [certs.github_issuer_pem]
    ocsp_url = extract_ocsp_url(cert_chain)

    assert ocsp_url == "http://ocsp.usertrust.com"


def test_build_ocsp_request_success():
    """test a successful build_ocsp_request function invocation"""

    host = "github.com"
    cert_chain = get_certificate_chain(host)
    ocsp_request_data = build_ocsp_request(cert_chain)

    assert ocsp_request_data == certs.github_ocsp_data


def test_build_ocsp_request_failure():
    """test an unsuccessful build_ocsp_request function invocation"""

    cert_chain = ["blah", "blah"]

    func_name: str = "build_ocsp_request"

    with pytest.raises(Exception) as excinfo:
        build_ocsp_request(cert_chain)

    assert str(excinfo.value) == f"{func_name}: Unable to load x509 certificate."


def test_get_ocsp_response_bad_url_format():
    """test an unsuccessful get_ocsp_response function invocation
    with a bad url format"""

    func_name: str = "get_ocsp_response"

    ocsp_url = "badurl"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == (
        f"{func_name}: Connection Error to {ocsp_url}. unknown url type: {ocsp_url!r}"
    )


def test_get_ocsp_response_connection_error():
    """test an unsuccessful get_ocsp_response function invocation
    with a bad url input"""

    func_name: str = "get_ocsp_response"

    ocsp_url = "http://blahhhhhhhh.com"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"{func_name}: {ocsp_url} is invalid or not known."


def test_get_ocsp_response_timeout():
    """test an unsuccessful get_ocsp_response function invocation
    with timeout"""

    func_name: str = "get_ocsp_response"

    ocsp_url = "http://blah.com:65534"
    ocsp_request_data = b"dummydata"

    with pytest.raises(Exception) as excinfo:
        get_ocsp_response(ocsp_url, ocsp_request_data)

    assert str(excinfo.value) == f"{func_name}: Request timeout for {ocsp_url}"


def test_extract_ocsp_result_unauthorized():
    """test an unsuccessful extract_ocsp_result function invocation"""

    ocsp_response = get_ocsp_response("http://ocsp.digicert.com", certs.unauthorized_ocsp_data)

    with pytest.raises(Exception) as excinfo:
        extract_ocsp_result(ocsp_response)

    assert str(excinfo.value) == "OCSP Response Error: Unauthorized"


def test_extract_ocsp_result_success():
    """test an unsuccessful extract_ocsp_result function invocation"""

    cert_chain = get_certificate_chain("github.com", 443)
    ocsp_url = extract_ocsp_url(cert_chain)
    ocsp_request = build_ocsp_request(cert_chain)
    ocsp_response = get_ocsp_response(ocsp_url, ocsp_request)

    ocsp_result = extract_ocsp_result(ocsp_response)

    assert ocsp_result == "OCSP Status: GOOD"


def test_end_to_end_success_test(monkeypatch):
    """test the full function end to end"""

    mock_get_ocsp_status = MagicMock(result=[
        "Host: github.com:443",
        "OCSP URL: http://ocsp.sectigo.com",
        "OCSP Status: GOOD",
    ])

    monkeypatch.setattr("ocspchecker.ocspchecker.get_ocsp_status", mock_get_ocsp_status)

    result = get_ocsp_status("github.com", 443)

    assert result == [
        "Host: github.com:443",
        "OCSP URL: http://ocsp.sectigo.com",
        "OCSP Status: GOOD",
    ]


def test_end_to_end_test_bad_host(monkeypatch):
    """test the full function end to end"""

    mock_get_ocsp_status = MagicMock(side_effect=Exception(
        "Host: nonexistenthost.com:443",
        "Error: get_certificate_chain: nonexistenthost.com:443 is invalid or not known.",
    ))

    monkeypatch.setattr("ocspchecker.ocspchecker.get_ocsp_status", mock_get_ocsp_status)

    result = get_ocsp_status("nonexistenthost.com", 443)

    assert result == [
        "Host: nonexistenthost.com:443",
        "Error: get_certificate_chain: nonexistenthost.com:443 is invalid or not known.",
    ]


def test_end_to_end_test_bad_fqdn(monkeypatch):
    """test the full function end to end"""

    mock_get_ocsp_status = MagicMock(side_effect=Exception(
        "Host: nonexistentdomain:443",
        "Error: get_certificate_chain: nonexistentdomain:443 is invalid or not known.",
    ))

    monkeypatch.setattr("ocspchecker.ocspchecker.get_ocsp_status", mock_get_ocsp_status)

    result = get_ocsp_status("nonexistentdomain", 443)

    assert result == [
        "Host: nonexistentdomain:443",
        "Error: get_certificate_chain: nonexistentdomain:443 is invalid or not known.",
    ]


def test_end_to_end_test_host_timeout(monkeypatch):
    """test the full function end to end"""

    mock_get_ocsp_status = MagicMock(side_effect=Exception(
        "Host: nonexistentdomain:443",
        "Error: get_certificate_chain: Connection to espn.com:65534 timed out.",
    ))

    monkeypatch.setattr("ocspchecker.ocspchecker.get_ocsp_status", mock_get_ocsp_status)

    result = get_ocsp_status("espn.com", 65534)

    assert result == [
        "Host: espn.com:65534",
        "Error: get_certificate_chain: Connection to espn.com:65534 timed out.",
    ]


def test_bad_port_overflow():
    """Validate passing a bad port results in failure"""

    host = "espn.com"
    ocsp_request = get_ocsp_status(host, 80000)

    assert ocsp_request == [
        "Host: espn.com:80000",
        "Error: get_certificate_chain: Illegal port: 80000. Port must be between 0-65535.",
    ]


def test_bad_port_typeerror():
    """Validate passing a bad port results in failure"""

    host = "espn.com"
    ocsp_request = get_ocsp_status(host, "a")  # type: ignore

    assert ocsp_request == [
        "Host: espn.com:a",
        "Error: get_certificate_chain: Illegal port: a. Port must be between 0-65535.",
    ]


def test_no_port_supplied():
    """Validate that when no port is supplied, the default of 443 is used"""

    host = "github.com"
    ocsp_request = get_ocsp_status(host)

    assert ocsp_request == [
        "Host: github.com:443",
        "OCSP URL: http://ocsp.sectigo.com",
        "OCSP Status: GOOD",
    ]


def test_strip_http_from_host():
    """Validate stripping http from host"""

    host = "http://github.com"
    ocsp_request = get_ocsp_status(host, 443)

    assert ocsp_request == [
        "Host: http://github.com:443",
        "OCSP URL: http://ocsp.sectigo.com",
        "OCSP Status: GOOD",
    ]


def test_strip_https_from_host():
    """Validate stripping https from host"""

    host = "https://github.com"
    ocsp_request = get_ocsp_status(host, 443)

    assert ocsp_request == [
        "Host: https://github.com:443",
        "OCSP URL: http://ocsp.sectigo.com",
        "OCSP Status: GOOD",
    ]


def test_tls_fatal_alert_112():
    """Validate Unrecognized server name provided"""

    host = "nginx.net"
    func_name: str = "get_certificate_chain"

    with pytest.raises(Exception) as excinfo:
        get_certificate_chain(host, 443)

    assert (
        str(excinfo.value)
        == f"{func_name}: Unrecognized server name provided. Check your target and try again."
    )
