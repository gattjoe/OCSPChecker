''' These global responders are sometimes flaky when testing from GitHub.
To make CI tests in GitHub more reliable, I am making these tests optional. '''

import pytest

from ocspchecker.ocspchecker import (
    build_ocsp_request,
    extract_ocsp_result,
    extract_ocsp_url,
    get_certificate_chain,
    get_ocsp_response,
    get_ocsp_status,
)

from . import certs

@pytest.mark.parametrize("root_ca", certs.cert_authorities)
def test_a_cert_from_each_root_ca(root_ca):
    """Test a cert from each root CA to ensure test coverage"""

    ocsp_request = get_ocsp_status(root_ca, 443)

    assert ocsp_request[2] == "OCSP Status: GOOD"

