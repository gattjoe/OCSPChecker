# OCSPChecker

[![Downloads](https://pepy.tech/badge/ocsp-checker/month)](https://pepy.tech/project/ocsp-checker)
[![PyPI Version](https://img.shields.io/pypi/v/ocsp-checker.svg)](https://pypi.org/project/ocsp-checker/)
[![Python version](https://img.shields.io/pypi/pyversions/ocsp-checker.svg)](https://pypi.org/project/ocsp-checker/)

## Overview

OCSPChecker is a python package based on Alban Diquet's [nassl](https://github.com/nabla-c0d3/nassl) wrapper and the Python Cryptographic Authority's [cryptography](https://github.com/pyca/cryptography) package. Relying on a web browser to check the revocation status of a x509 digital certificate [has](https://www.imperialviolet.org/2014/04/19/revchecking.html) [been](https://www.imperialviolet.org/2014/04/29/revocationagain.html) [broken](https://scotthelme.co.uk/revocation-is-broken/) from the beginning, and validating certificates outside of the web browser is a manual process. OCSP-Checker aims to solve this by providing an automated means to check the [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) revocation status for a x509 digital certificate.


## Pre-requisites

__Python__ - Python 3.9 (64-bit) and above.

## Installation

It is strongly recommended to run ocsp-checker in a virtual environment. This will prevent you from impacting your system python when installing its dependencies. [venv](https://docs.python.org/3/library/venv.html) is a good option, with an example below:

```python -m venv ocsp-checker```
```cd ocsp-checker && source bin/activate```

Once your virtual environment is activated, install ocsp-checker as follows:

```pip install ocsp-checker```

## Usage

```
>>> from ocspchecker import ocspchecker
>>> ocsp_request = ocspchecker.get_ocsp_status("github.com")
```

## Sample Output

Sample output below, let me know if you want to add more fields/information to the output.

```
['Host: github.com:443', 'OCSP URL: http://ocsp.digicert.com', 'OCSP Status: GOOD']
```

PLEASE NOTE: If you run this on a network with a MITM SSL proxy, you may receive unintended results (see below):
```
["Error: Certificate Authority Information Access (AIA) Extension Missing. Possible MITM Proxy."]
```

## Command Line Usage

OCSPChecker can now be used at the command line. The format is:
```
usage: ocspchecker [-h] --target target [--port port]

Check the OCSP revocation status for a x509 digital certificate.

optional arguments:
  -h, --help            show this help message and exit
  --target target, -t target
                        The target to test
  --port port, -p port  The port to test (default is 443)
```

For example:

``` ocspchecker -t github.com ```
