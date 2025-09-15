# Changelog for OCSP-StatusChecker

# v1.0.0
- Initial Release

# v1.3.0
- Add Server Name Indication (SNI) support
- Add tests to cover each root certificate authority in use
- Fix MITM proxy error reporting

# v1.4.0
- Added the ability to call from the command line
- Updated cryptography and validators
- Some pylint fixes

# v1.5.0
- Fixed an uncaught exception when port is > 65535 or not numeric
- Parse out http(s) when submitting a request

# v1.6.0
- Upgrade cryptography to 3.2
- Upgrade nassl to 3.1
- Added tox tests for Python versions 3.7 and 3.8

# v1.7.0
- Added support for M1 Mac's
- Added support for Python 3.9
- Upgraded nassl to 4.0.0
- Upgraded cryptography to 3.4.6
- Fixed failing tests
- Added tox tests for Python 3.9

# v1.8.0
- Fixed a bug to handle a situation when parsing a certificate with an AIA extension but no OCSP URL
- Fixed a bug to handle a situation where the remote host is not using SSL/TLS and we attempt to do a SSL/TLS handshake
- Fixed a bug to handle a situation where the remote host does not respond to a Client Hello
- Prepended all exceptions with the function name for easier troubleshooting
- Upgraded cryptography to 3.4.7 to support the latest versions of OpenSSL

# v1.8.2
- Pinned all direct and transitive dependencies to a specific version in requirements.txt
- add pylintrc file and pylint fixes
- run black against code base
- move CI from Azure DevOps to Github Actions
- fixed a logic bug when not supplying a port
- increased test coverage

# v1.9.0
- bump all dependencies
- remove requests library and use built-in urllib module

# v1.9.9
- created docker development environment in VS Code to work around Apple M1 compatibility issues with NaSSL
- removed a test that will never be able to run in the context of a docker container
- Improved errors returned to the user for various OpenSSL errors
- switch from get_received_chain to the get_verified_chain method in NaSSL to ensure the certificate is validated before we try any operations

# v1.9.11
- bump all dependencies
- moved to pyproject.toml for project definition
- added tests for python 3.10 and 3.11
- added coverage across macOS, Linux, and Windows
- fixed two broken tests and commented one out for now

# v1.9.12
- removed validators
- bump all dependencies
- added dev-requirements.txt for CI
- removed tox

# v1.9.13
- allow usage of http proxy to request both host certificate and perform the ocsp request
- allow configuration of request timeouts as function argument
- add extra info in unknown exceptions

# v1.9.14
- allow custom path to ca-certs via @vLabayen
- update devcontainer
- fix flaky tests
- update CI
- remove support for Python 3.7

# v2.0.0
- Relocate repository under gattjoe
- Removed support for Python 3.8 and added support for Python 3.13
- Update dependencies and rely soley on pyproject.toml
- Add CODEOWNERS

# v2.0.1
- Refactored some tests with mock
- Added OCSPResponseError class and refactored error handling

# v2.0.2
