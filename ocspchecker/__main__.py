""" Command line module for ocspchecker """

import argparse

from ocspchecker import get_ocsp_status

# Create the parser
arg_parser = argparse.ArgumentParser(
    prog="ocspchecker",
    description="""Check the OCSP revocation\
                                     status for a x509 digital certificate.""",
)

# Add the arguments
arg_parser.add_argument(
    "--target",
    "-t",
    metavar="target",
    type=str,
    required=True,
    help="The target to test",
)

arg_parser.add_argument(
    "--port",
    "-p",
    metavar="port",
    type=int,
    required=False,
    default=443,
    help="The port to test (default is 443)",
)


def main() -> None:
    """Main function"""
    # Execute the parse_args() method
    args = arg_parser.parse_args()
    target = args.target
    arg_port = args.port

    ocsp_status = get_ocsp_status(target, arg_port)
    print(ocsp_status)


if __name__ == "__main__":
    main()
