import argparse


__version__ = '0.1.0'

def main():
    parser = argparse.ArgumentParser(
        description='Tool for testing IPv4 and IPv6 DHCP services'
    )
    parser.add_argument(
        '-V', '--version', action='version', version='%(prog)s {}'.format(__version__)
    )
    args = parser.parse_args()
    


if __name__ == "__main__":
    main()
