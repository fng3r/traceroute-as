import argparse
import socket
import sys
from ipaddress import IPv4Address
from ping import Ping, PingStatus
from whois import get_whois_info


def is_valid_ipv4_address(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False


def validate(addr):
    if not is_valid_ipv4_address(target):
        print('enter valid IPv4 address or DNS name')
        sys.exit(1)


def create_argparser():
    parser = argparse.ArgumentParser(description='traceroute util')
    parser.add_argument('target', help='target host')
    return parser


if __name__ == '__main__':
    parser = create_argparser()
    args = parser.parse_args()
    target = args.target
    validate(target)
    ping = Ping(args.target, 1, b'', 1)
    while True:
        try:
            reply = ping.send()
        except OSError:
            print('you must have admin rights to use this util')
            sys.exit(1)

        if reply.status == PingStatus.Timeout or \
           reply.status == PingStatus.UnexpectedError:
            print('%s.' % ping.ttl, '*',)
        else:
            print('%s.' % ping.ttl, reply.address)
            data = get_whois_info(reply.address, ['netname', 'as', 'country'])
            if not data:
                print('local')
            else:
                data = filter(lambda item: item, data.values())
                print(*data, sep=', ')
        print(end='\r\n')

        if reply.status == PingStatus.Success:
            break

        ping.ttl += 1

