import argparse
import socket
import sys
from ipaddress import IPv4Address
from ping import Ping, PingStatus
from whois import get_whois_info


REQUESTED_FIELDS = ['netname', 'as', 'country']


def is_valid_ipv4_address(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

def is_local_address(addr):
    addr = IPv4Address(addr)
    return addr.is_private or addr.is_reserved


def is_valid_domain_name(host):
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False


def validate(addr):
    if is_valid_ipv4_address(addr):
        if not is_local_address(addr):
            return
    elif is_valid_domain_name(addr):
        return

    exit_with_error_message('enter valid non-local IPv4 address or DNS name')



def ensure_have_enough_rights():
    try:
        ping = Ping('localhost', 0, b'', 0)
        ping.send()
    except OSError:
        exit_with_error_message('you must have admin rights to use this util')


def exit_with_error_message(msg):
    print(msg)
    sys.exit(1)


def create_argparser():
    parser = argparse.ArgumentParser(description='traceroute util')
    parser.add_argument('target', help='target host')
    parser.add_argument('-n', metavar='TTL', dest='hopes',
                        type=int, default=30,
                        help='hopes number will be use to reach destination')
    parser.add_argument('-t', '--timeout', type=int, default=1,
                        help='timeout for each hope(in seconds)')

    return parser


def print_requested_fields(data):
    if data:
        p = [data[field] for field in REQUESTED_FIELDS if data[field]]
        print(', '.join(p))


def traceroute(args):
    ping = Ping(args.target, args.timeout, b'', 1)
    for i in range(args.hopes):
        reply = ping.send()

        if reply.status == PingStatus.Timeout or \
                        reply.status == PingStatus.UnexpectedError:
            print('%s.' % ping.ttl, '*', )
        else:
            print('%s.' % ping.ttl, reply.address)
            if IPv4Address(reply.address).is_private:
                print('local')
            else:
                data = get_whois_info(reply.address, REQUESTED_FIELDS)
                print_requested_fields(data)
        print(end='\r\n')

        if reply.status == PingStatus.Success:
            break

        ping.ttl += 1


if __name__ == '__main__':
    parser = create_argparser()
    args = parser.parse_args()
    validate(args.target)
    ensure_have_enough_rights()
    traceroute(args)
