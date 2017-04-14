from ipaddress import IPv4Address
from select import select
import socket
import re

DEFAULT_WHOIS_PORT = 43
SOCKET_CONNECT_TIMEOUT = 1
SOCKET_POLLING_PERIOD = 1.25

BUFFER_SIZE = 4 * 1024

IANA_WHOIS = 'whois.iana.org'
REGISTRARS = ['ripe', 'arin', 'apnic', 'lacnic', 'afrinic']
WHOIS_SERVERS = dict(
        [(registrar, 'whois.%s.net' % registrar)
         for registrar in REGISTRARS])

WHOIS_FIELDS_PATTERNS = {
    'netname': r'(?:netname|Name):\s*([\w-]+)',
    'as': r'(?:origin|aut-num|OriginAS):\s*(?:AS)*(\d+)',
    'country': r'[cC]ountry:\s*(\w+)',
    'refer': r'refer:\s*([\w\.]*)',
    'status': r'status:\s*(\w+)'
}

WHOIS_TRY_COUNT = 3


def get_socket_address(address_string):
    chunks = address_string.split(':')
    return chunks[0], int(chunks[1]) if len(chunks) > 1 else DEFAULT_WHOIS_PORT


def recv_all(sock):
    result = b''
    while select([sock], [], [], SOCKET_POLLING_PERIOD)[0]:
        data = sock.recv(BUFFER_SIZE)
        if len(data) == 0:
            break
        result += data
    return result


def receive_information(socket_address, target):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(SOCKET_CONNECT_TIMEOUT)
        sock.connect(socket_address)
        sock.setblocking(0)
        result = recv_all(sock).decode('utf-8')
        sock.sendall((target + "\r\n").encode('utf-8'))
        result += recv_all(sock).decode('utf-8')
    return result


def whois(source, target):
    for _ in range(WHOIS_TRY_COUNT):
        try:
            socket_address = get_socket_address(source)
            target = str(IPv4Address(target))
            info = receive_information(socket_address, target)
            return info
        except Exception:
            pass


def get_right_whois(ip):
    data = whois(IANA_WHOIS, ip)
    return get_match(WHOIS_FIELDS_PATTERNS['refer'], data)


def get_whois_info(ip, requested_fields):
    whois_server = get_right_whois(ip)
    if not whois_server:
        return

    # print(whois_server)
    response = whois(whois_server, ip)
    data = parse_response(response, requested_fields)
    # print(ip, data['netname'], data['as'], data['country'], sep=', ')
    return data


def parse_response(response, fields):
    data = {field: get_match(WHOIS_FIELDS_PATTERNS[field], response)
            for field in fields}

    return data


def get_match(pattern, data):
    mo = re.search(pattern, data)
    if not mo:
        return ''

    return mo.group(1)


if __name__ == '__main__':
    get_whois_info('127.123.123.1', ['netname', 'as', 'country'])
