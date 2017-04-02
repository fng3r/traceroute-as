import argparse
from ipaddress import IPv4Address
from select import select
import socket

DEFAULT_WHOIS_PORT = 43
DEFAULT_WHOIS_PROVIDER = "whois.ripe.net"
SOCKET_CONNECT_TIMEOUT = 1
SOCKET_POLLING_PERIOD = 1

BUFFER_SIZE = 4 * 1024


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


def get_local_machine_ip():
    return socket.gethostbyname(socket.gethostname())


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
    source = "whois.arin.net"
    target = "198.194.0.0"
    try:
        socket_address = get_socket_address(source)
        target = str(IPv4Address(target))
        print(receive_information(socket_address, target))
    except Exception:
        # print("Failed to request info about '%s' from '%s'" % (args.target, args.source))
        pass


whois('', '')