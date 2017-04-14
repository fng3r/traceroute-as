import os
import socket
import select
import struct
import sys
from enum import Enum

ECHO_REQUEST_TYPE = 8
ECHO_REQUEST_CODE = 0


def calculate_checksum(source_string):
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    while count < countTo:
        if (sys.byteorder == 'little'):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum += hiByte * 256 + loByte
        count += 2

    if countTo < len(source_string):
        loByte = source_string[len(source_string) - 1]
        sum += loByte

    sum &= 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = socket.htons(answer)

    return answer


def header_to_dict(fields, header_format, packed_data):
    unpacked_data = struct.unpack(header_format, packed_data)
    return dict(zip(fields, unpacked_data))


class Ping:
    def __init__(self, host, timeout, data, ttl):
        self.host = host
        self.timeout = timeout
        self.data = data
        self.ttl = ttl
        self.owner_id = os.getpid() & 0xFFFF
        self.seq_number = 0

    def send(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        addr = (self.host, 1)
        icmp_packet = self.create_icmp_packet()
        sock.sendto(icmp_packet, addr)

        return self.receive_reply(sock)

    def receive_reply(self, sock):
        ready, _, _ = select.select([sock], [], [], self.timeout)
        if not ready:
            return PingReply(PingStatus.Timeout, self.ttl)

        data, addr = sock.recvfrom(2048)
        return PingReply.from_icmp_packet(data, self.ttl, addr[0])

    def create_icmp_packet(self):
        header = self.create_header(0)
        data = self.data
        checksum = calculate_checksum(header + data)

        header = self.create_header(checksum)
        packet = header + data

        return packet

    def create_header(self, checksum):
        return struct.pack('!2B3H', ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE,
                           checksum, self.owner_id, self.seq_number)


class PingStatus(Enum):
    Success = 1
    TTlExpired = 2
    Timeout = 3
    UnexpectedError = 4


class PingReply:
    statuses = {
        (0, 0): PingStatus.Success,
        (11, 0): PingStatus.TTlExpired
    }

    def __init__(self, status, ttl, address=''):
        self.status = status
        self.ttl = ttl
        self.address = address

    @staticmethod
    def from_icmp_packet(data, ttl, address):
        ip_data = header_to_dict(
            ['version', 'type', 'length',
             'id', 'flags',
             'ttl', 'protocol','checksum',
             'src_ip', 'dest_ip'],
            '!BBHHHBBHII', data[:20])

        icmp_data = header_to_dict(
            ['type', 'code', 'checksum', 'owner_id', 'seq_number'],
            '!BBHHH', data[20:28])

        type, code = icmp_data['type'], icmp_data['code']
        status = PingReply.statuses.get((type, code), PingStatus.UnexpectedError)

        return PingReply(status, ttl, address)
