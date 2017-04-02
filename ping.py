import os
import select
import socket
import struct
import sys
from enum import Enum


def calculate_checksum(source_string):
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (hiByte * 256 + loByte)
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


class Ping:
    def __init__(self, host, timeout, data, ttl):
        self.host = host
        self.timeout = timeout
        self.data = data
        self.ttl = ttl
        self.own_id = os.getpid() & 0xFFFF
        self.seq_number = 0

    def send(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.getprotobyname('icmp'))
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        addr = (self.host, 1)
        icmp_packet = self.create_icmp_packet()
        sock.sendto(icmp_packet, addr)

        return self.receive(sock)

    def receive(self, sock):
        ready, *_ = select.select([sock], [], [], self.timeout)
        if not ready:
            return PingReply(PingStatus.Timeout, self.ttl)

        data, addr = sock.recvfrom(2048)
        return PingReply.from_icmp_packet(data, addr)


    def create_icmp_packet(self):
        header = self.create_header(0)
        data = self.data
        checksum = calculate_checksum(header + data)

        header = self.create_header(checksum)
        packet = header + data

        return packet

    def create_header(self, checksum: int):
        return struct.pack('!BBHHH', 8, 0, checksum,
                           self.own_id, self.seq_number)


class PingReply:
    def __init__(self, status, ttl, address=('', '')):
        self.status = status
        self.ttl = ttl
        self.address = address

    @staticmethod
    def from_icmp_packet(data, address):
        ip_data = data[0:20]
        icmp_data = data[20:28]
        type, code = struct.unpack('!2B', icmp_data[:2])
        ttl = struct.unpack('!B', ip_data[9:10])
        # print('ttl: %s' % ttl)
        # print('reply: %s %s' % (type, code))
        status = 0

        if type == 0 and code == 0:
            status = PingStatus.Ok

        if type == 11 and code == 0:
            status = PingStatus.TTlExpired

        if status == 0:
            print(status)
        return PingReply(status, ttl, address)


class PingStatus(Enum):
    Ok = 1
    TTlExpired = 2
    Timeout = 3
    Error = 4


ping = Ping('google.com', 2, b'adcdef', 1)
while True:
    reply = ping.send()
    print(ping.ttl, reply.address[0] or '*')
    if reply.status == PingStatus.Ok:
        break

    ping.ttl += 1

