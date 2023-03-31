#!/usr/bin/python3
import socket
import struct
from datetime import datetime, timedelta
import sys

HOST = '0.0.0.0'

"""
ICMP Packet Header Spec
0      8      16         31 ------------+
+------+------+----------+ -+           |
| type | code | checksum |  | 4 bytes   |
+------+------+----------+ -+           |
| identifier  | seq num  |  | 4 bytes   |
+-------------+----------+ -+           |
|        64 bits         |  | 8         +--> 512 bits (64 bytes)
|        timestamp       |  | bytes     |
+------------------------+ -+           |
|       384 bits         |  | 48        |
|         data           |  | bytes     |
+------------------------+ -+           |
                            ------------+
"""
def time(s):
    unix_time = datetime(year=1970, month=1, day=1, hour=0, minute=0, second=0)
    now = unix_time + timedelta(seconds=s)
    return now

def parse(packet, address):
    print(f'received: {packet} from: {address}')
    icmp = struct.unpack('<BBHHHI', packet)
    t = icmp[0] # type
    code = icmp[1]
    checksum = icmp[2]
    identifier = icmp[3]
    seq_num = icmp[4]
    timestamp = time(icmp[5])

    print(f'type: {t}\ncode: {code}\nchecksum: {checksum}\nidentifier: {identifier}\nsequence number: {seq_num}\ntimestamp: {timestamp}')


if __name__ == '__main__':
    # make listening socket (this only catches inbound traffic)
    server = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # our proxy
    server.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # client = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_ICMP) # where proxy forwards pings to
    server.bind((HOST, 0))

    # now we need to catch things being returned to us?

    # actually sniffing now lol
    try:
        while True:
            packet, address = server.recvfrom(65535)
            # first 20 bytes are IP
            parse(packet[20:32], address)
            data = packet[32:]
            print(f'data:\n{data}\n')
    except KeyboardInterrupt:
        sys.exit()
