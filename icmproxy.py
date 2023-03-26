#!/usr/bin/python3
import socket
import struct

HOST = '192.168.1.10'

"""
ICMP Packet Header Spec
0      8      16         31
+------+------+----------+ -+
| type | code | checksum |  |
+------+------+----------+  |
| identifier  | seq num  |  |
+-------------+----------+  |
|        64 bits         |  +--> 512 bits (64 bytes)
|        timestamp       |  |
+------------------------+  |
|       384 bits         |  |
|         data           |  |
+------------------------+ -+
"""
def parse(packet, address):
    print(f'packet: {packet} from: {address}')
    icmp = struct.unpack('<BBHHHI', packet)
    t = icmp[0] # type
    code = icmp[1]
    checksum = icmp[2]
    identifier = icmp[3]
    seq_num = icmp[4]
    timestamp = icmp[5]
    print(f'type: {t}\ncode: {code}\nchecksum: {checksum}\nidentifier: {identifier}\nsequence number: {seq_num}\ntimestamp: {timestamp}\n')


# IPPROTO_ICMP = socket.getprotobyname('icmp')

if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # our proxy
    # client = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_ICMP) # where proxy forwards pings to

    server.bind((HOST, 0))
    server.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    packet, address = server.recvfrom(65535)

    parse(packet[20:32], address)
