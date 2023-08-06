from buffer import Buffer
from packet import (
    DnsPacket,
    DnsHeader,
    DnsQuestion,
    DnsRecord,
    DnsRecordA,
    DnsRecordUnknown,
)
from packet import QueryType
import socket

QNAME = "google.com"
QTYPE = QueryType.A

import sys
if len(sys.argv) > 1:
    QNAME = sys.argv[1]


server = ("8.8.8.8", 53)
header = DnsHeader.default()
header.id = 1337 # Doesn't matter, random number
header.questions = 1
header.recursion_desired = True

packet = DnsPacket.default()
packet.header = header
packet.questions.append(
    DnsQuestion(name=QNAME, qtype=QTYPE)
)

pp = __import__("pprint").pprint

buf = Buffer()
packet.write(buf)


# create a udp socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# bind to random port
sock.bind(("", 0))

sock.connect(server)
sock.send(buf.buf)

response = sock.recv(512)
buffer = Buffer(response)
packet = DnsPacket.parse(buffer)

sock.send(buf.buf)
nbuf = Buffer(sock.recv(512))
npacket = DnsPacket.parse(nbuf)
pp(npacket)
pp(packet)