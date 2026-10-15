"""Answers every DNS query with SERVFAIL, so the test can check the milter
reports temperror for a failed lookup instead of none."""
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 5353))
while True:
    query, peer = sock.recvfrom(512)
    if len(query) < 12:
        continue
    end = 12  # skip the question name, then its type and class
    while end < len(query) and query[end]:
        end += 1 + query[end]
    end += 5
    # Same id and question, QR and RA set, RD copied, RCODE 2, nothing else.
    reply = bytearray(query[:end])
    reply[2] = 0x80 | (query[2] & 0x01)
    reply[3] = 0x80 | 2
    reply[6:12] = bytes(6)
    sock.sendto(bytes(reply), peer)
