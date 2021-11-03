#!/usr/bin/env python2

from cStringIO import StringIO
from struct import pack
from binascii import unhexlify

def encode_data(sccp, opc, dpc, sls):
  '''prepend M3UA DATA header to sccp bytes, with given opc, dpc and sls'''

  assert(type(opc) == int)
  assert(opc >= 0 and opc < 2**32)
  assert(type(dpc) == int)
  assert(dpc >= 0 and dpc < 2**32)
  assert(type(sls) == int)
  assert(sls >= 0 and sls < 256)

  f = StringIO()

  f.write(pack('!BBBBIHH',
    1, # version: release 1
    0, # reserved
    1, # message class: transfer messages
    1, # message type: payload DATA
    len(sccp)+16+8, # length
    0x210, # protocol data
    len(sccp)+16 # parameter length
  ))

  f.write(pack('!IIBBBB',
    opc, # originating point code
    dpc, # destination point code
    3, # SI: SCCP
    2, # National network
    0, # MP
    sls, # SLS
  ))
  f.write(sccp)

  if len(sccp) % 4 != 0:
    f.write('\x00' * (4-(len(sccp)%4)))

  return f.getvalue()
