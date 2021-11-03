#!/usr/bin/env python2

from cStringIO import StringIO
from struct import pack
from binascii import unhexlify

from .util import split_by

def encode_udt(tcap, called_gt, calling_gt):
  '''prepend SCCP header to TCAP payload, as UDT'''
  f = StringIO()

  f.write(pack('!BBBBB',
    0x09, # UDT
    0x00, # handling / class
    3, # first mandatory variable parameter is always at 2
    3+len(called_gt), # second mandatory variable parameter
    3+len(called_gt)+len(calling_gt), # third mandatory variable parameter
  ))

  f.write(pack('!B', len(called_gt)) + called_gt)
  f.write(pack('!B', len(calling_gt)) + calling_gt)
  f.write(pack('!B', len(tcap)) + tcap)

  return f.getvalue()

def encode_xudt(chunk, first_segment, remaining, called_gt, calling_gt):
  '''prepend SCCP header to chunk, as XUDT'''
  assert(type(first_segment) == int)
  assert(first_segment in (0, 1))
  assert(type(remaining) == int)
  assert(remaining in xrange(0, 32))

  f = StringIO()

  f.write(pack('!BBBBBBB',
    0x11, # XUDT
    0x00, # handling / class
    0x0c, # hop counter
    4, # first mandatory variable parameter is always at 4
    4+len(called_gt), # second mandatory variable parameter
    4+len(called_gt)+len(calling_gt), # third mandatory variable parameter
    4+len(called_gt)+len(calling_gt)+len(chunk)
  ))

  segmentation = pack('!B', ((first_segment<<7) + (1<<6) + remaining)) + unhexlify('b1eed4')[::-1]

  f.write(pack('!B', len(called_gt)) + called_gt)
  f.write(pack('!B', len(calling_gt)) + calling_gt)
  f.write(pack('!B', len(chunk)) + chunk)
  f.write(pack('!BB', 0x10, len(segmentation)) + segmentation)
  f.write('\x00')

  return f.getvalue()

def fragment(tcap, called_gt, calling_gt, size=42):
  chunks = [c for c in split_by(tcap, size)]
  assert(len(chunks) < 16)

  for i in range(len(chunks)):
    first_segment = 0
    if i == 0:
      first_segment = 1

    remaining = len(chunks)-i-1

    yield encode_xudt(chunks[i], first_segment, remaining, called_gt, calling_gt)
