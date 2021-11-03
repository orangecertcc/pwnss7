#!/usr/bin/env python2

from cStringIO import StringIO
from struct import pack
from binascii import unhexlify
from itertools import count, dropwhile

VERBOSE = True

class Asn1Obj:
  '''generic frame for ASN1 fields, supports nesting'''
  def __init__(self, klass, constructed, type, indefinite=False, value=None, children=[], absorbed=None):
    self.klass = klass
    self.constructed = constructed
    self.type = type
    self.indefinite = indefinite
    self.value = value
    self.children = children
    self.absorbed = absorbed

  def __repr__(self, indent=0):
    prefix = ' '*indent

    indefinite_tag = ''
    if self.indefinite:
      indefinite_tag = ', indefinite=True'

    if self.children:
      l = ''.join([c.__repr__(indent+2) + ',\n' for c in self.children])
      return '%sAsn1Obj(0x%x, %d, 0x%x%s, children=[\n%s%s])' % (prefix, self.klass, self.constructed, self.type, indefinite_tag, l, prefix)
    else:
      return '%sAsn1Obj(0x%x, %d, 0x%x%s, value=%r)' % (prefix, self.klass, self.constructed, self.type, indefinite_tag, self.value)

def push_u8(f, u):
  f.write(pack('!B', u))

class EndOfStream(Exception): pass

def pop_u8(f):
  data = f.read(1)
  if len(data) == 0: raise EndOfStream()
  return ord(data)

def split_to_bits(x, n):
  assert(x >= 0)
  m = (1<<n)-1

  nimbs = []
  while True:
    nimbs.append(x&m)
    x>>=n
    if x == 0:
      break

  return nimbs[::-1]

assert(split_to_bits(0, 8) == [0])
assert(split_to_bits(1, 8) == [1])
assert(split_to_bits(128, 8) == [0x80])
assert(split_to_bits(255, 8) == [0xff])
assert(split_to_bits(256, 8) == [1, 0])

def two_complement(x):
  assert(x < 0)

  x = -x
  for n in count(0, 8):
    if pow(2, n) > x:
      break

  return (-x) & (pow(2, n)-1)

def encode_integer(x):
  positive = (x >= 0)
  abs_x = x
  if not positive:
    abs_x = two_complement(x)

  elms = split_to_bits(abs_x, 8)
  if positive:
    if elms[0] & 0x80:
      elms = [0] + elms
  else:
    elms = [e for e in dropwhile(lambda x: x == 255, elms)]
    if not elms[0] & 0x80:
      elms = [0xff] + elms

  return ''.join(chr(c) for c in elms)

TESTS = (
  (0, '00'),
  (127, '7f'),
  (128, '0080'),
  (256, '0100'),
  (-128, '80'),
  (-129, 'ff7f'),
)

for (v, expected) in TESTS:
  assert(encode_integer(v) == unhexlify(expected))


def encode_ber(f, obj):
  '''encode ASN1Obj instance as Binary Encoded Representation'''
  # encode identifier octets
  if obj.type < 31:
    u = (obj.klass<<6) + (obj.constructed<<5) + obj.type
    push_u8(f, u)
  else:
    u = (obj.klass<<6) + (obj.constructed<<5) + 0x1f
    push_u8(f, u)

    type_nimbs = split_to_bits(obj.type, 7)
    for i in range(len(type_nimbs)):
      u = type_nimbs[i]
      if i < len(type_nimbs)-1:
        u |= 0x80
      push_u8(f, u)

  # if obj.constructed, then obj can be definite length, or not
  # if !obj.constructed, then obj must be definite length
  assert(obj.constructed or not obj.indefinite)

  # if obj is constructed, recursively build its value
  if obj.constructed:
    g = StringIO()
    for child in obj.children:
      encode_ber(g, child)
    obj.value = g.getvalue()

  # encode length octets
  if not obj.indefinite:
    length = len(obj.value)
    if length <= 127:
      push_u8(f, length)
    else:
      nimbs = split_to_bits(length, 8)
      push_u8(f, 0x80 + len(nimbs))
      for u in nimbs:
        push_u8(f, u)
  else:
    push_u8(f, 0x80)

  f.write(obj.value)

  if obj.indefinite:
    f.write('\x00\x00')


def decode_ber(f, level=0):
  '''decode Binary Encoded Representation bytes to ASN1Obj'''

  absorbed = ''

  u = 0
  try:
    u = pop_u8(f)
  except EndOfStream:
    return

  absorbed += chr(u)

  _klass = (u>>6) & 0x3
  _constructed = ((u>>5) & 0x1) == 1
  if u & 0x1f != 0x1f:
    _type = (u & 0x1f)
  else:
    _type = 0
    while True:
      u = pop_u8(f)
      absorbed += chr(u)

      _type <<= 7
      _type |= (u & 0x7f)
      if u & 0x80 == 0: break

  # at this point, _type, _klass and _constructed shall be defined

  _length = 0
  u = pop_u8(f)
  absorbed += chr(u)
  if u <= 127:
    _length = u
  else:
    nimbs = u & 0x7f
    for i in range(nimbs):
      u = pop_u8(f)
      absorbed += chr(u)
      _length <<= 8
      _length |= u

  _indefinite = (_constructed == 1 and _length == 0)

  # at this point, _length shall be defined
  assert((_indefinite and _length == 0) or (not _indefinite and _length >= 0))

  _children = []
  _value = None
  if not _indefinite:
    data = f.read(_length)
    absorbed += data
    assert(len(data) == _length)

    if _constructed:
      g = StringIO(data)
      while True:
        child = decode_ber(g, level+1)
        if not child:
          break
        _children.append(child)
    else:
      _value = data
  elif _klass != 0 or _type != 0:
    while True:
      o = decode_ber(f, level+1)
      _children.append(o)
      if o.klass == 0 and o.type == 0:
        break

  # at this point, _children xor _value shall be defined
  o = Asn1Obj(_klass, _constructed, _type, _indefinite, _value, _children, absorbed)

  return o



if __name__ == '__main__':
  import sys
  f = open(sys.argv[1], 'rb')
  o = decode_ber(f)
  print(o)
