#!/usr/bin/env python2


from itertools import islice
import string
import subprocess
from cStringIO import StringIO

# construct a De Bruijn sequence with non-repeating sequences of length n over an abstract alphabet of length k
def deBruijn(n, k):
  a = [0] * (n + 1)
  def gen(t, p):
    if t > n:
      for v in a[1:p + 1]:
        yield v
    else:
       a[t] = a[t-p]
       for v in gen(t+1, p):
         yield v
       for j in xrange(a[t-p]+1, k):
         a[t] = j
         for v in gen(t+1, t):
           yield v
  return gen(1, 1)

# nearly the equivalent of pwnlib cyclic
def cyclic(n, k=8, alphabet=string.ascii_letters):
  alphabet_size = len(alphabet)
  return ''.join(alphabet[x] for x in islice(deBruijn(k, alphabet_size), n))

# split a given string data in strings with length smaller than n
def split_by(data, n):
  for i in range(0, len(data), n):
    yield data[i:i+n]

def hexdump(pkts, f):
  '''hexdump packets in a format compatible with text2pcap'''
  for data in pkts:
    for i in range(0, len(data), 8):
      f.write('%04x  ' % i)
      for j in range(i, min([i+8, len(data)])):
        f.write('%02x ' % ord(data[j]))
      f.write('\n')

def convert2pcap(pkts, sctp=[1337,31337,3], v4=['127.0.0.1', '127.0.0.1'], eth=None):
  '''Wrap packets into a pcap, which raw content will returned'''

  args = ['text2pcap']

  if v4:
    args.extend(['-4', ','.join(v4)])
  if sctp:
    args.extend(['-S', ','.join(['%d' % x for x in sctp])])
  if eth:
    args.extend(['-e', '0x%x' % eth])
  args.extend(['-', '-'])

  cld = subprocess.Popen(args, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

  f = StringIO()
  hexdump(pkts, f)
  dumped_pkts = f.getvalue()

  (output, outerr) = cld.communicate(dumped_pkts)

  return output
