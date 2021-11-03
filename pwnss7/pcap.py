#!/usr/bin/env python2

import subprocess
from cStringIO import StringIO

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
