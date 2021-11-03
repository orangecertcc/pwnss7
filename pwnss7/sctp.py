#!/usr/bin/env python2

import socket
import struct
import sys

# Monkey patch for:
# - SOCK_SEQPACKET
# - IPPROTO_SCTP
# - bindx

if not hasattr(socket, 'SOCK_SEQPACKET'):
  socket.SOCK_SEQPACKET = 5

if not hasattr(socket, 'IPPROTO_SCTP'):
  socket.IPPROTO_SCTP = 132

SCTP_BINDX_ADD_ADDR = 1
SCTP_BINDX_REM_ADDR = 2

# Load libsctp shared library
# and resolve sctp_bindx

# under x64-64 Debian 9, it resolves to /usr/lib/x86_64-linux-gnu/libsctp.so.1

import ctypes

libsctp = None
if libsctp is None:
  try:
    libsctp = ctypes.CDLL('libsctp.so')
  except:
    pass

if libsctp is None:
  try:
    libsctp = ctypes.CDLL('libsctp.so.1')
  except:
    pass

if libsctp is None:
  print('could not load SCTP shared library. Will now exit')
  sys.exit(1)
assert(libsctp is not None)

real_bindx = libsctp.sctp_bindx
assert(real_bindx)

real_connectx = libsctp.sctp_connectx
assert(real_connectx)

real_getsockopt = libsctp.getsockopt
assert(real_getsockopt)

real_setsockopt = libsctp.setsockopt
assert(real_setsockopt)

SCTP_ASSOCINFO = 0x1

class sctp_assocparams(ctypes.Structure):
  _fields_ = [
    ("sasoc_assoc_id", ctypes.c_int32),
    ("sasoc_asocmaxrxt", ctypes.c_uint16),
    ("sasoc_number_peer_destinations", ctypes.c_uint16),
    ("sasoc_peer_rwnd", ctypes.c_uint32),
    ("sasoc_local_rwnd", ctypes.c_uint32),
    ("sasoc_cookie_like", ctypes.c_uint32),
  ]

def getassocid(f):
  params = sctp_assocparams()
  paramlen = ctypes.c_int(ctypes.sizeof(params))
  ret = real_getsockopt(f.fileno(), socket.IPPROTO_SCTP, SCTP_ASSOCINFO, ctypes.byref(params), ctypes.byref(paramlen))
  assert(ret == 0)
  return params.sasoc_assoc_id


SCTP_DEFAULT_SEND_PARAM = 0xa

class sctp_sndrcvinfo(ctypes.Structure):
  _fields_ = [
    ("sinfo_stream", ctypes.c_uint16),
    ("sinfo_ssn", ctypes.c_uint16),
    ("sinfo_flags", ctypes.c_uint16),
    ("sinfo_ppid", ctypes.c_uint32),
    ("sinfo_context", ctypes.c_uint32),
    ("sinfo_timetolive", ctypes.c_uint32),
    ("sinfo_tsn", ctypes.c_uint32),
    ("sinfo_cumtsn", ctypes.c_uint32),
    ("sinfo_assoc_id", ctypes.c_int32),
  ]

def setdefaultsndrcvinfo(f, sndrcvinfo):
  ret = real_setsockopt(f.fileno(), socket.IPPROTO_SCTP, SCTP_DEFAULT_SEND_PARAM, ctypes.byref(sndrcvinfo), ctypes.sizeof(sndrcvinfo))
  assert(ret == 0)


# sockaddr_in structure
class SOCKADDR_IN(ctypes.Structure):
  _fields_ = [
    ("sin_family", ctypes.c_uint16),
    ("sin_port", ctypes.c_uint16),
    ("sin_addr", ctypes.c_uint32),
    ("sin_zero", ctypes.c_byte*8),
  ]

def bindx(f, addrs):
  ADDRS_IN = SOCKADDR_IN * len(addrs)
  addrs_in = ADDRS_IN()

  for i in range(len(addrs)):
    (addr, port) = addrs[i]
    addrs_in[i].sin_family = socket.AF_INET
    addrs_in[i].sin_port = socket.htons(port)
    addrs_in[i].sin_addr = struct.unpack('<I', socket.inet_aton(addr))[0]

  return real_bindx(f.fileno(), addrs_in, len(addrs_in), SCTP_BINDX_ADD_ADDR)

def connectx(f, addrs):
  ADDRS_IN = SOCKADDR_IN * len(addrs)
  addrs_in = ADDRS_IN()

  for i in range(len(addrs)):
    (addr, port) = addrs[i]
    addrs_in[i].sin_family = socket.AF_INET
    addrs_in[i].sin_port = socket.htons(port)
    addrs_in[i].sin_addr = struct.unpack('<I', socket.inet_aton(addr))[0]

  assoc = ctypes.c_int(0)
  ret = real_connectx(f.fileno(), addrs_in, len(addrs_in), ctypes.byref(assoc))
  return ret
