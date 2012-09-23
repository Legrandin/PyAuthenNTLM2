#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# asn1.py
#
# Copyright 2011 Legrandin <helderijs@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from struct import pack, unpack
from binascii import hexlify, unhexlify

class ASN1_Parse_Exception(Exception):
    pass

def maketlv(dertype, payload):
    """Construct a DER encoding of an ASN.1 entity of given type and payload"""
    if len(payload)<128:
        return dertype + chr(len(payload)) + payload
    if len(payload)<256:
        return dertype + '\x81' + chr(len(payload)) + payload
    return dertype + '\x82' + pack('>H',len(payload)) + payload

def makeint(number, tag='\x02'):
    """Construct a DER encoding of an ASN.1 INTEGER for a given number"""
    assert number>=0
    if number==0:
        payload = '\x00'
    payload = ''
    while number>0:
        payload = chr(number&255) + payload
        number /= 256
    if not payload:
        payload = '\x00'
    return maketlv(tag, payload)

def makeenum(number):
    """Construct a DER encoding of an ASN.1 ENUMERATION for a given tag"""
    return makeint(number, '\x0A')

def makeseq(payload):
    """Construct a DER encoding of an ASN.1 SEQUENCE of given payload"""
    return maketlv('\x30', payload)

def makeoctstr(payload):
    """Construct a DER encoding of an ASN.1 OCTET STRING of given payload"""
    return maketlv('\x04', payload)

def makegenstr(payload):
    """Construct a DER encoding of an ASN.1 GeneralString of given payload"""
    return maketlv('\x1b', payload)

def makebool(payload):
    """Construct a DER encoding of an ASN.1 BOOLEAN of given payload"""
    if payload:
        return maketlv('\x01', '\x7F')
    else:
        return maketlv('\x01', '\x00')

def parselen(berobj):
    """ Decode length field of a BER object.

    @berobj     The BER encoded object to parse.
    @return     A tuple (payload length, index of the first payload byte)
    """

    length = ord(berobj[1])
    # Short
    if length<128:
        return (length, 2)
    # Long
    nlength = length & 0x7F
    length = 0
    for i in xrange(2, 2+nlength):
        length = length*256 + ord(berobj[i])
    return (length, 2 + nlength)

def parsetlv(dertype, derobj, partial=False):
    """Parse a BER encoded object.
    
    @dertype    The expected type field (class, P/C, tag).
    @derobj     The BER encoded object to parse.
    @partial    Flag indicating whether all bytes should be consumed by the parser.

    An exception is raised if parsing fails, if the type is not matched, or if 'partial'
    is not honoured.

    @return     The object payload if partial is False
                A list (object payload, remaining data) if partial is True
    """
    
    if derobj[0]!=dertype:
        raise ASN1_Parse_Exception('BER element %s does not start with type 0x%s.' % (hexlify(derobj), hexlify(dertype)))
    
    length, pstart = parselen(derobj)
    if partial:
        if len(derobj)<length+pstart:
            raise ASN1_Parse_Exception('BER payload %s is shorter than expected (%d bytes, type %X).' % (hexlify(derobj), length, ord(derobj[0])))
        return derobj[pstart:pstart+length], derobj[pstart+length:]
    if len(derobj)!=length+pstart:
        raise ASN1_Parse_Exception('BER payload %s is not %d bytes long (type %X).' % (hexlify(derobj), length, ord(derobj[0])))
    return derobj[pstart:]

def parseint(payload, partial=False, tag='\x02'):
    """Parse a BER INTEGER
    
    @payload    The complete BER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @tag        The BER tar we expect in the object
    @return     The INTEGER value if partial is False
                A list (INTEGER value, remaining data) if partial is True
    """
    res = parsetlv(tag, payload, partial)
    if partial:
        payload = res[0]
    else:
        payload = res
    value = 0
    assert (ord(payload[0]) & 0x80) == 0x00
    for i in xrange(0,len(payload)):
        value = value*256 + ord(payload[i])
    if partial:
        return (value, res[1])
    else:
        return value

def parseenum(payload, partial=False):
    """Parse a BER ENUMERATED
    
    @payload    The complete BER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @return     The ENUMERATED value if partial is False
                A list (ENUMERATED value, remaining data) if partial is True
    """
    return parseint(payload, partial, tag='\x0A')

def parseseq(payload, partial=False):
    """Parse a BER SEQUENCE
    
    @paylaod    The complete BER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @return     The SEQUENCE byte string if partial is False
                A list (SEQUENCE byte string, remaining data) if partial is True
    """
    return parsetlv('\x30', payload, partial)

def parseoctstr(payload, partial=False):
    """Parse a BER OCTET STRING
    
    @paylaod    The complete BER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @return     The OCTET STRING byte string if partial is False
                A list (OCTET STRING byte string, remaining data) if partial is True
    """
    return parsetlv('\x04', payload, partial)

def parseset(payload, partial=False):
    """Parse a BER SET (OF)
    
    @payload    The complete BER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @return     The SET (OF) byte string if partial is False
                A list (SET (OF) byte string, remaining data) if partial is True
    """
    return parsetlv('\x31', payload, partial)


