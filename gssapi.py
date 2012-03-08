#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# gssapi.py
#
# Copyright 2011 Legrandin <gooksankoo@hoiptorrow.mailexpire.com>
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

# ASN.1 DER OID assigned to NTLM
#   1.3.6.1.4.1.311.2.2.10
ntlm_oid = '\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'

def maketlv( dertype, payload):
    """Construct a DER encoding of an ASN.1 entity of given type and payload"""
    if len(payload)<128:
        return dertype + chr(len(payload)) + payload
    if len(payload)<256:
        return dertype + '\x81' + chr(len(payload)) + payload
    return dertype + '\x82' + pack('>H',len(payload)) + payload

def makeseq( payload):
    """Construct a DER encoding of an ASN.1 SEQUENCE of given payload"""
    return maketlv('\x30', payload)

def makeoctstr( payload):
    """Construct a DER encoding of an ASN.1 OCTET STRING of given payload"""
    return maketlv('\x04', payload)

def makegenstr( payload):
    """Construct a DER encoding of an ASN.1 GeneralString of given payload"""
    return maketlv('\x1b', payload)

def parsetlv( dertype, derobj, partial=False):
    """Parse a DER encoded object.
    
    @dertype    The expected type field (class, P/C, tag).
    @derobj     The DER encoded object to parse.
    @partial    Flag indicating whether all bytes should be consumed by the parser.

    An exception is raised if parsing fails, if the type is not matched, or if 'partial'
    is not honoured.

    @return     The object payload if partial is False
                A list (object payload, remaining data) if partial is True
    """
    if derobj[0]!=dertype:
        raise SMB_Parse_Exception('DER element %s does not start with type %s.' % (hexlify(derobj), hex(ord(tag))))
    
    # Decode DER length
    length = ord(derobj[1])
    if length<128:
        pstart = 2
    else:
        nlength = length & 0x1F
        if nlength==1:
            length = ord(derobj[2])
        elif nlength==2:
            length = unpack('>H', derobj[2:4])[0]
        pstart = 2 + nlength
    if partial:
        if len(derobj)<length+pstart:
            raise SMB_Parse_Exception('DER payload %s is shorter than expected (%d bytes, type %X).' % (hexlify(derobj), length, ord(derobj[0])))
        return derobj[pstart:pstart+length], derobj[pstart+length:]
    if len(derobj)!=length+pstart:
        raise SMB_Parse_Exception('DER payload %s is not %d bytes long (type %X).' % (hexlify(derobj), length, ord(derobj[0])))
    return derobj[pstart:]

def parseenum(payload, partial=False):
    """Parse a DER ENUMERATED
    
    @paylaod    The complete DER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @return     The ENUMERATED value if partial is False
                A list (ENUMERATED value, remaining data) if partial is True
    """
    res = parsetlv('\x0a', payload, partial)
    if partial:
        return (ord(res[0]), res[1])
    else:
        return ord(res[0])

def parseseq(payload, partial=False):
    """Parse a DER SEQUENCE
    
    @paylaod    The complete DER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @return     The SEQUENCE byte string if partial is False
                A list (SEQUENCE byte string, remaining data) if partial is True
    """
    return parsetlv('\x30', payload, partial)


def parseoctstr(payload, partial=False):
    """Parse a DER OCTET STRING
    
    @paylaod    The complete DER object
    @partial    Flag indicating whether all bytes should be consumed by the parser.
    @return     The OCTET STRING byte string if partial is False
                A list (OCTET STRING byte string, remaining data) if partial is True
    """
    return parsetlv('\x04', payload, partial)

### End ASN1. DER helpers

def make_token(ntlm_token, type1=True):
    '''Construct a GSSAPI/SPNEGO message, wrapping the given NTLM token.
    
    @ntlm_token     The NTLM token to embed into the message
    @type1          True if Type1, False if Type 3
    @return         The GSSAPI/SPNEGO message
    '''

    if not type1:
        mechToken = maketlv('\xa2', makeoctstr(ntlm_token))
        negTokenResp = maketlv('\xa1', makeseq(mechToken))
        return negTokenResp

    # NegTokenInit (rfc4178)
    mechlist = makeseq(ntlm_oid)
    mechTypes = maketlv('\xa0', mechlist)
    mechToken = maketlv('\xa2', makeoctstr(ntlm_token))

    # NegotiationToken (rfc4178)
    negTokenInit = makeseq(mechTypes + mechToken ) # + mechListMIC)
    innerContextToken = maketlv('\xa0', negTokenInit)

    # MechType + innerContextToken (rfc2743)
    thisMech = '\x06\x06\x2b\x06\x01\x05\x05\x02' # SPNEGO OID 1.3.6.1.5.5.2
    spnego = thisMech + innerContextToken

    # InitialContextToken (rfc2743)
    msg = maketlv('\x60', spnego)
    return msg

def extract_token(msg):
    '''Extract the NTLM token from a GSSAPI/SPNEGO message.
    
    @msg        The full GSSAPI/SPNEGO message
    @return     The NTLM message
    '''

    # Extract negTokenResp from NegotiationToken
    spnego = parseseq(parsetlv('\xa1', msg))

    # Extract negState
    negState, msg = parsetlv('\xa0', spnego, True)
    status = parseenum(negState)
    if status != 1:
        raise SMB_Parse_Exception("Unexpected SPNEGO negotiation status (%d)." % status)

    # Extract supportedMech
    supportedMech, msg = parsetlv('\xa1', msg, True)
    if supportedMech!=ntlm_oid:
        raise SMB_Parse_Exception("Unexpected SPNEGO mechanism in GSSAPI response.")

    # Extract Challenge, and forget about the rest
    token, msg = parsetlv('\xa2', msg, True)
    return parseoctstr(token)
 

