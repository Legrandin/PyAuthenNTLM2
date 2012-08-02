#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# gssapi.py
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

from asn1 import *
from struct import pack, unpack
from binascii import hexlify, unhexlify

class GSSAPI_Parse_Exception(Exception):
    pass

# ASN.1 DER OID assigned to NTLM
#   1.3.6.1.4.1.311.2.2.10
ntlm_oid = '\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'

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
        raise GSSAPI_Parse_Exception("Unexpected SPNEGO negotiation status (%d)." % status)

    # Extract supportedMech
    supportedMech, msg = parsetlv('\xa1', msg, True)
    if supportedMech!=ntlm_oid:
        raise GSSAPI_Parse_Exception("Unexpected SPNEGO mechanism in GSSAPI response.")

    # Extract Challenge, and forget about the rest
    token, msg = parsetlv('\xa2', msg, True)
    return parseoctstr(token)
 

