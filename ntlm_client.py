#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# ntlm_client.py
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

import os
import sys
import getopt
from struct import pack, unpack
from binascii import hexlify, unhexlify
from Crypto.Hash import MD4, HMAC
from ntlm_proxy import SMB_Context, NTLM_Proxy

def tuc(s):
    return s.encode('utf-16-le')

class NTLM_Parse_Exception(Exception):
    pass

class NTLM_Client:
    """This class implements an NTLMv2 client"""

    NTLMSSP_NEGOTIATE_UNICODE                   = 0x00000001
    NTLM_NEGOTIATE_OEM                          = 0x00000002
    NTLMSSP_REQUEST_TARGET                      = 0x00000004
    NTLMSSP_NEGOTIATE_LM_KEY                    = 0x00000080
    NTLMSSP_NEGOTIATE_NTLM                      = 0x00000200
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED       = 0x00001000
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED  = 0x00002000
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN               = 0x00008000
    NTLMSSP_TARGET_TYPE_DOMAIN                  = 0x00010000
    NTLMSSP_TARGET_TYPE_SERVER                  = 0x00020000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY  = 0x00080000
    NTLMSSP_NEGOTIATE_TARGET_INFO               = 0x00800000
    NTLMSSP_NEGOTIATE_VERSION                   = 0x02000000
    NTLMSSP_NEGOTIATE_128                       = 0x20000000
    NTLMSSP_NEGOTIATE_KEY_EXCH                  = 0x40000000
    NTLMSSP_NEGOTIATE_56                        = 0x80000000
    
    avids = {
            1 : ("Server's NETBIOS name",   True),
            2 : ("Server's NETBIOS domain", True),
            3 : ("Server's DNS name",       True),
            4 : ("FQDN of the domain",      True),
            5 : ("FQDN of the forest",      True),
            6 : ("Flag value",              False),
            7 : ("Timestamp",               False),
            8 : ("Restriction",             False),
            9 : ("SPN of the server",        True),
            10 : ("Channel bindings",       False),
        }
 
    def __init__(self, username, domain, password, workstation='python'):
        self.username = username
        self.domain = domain
        self.password = password
        self.workstation = workstation

    def printAVpairs(self, avs):
        print "AVS = ", hexlify(avs)
        while avs:
            avid, avlen = unpack('<HH', avs[0:4])
            avvalue = avs[4:4+avlen]
            if avid==0:
                assert avlen==0
            else:
                if avid in self.avids:
                    print self.avids[avid][0], "=",
                    if self.avids[avid][1]:
                        print avvalue
                    else:
                        print hexlify(avvalue)
                else:
                    print "Unknown AV 0x%X = %s" % (avid, hexlify(avvalue))
            avs = avs[4+avlen:]

    def createAVpairs(self, listAVs):
        avs = ''
        for av in listAVs:
            if self.avids[av[0]][1]:
                avvalue = av[1].encode('utf_16_le')
            else:
                avvalue = av[1]
            avs += pack('<HH', av[0], len(avvalue)) + avvalue
        avs += '\x00'*4
        return avs

    def getNTTimestamp(self):
        import time
        from math import floor
        return (floor(time.time())+11644473600)*10000000

    def ntowfv2(self):
        return HMAC.new(MD4.new(tuc(self.password)).digest(), tuc(self.username.upper() + self.domain)).digest()

    def lmowfv2(self):
        return self.ntowfv2()

    def lmntchallengeresponse(self):
        responseKeyNT = self.ntowfv2()
        responseKeyLM = self.lmowfv2()
        ## LMv2
        lmchallengeresp = HMAC.new(responseKeyLM, self.serverChallenge + self.clientChallenge).digest() + self.clientChallenge
        ## NTv2
        timestamp = self.getNTTimestamp()
        temp = '\x01\x01'+'\x00'*6+pack('<Q',timestamp)+self.clientChallenge+'\x00'*4+self.targetInfo+'\x00'*4
        ntproofstr = HMAC.new(responseKeyNT, self.serverChallenge + temp).digest()
        ntchallengeresp = ntproofstr + temp
        #sessionKey = HMAC.new(responseKeyNT, ntproofstr).digest()
        return (lmchallengeresp, ntchallengeresp)

    def make_ntlm_negotiate(self):
        msg =  'NTLMSSP\x00'    # Signature
        msg += pack('<I', 1)    # Message Type 1

        # Flags
        self.flags = (
            self.NTLMSSP_NEGOTIATE_UNICODE      |
            self.NTLM_NEGOTIATE_OEM             |
            self.NTLMSSP_REQUEST_TARGET         |
            self.NTLMSSP_NEGOTIATE_LM_KEY       |
            self.NTLMSSP_NEGOTIATE_NTLM         |
            self.NTLMSSP_NEGOTIATE_ALWAYS_SIGN  |
            #self.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
            self.NTLMSSP_NEGOTIATE_VERSION
            )
        msg += pack('<I', self.flags)
 
        # DomainNameFields
        msg += pack('<HHI', 0, 0, 0)
        # WorkstationNameFields
        msg += pack('<HHI', 0, 0, 0)
        # Version (to be removed)
        if self.flags & self.NTLMSSP_NEGOTIATE_VERSION:
            msg += '\x05'           # Product Major: Win XP SP2
            msg += '\x01'           # Product Minor: Win XP SP2
            msg += pack('<H', 2600) # ProductBuild
            msg += '\x00\x00\x00'   # Reserved
            msg += '\x0F'           # NTLMRevisionCurrent
        return msg

    def parse_ntlm_challenge(self, msg):
        # Signature
        idx=0
        if msg[idx:idx+8]!='NTLMSSP\x00':
            raise NTLM_Parse_Exception("NTLM SSP signature not found.")
        # Type
        idx += 8
        typex = unpack('<I',msg[idx:idx+4])[0]
        if typex!=2:
            raise NTLM_Parse_Exception("Not a Type 2 NTLM message (%d)." % typex)
        # TargetNameFields
        idx += 4
        targetNameLen = unpack('<H', msg[idx:idx+2])[0]
        targetNameOffset = unpack('<I', msg[idx+4:idx+8])[0]
        # Flags
        idx += 8
        self.flags = unpack('<I', msg[idx:idx+4])[0]
        # TargetNameFields (again)
        if self.flags and self.NTLMSSP_REQUEST_TARGET and targetNameLen>0:
            targetName = msg[targetNameOffset:targetNameOffset+targetNameLen]
        # TODO: verify Unicode, since this affects DomainName in Type3
        # Server challenge
        idx += 4
        self.serverChallenge = msg[idx:idx+8]
        # TargetInfoFields
        idx += 16
        self.targetInfo = ''
        targetInfoLen = unpack('<H', msg[idx:idx+2])[0]
        targetInfoOffset = unpack('<I', msg[idx+4:idx+8])[0]
        if self.flags and self.NTLMSSP_NEGOTIATE_TARGET_INFO and targetInfoLen>0:
            self.targetInfo = msg[targetInfoOffset:targetInfoOffset+targetInfoLen]
            #self.printAVpairs(self.targetInfo)
 
    def make_ntlm_authenticate(self):
        self.clientChallenge = os.urandom(8)
        #print "Selected client challenge is", hexlify(self.clientChallenge)

        # Pre-compute LmChallengeResponse and NtChallengeResponse
        # see 3.3.2 in MS-NLMP
        (lmchallengeresp, ntchallengeresp) = self.lmntchallengeresponse()

        msg =  'NTLMSSP\x00'    # Signature
        msg += pack('<I', 3)    # Message Type 3

        fixup = []
        for f in lmchallengeresp, ntchallengeresp, tuc(self.domain), tuc(self.username), tuc(self.workstation):
            msg += pack('<H', len(f))
            msg += pack('<H', len(f))
            fixup.append((len(msg), f))
            msg += ' '*4 # Fake offset

        # EncryptedRandomSessionKeyFields
        assert not (self.flags & self.NTLMSSP_NEGOTIATE_KEY_EXCH)
        msg += pack('<HHI', 0, 0, 0)

        # NegotiateFlags
        self.flags &= ~(
            self.NTLMSSP_TARGET_TYPE_SERVER     |
            self.NTLMSSP_TARGET_TYPE_DOMAIN     |
            self.NTLMSSP_NEGOTIATE_VERSION      |
            self.NTLM_NEGOTIATE_OEM
            )
        msg += pack('<I', self.flags)

        # Version
        if self.flags & self.NTLMSSP_NEGOTIATE_VERSION:
            msg += '\x05'           # Product Major: Win XP SP2
            msg += '\x01'           # Product Minor: Win XP SP2
            msg += pack('<H', 2600) # ProductBuild
            msg += '\x00\x00\x00'   # Reserved
            msg += '\x0F'           # NTLMRevisionCurrent

        # MIC
        msg += pack('<IIII', 0, 0, 0, 0)

        # Fix up offsets
        msg = list(msg)
        payload = ''
        for offset, entry in fixup:
            msg[offset:offset+4] = pack('<I', len(msg)+len(payload))
            payload += entry
        msg = ''.join(msg) + payload
        return msg

def print_help():
    print
    print "Performs an NTLM authentication for user\\DOMAIN against the Domain Controller at the given address:"
    print "ntlm_client {-u|--user} usr {-p|--password} pwd {-d|--domain} DOMAIN {-a|--address} address"
    sys.exit(-1)

if __name__ == '__main__':
    config = dict()

    if len(sys.argv)<2:
        print_help()

    try:
        options, remain = getopt.getopt(sys.argv[1:],'hu:p:d:a:',['help', 'user=', 'password=', 'domain=', 'address='])
    except getopt.GetoptError, err:
        print err.msg
        print_help()
    if remain:
        print "Unknown option", ''.join(remain)
        print_help()

    for o, v in options: 
        if o in ['-h', '--help']:
            print_help()
        elif o in ['-u', '--user']:
            config['user'] = v
        elif o in ['-p', '--password']:
            config['password'] = v
        elif o in ['-d', '--domain']:
            config['domain'] = v
        elif o in ['-a', '--address']:
            config['address'] = v

    if len(config)!=4:
        print "Too few options specified."
        print_help()

    proxy = NTLM_Proxy(config['address'], config['domain'])
    client = NTLM_Client(config['user'],config['domain'],config['password'])

    type1 = client.make_ntlm_negotiate()
    challenge = proxy.negotiate(type1)
    if not challenge:
        print "Did not get the challenge!"
        sys.exit(-2)

    client.parse_ntlm_challenge(challenge)
    authenticate = client.make_ntlm_authenticate()
    if proxy.authenticate(authenticate):
        print "User %s\\%s was authenticated." % (config['user'], config['domain'])
    else:
        print "User %s\\%s was NOT authenticated." % (config['user'], config['domain'])

