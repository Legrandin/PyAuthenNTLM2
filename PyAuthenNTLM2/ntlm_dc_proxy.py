#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# ntlm_dc_proxy.py
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

import socket
from struct import pack, unpack
from binascii import hexlify, unhexlify

import gssapi
from ntlm_proxy import NTLM_Proxy

def tuc(s):
    return s.encode('utf-16-le')

class SMB_Parse_Exception(Exception):
    pass

class SMB_Context:
    """This is a class that creates and parses SMB messages belonging to the same context.
    """

    def addTransport(self, msg):
        '''Add Direct TCP transport to SMB message'''
        return '\x00\x00' + pack('>H', len(msg)) + msg

    def getTransportLength(self, msg):
        '''Return length of SMB message from Direct TCP tranport'''
        return unpack('>H', msg[2:4])[0]

    def removeTransport(self, msg):
        '''Remove Direct TCP transport to SMB message'''
        data = msg[4:]
        length = unpack('>H', msg[2:4])[0]
        if msg[0:2]!='\x00\x00' or length!=len(data):
            raise SMB_Parse_Exception('Error while parsing Direct TCP transport Direct (%d, expected %d).' % (length,len(data)))
        return data

    # See MS-CIFS and MS-SMB
    SMB_Header_Length               = 32
    SMB_COM_NEGOTIATE               = 0x72
    SMB_COM_SESSION_SETUP_ANDX      = 0x73

    SMB_FLAGS2_EXTENDED_SECURITY    = 0x0800
    SMB_FLAGS2_NT_STATUS            = 0x4000
    SMB_FLAGS2_UNICODE              = 0x8000

    CAP_UNICODE                     = 0x00000004
    CAP_NT_SMBS                     = 0x00000010
    CAP_STATUS32                    = 0x00000040
    CAP_EXTENDED_SECURITY           = 0x80000000

    def __init__(self):
        self.userId = 0
        self.sessionKey = '\x00'*4
        self.systemTime = 0
        
        # Direct TCP transport (see 2.1 in MS-SMB)
        self.minimumData = 4

    def create_smb_header(self, command):
        """Create an SMB header.

        @command        A 1-byte identifier (SMB_COM_*)
        @return         The 32-byte SMB header
        """

        # See 2.2.3.1 in [MS-CIFS]
        hdr =  '\xFFSMB'
        hdr += chr(command)
        hdr += pack('<I', 0)    # Status
        hdr += '\x00'           # Flags
        hdr += pack('<H',       # Flags2
            self.SMB_FLAGS2_EXTENDED_SECURITY   | 
            self.SMB_FLAGS2_NT_STATUS           |
            self.SMB_FLAGS2_UNICODE
            )
        # PID high, SecurityFeatures, Reserved, TID, PID low, UID, MUX ID
        hdr += pack('<H8sHHHHH', 0, '', 0, 0, 0, self.userId, 0)
        return hdr

    def make_negotiate_protocol_req(self):
        """Create an SMB_COM_NEGOTIATE request, that can be sent to the DC.

        The only dialect being negotiated is 'NT LM 0.12'.

        @returns the complete SMB packet, ready to be sent over TCP to the DC.
        """
        self.userId = 0
        hdr = self.create_smb_header(self.SMB_COM_NEGOTIATE)
        params = '\x00'         # Word count
        dialects = '\x02NT LM 0.12\x00'
        data = pack('<H', len(dialects)) + dialects
        return self.addTransport(hdr+params+data)

    def parse_negotiate_protocol_resp(self, response):
        """ Parse a SMB_COM_NEGOTIATE response from the server.

        This function validates the response of a NEGOTIATE request.

        @returns Nothing
        """
        smb_data = self.removeTransport(response)
        hdr = smb_data[:self.SMB_Header_Length]
        msg = smb_data[self.SMB_Header_Length:]
        # WordCount
        idx = 0
        if msg[idx]!='\x11':          # Only accept NT LM 0.12
            raise SMB_Parse_Exception('The server does not support NT LM 0.12')
        # SessionKey
        idx += 16
        self.sessionKey = msg[idx:idx+4]
        # Capabilities
        idx += 4
        capabilities = unpack('<I', msg[idx:idx+4])[0]
        if not(capabilities & self.CAP_EXTENDED_SECURITY):
            raise SMB_Parse_Exception("This server does not support extended security messages.")
        # SystemTime
        idx += 4
        self.systemTime = unpack('<Q', msg[idx:idx+8])[0]
        # ChallengeLength
        idx += 10
        if msg[idx]!='\x00':
            raise SMB_Parse_Exception('No challenge expected, but one found in extended security message.')

    def make_session_setup_req(self, ntlm_token, type1=True):
        """Create an SMB_COM_SESSION_SETUP_ANDX request that can be sent to the DC.

        @ntlm_token     The NTLM message
        @type1          True for Type 1, False for Type 3
        @return         The SMB request
        """
        hdr = self.create_smb_header(self.SMB_COM_SESSION_SETUP_ANDX)

        # Start building SMB_Data, excluding ByteCount
        data = gssapi.make_token(ntlm_token, type1)

        # See 2.2.4.53.1 in MS-CIFS and 2.2.4.6.1 in MS-SMB
        params = '\x0C\xFF\x00'             # WordCount, AndXCommand, AndXReserved
        # AndXOffset, MaxBufferSize, MaxMpxCount,VcNumber, SessionKey
        params += pack('<HHHH4s', 0, 1024, 2, 1, self.sessionKey)

        params += pack('<H', len(data))     # SecurityBlobLength
        params += pack('<I',0)              # Reserved
        params += pack('<I',                # Capabilities
              self.CAP_UNICODE  |
              self.CAP_NT_SMBS  |
              self.CAP_STATUS32 |
              self.CAP_EXTENDED_SECURITY)
        
        if (len(data)+len(params))%2==1: data += '\x00'
        data += 'Python\0'.encode('utf-16-le')  # NativeOS
        data += 'Python\0'.encode('utf-16-le')  # NativeLanMan
        return self.addTransport(hdr+params+pack('<H',len(data))+data)

    def parse_session_setup_resp(self, response):
        """Parse the SMB_COM_SESSION_SETUP_ANDX response, as received from the DC.
        
        @response       The SMB response received from the DC
        @return         A tuple where:
                          - the 1st item is a boolean. If False the user
                            is not authenticated
                          - the 2nd item is the NTLM Message2 (1st respone)
                            or is empty (2nd response)
        """

        smb_data = self.removeTransport(response)
        hdr = smb_data[:self.SMB_Header_Length]
        msg = smb_data[self.SMB_Header_Length:]

        status = unpack('<I', hdr[5:9])[0]
        if status==0:
            return (True,'')
        if status!=0xc0000016:
            return (False,'')

        # User ID
        self.userId = unpack('<H',hdr[28:30])[0]
        # WordCount
        idx = 0
        if msg[idx]!='\x04':
            raise SMB_Parse_Exception('Incorrect WordCount')
        # SecurityBlobLength
        idx += 7
        length = unpack('<H', msg[idx:idx+2])[0]
        # Security Blob
        idx += 4
        blob = msg[idx:idx+length]
        return (True, gssapi.extract_token(blob))

class NTLM_DC_Proxy(NTLM_Proxy):
    """This is a class that handles one single NTLM authentication request like it was
    a domain controller. However, it is just a proxy for the real, remote DC.
    """

    # Raw SMB over IP
    _portdc = 445

    def __init__(self, ipdc, domain, socketFactory=socket, smbFactory=None, verbose=False):
        NTLM_Proxy.__init__(self, ipdc, self._portdc, domain, lambda: SMB_Context(), socketFactory)
        self.debug = verbose
        #self.smbFactory =  smbFactory or (lambda: SMB_Context())

      
