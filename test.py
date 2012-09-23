#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# test.py
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

import random
import unittest
from struct import unpack, pack
from binascii import hexlify, unhexlify
import ntlm_proxy

class TestSMB_Context(unittest.TestCase):
    
    def setUp(self):
        self.smb = ntlm_proxy.SMB_Context()

        self.ntlm_msg1 = unhexlify('4e544c4d5353500001000000978208e2000000000000000000000000000000000501280a0000000f')
        self.ntlm_msg2 = unhexlify('4e544c4d53535000020000000e000e0038000000158289e29340b686de6042570000000000000000ca00ca00460000000502ce0e0000000f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self.ntlm_msg3 = unhexlify('4e544c4d5353500003000000010001005c000000000000005d000000000000004800000000000000480000001400140048000000100010005d000000158a88e20501280a0000000f4300480049005100550049005400490054004100007478efcdcb0cbf7b47d264d3e1775779')

    def testAsn1(self):
        smb = ntlm_proxy.SMB_Context()
        
        self.assertEqual( smb.maketlv('\x55',''), '\x55\x00' )
        self.assertEqual( smb.maketlv('\x55','x'), '\x55\x01x' )
        self.assertEqual( smb.maketlv('\x55','x'*128), '\x55\x81\x80' + 'x'*128)

        self.assertEqual( smb.makeseq('y'*16), '\x30\x10' + 'y'*16)
        self.assertEqual( smb.makeoctstr('y'*16), '\x04\x10' + 'y'*16)
        self.assertEqual( smb.makegenstr('y'*16), '\x1b\x10' + 'y'*16)

        self.assertEqual( smb.parsetlv('\x88','\x88\x02\x00\x00'), '\x00\x00')
        self.assertEqual( smb.parsetlv('\x88','\x88\x02\x00\x00', False), '\x00\x00')
        self.assertEqual( smb.parsetlv('\x88','\x88\x02\x00\x00\x00', True), ('\x00\x00', '\x00'))
        self.assertEqual( smb.parsetlv('\x88','\x88\x81\x01\x00'), '\x00')
        self.assertEqual( smb.parsetlv('\x88','\x88\x82\x00\x01\x00'), '\x00')

        self.assertEqual( smb.parseenum('\x0a\x01\x01'), 1 )
        self.assertEqual( smb.parseseq('\x30\x01\x01'), '\x01' )
        self.assertEqual( smb.parseoctstr('\x04\x01\x01'), '\x01' )

    def testTranport(self):
        smb = ntlm_proxy.SMB_Context()

        self.assertEqual( smb.addTransport('zzzz'), '\x00\x00\x00\x04zzzz')
        self.assertEqual( smb.getTransportLength('\x00\x00\x00\x04zzzz'), 4)
        self.assertEqual( smb.removeTransport('\x00\x00\x00\x04zzzz'), 'zzzz')

    def testGSSAPI(self):
        smb = ntlm_proxy.SMB_Context()
        
        # Test Type1 NTLM message
        gssapi1 = unhexlify('604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000501280a0000000f')
        self.assertEqual( smb.make_gssapi_token(self.ntlm_msg1), gssapi1)

        # Test Typer2 NTLM message
        gssapi2 = unhexlify('a182012f3082012ba0030a0101a10c060a2b06010401823702020aa2820114048201104e544c4d53535000020000000e000e0038000000158289e29340b686de6042570000000000000000ca00ca00460000000502ce0e0000000f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual( smb.extract_gssapi_token(gssapi2), self.ntlm_msg2)

        # Test Type3 NTLM message
        gssapi3 = unhexlify('a1733071a26f046d4e544c4d5353500003000000010001005c000000000000005d000000000000004800000000000000480000001400140048000000100010005d000000158a88e20501280a0000000f4300480049005100550049005400490054004100007478efcdcb0cbf7b47d264d3e1775779')
        self.assertEqual( smb.make_gssapi_token(self.ntlm_msg3, False), gssapi3)

    def testSMB(self):

        smb = ntlm_proxy.SMB_Context()
        self.assertEqual( smb.create_smb_header(0x72), unhexlify('ff534d4272000000000000c80000000000000000000000000000000000000000') )

        # First transaction to DC
        self.assertEqual( smb.make_negotiate_protocol_req(), unhexlify('0000002fff534d4272000000000000c80000000000000000000000000000000000000000000c00024e54204c4d20302e313200') )
        self.assertFalse( smb.parse_negotiate_protocol_resp(unhexlify('000000bfff534d4272000000009853c80000000000000000000000000000fffe000000001105000f32000100041100000000010000000000fdf30180a4aa80ebb0a7cc01c4ff007a00677f326ea873384584fd7607fb1cad72606806062b0601050502a05e305ca030302e06092a864882f71201020206092a864886f712010202060a2a864886f71201020203060a2b06010401823702020aa3283026a0241b22777777777777777777777777763933244057494e323030332e46414b452e53495445')))

        # Second transaction to DC
        self.assertEqual( smb.make_session_setup_req(self.ntlm_msg1), unhexlify('000000a2ff534d4273000000000000c800000000000000000000000000000000000000000cff000000000402000100000000004a0000000000540000806700604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000501280a0000000f0050007900740068006f006e00000050007900740068006f006e000000'))
        resp = unhexlify('000001eaff534d4273160000c09807c800004253525350594c2000000000fffe0218400004ff00ea0100003301bf01a182012f3082012ba0030a0101a10c060a2b06010401823702020aa2820114048201104e544c4d53535000020000000e000e0038000000158289e29340b686de6042570000000000000000ca00ca00460000000502ce0e0000000f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000570069006e0064006f0077007300200053006500720076006500720020003200300030003300200052003200200033003700390030002000530065007200760069006300650020005000610063006b00200032000000570069006e0064006f0077007300200053006500720076006500720020003200300030003300200052003200200035002e0032000000')
        resp2 = smb.parse_session_setup_resp(resp)
        self.assertTrue(resp2[0])
        self.assertEqual(resp2[1], self.ntlm_msg2)

        # Third transaction to DC
        resp = unhexlify('000000c0ff534d4273000000009807c800004253525350594c2000000000fffe0218800004ff00c000000009009500a1073005a0030a0100570069006e0064006f0077007300200053006500720076006500720020003200300030003300200052003200200033003700390030002000530065007200760069006300650020005000610063006b00200032000000570069006e0064006f0077007300200053006500720076006500720020003200300030003300200052003200200035002e0032000000')
        resp2 = smb.parse_session_setup_resp(resp)
        self.assertTrue(resp2[0])
        self.assertEqual(resp2[1],'')

class fakeSmb:
    Transport_Header_Length         = 4
    def __call__(self):
        return self
    def getTransportLength(self, msg):
        return unpack('>H', msg[2:4])[0]
    def removeTransport(self, msg):
        return msg[4:]
    def make_negotiate_protocol_req(self):
        return 'negotiatereq'
    def parse_negotiate_protocol_resp(self, response):
        pass
    def make_session_setup_req(self, ntlm_token, type1):
        return ntlm_token+'y'
    def parse_session_setup_resp(self, response):
        return (True,self.removeTransport(response))

class fakeSocket:
    def __init__(self, serverAddr, serverPort, listReplies, testObj):
        self.serverAddr = serverAddr
        self.serverPort = serverPort
        self.listReplies = listReplies
        self.testObj = testObj
        self.received = ''
    def socket(self, domain, protocol):
        import socket
        self.testObj.assertEqual(domain, socket.AF_INET)
        return self
    def settimeout(self, timeout):
        pass
    def connect(self, ipport):
        self.testObj.assertEqual(ipport[0], self.serverAddr)
        self.testObj.assertEqual(ipport[1], 445)
    def send(self, data):
        self.received += data
    def recv(self, bufferSize):
        reply, self.listReplies = self.listReplies[0], self.listReplies[1:]
        return reply
    def close(self):
        pass

class TestNTLM_Proxy(unittest.TestCase):

    def setUp(self):
        pass

    def testNegotiate(self):
        fsock = fakeSocket("127.0.0.1", 445, ('\x00\x00\x00\x01a','\x00\x00\x00\x01b', '\x00\x00\x00\x01c'), self)
        fsmb  = fakeSmb()

        proxy = ntlm_proxy.NTLM_Proxy("127.0.0.1", "MyDomain", fsock, fsmb)

        challenge = proxy.negotiate('x')
        self.assertEqual(challenge, 'b')
        self.assertEqual(fsock.received, 'negotiatereq' + 'xy')

        challenge = proxy.authenticate('w')
        self.assertEqual(fsock.received, 'negotiatereq' + 'xy' + 'wy')

if __name__ == "__main__":
    unittest.main()

