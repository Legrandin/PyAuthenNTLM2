#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# ntlm_proxy.py
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

class NTLM_Proxy_Exception(Exception):
    pass

class NTLM_Proxy:
    """This is a class that handles one single NTLM authentication request like it was
    a domain controller. However, it is just a proxy for the real, remote DC.
    """

    def __init__(self, ipaddress, port, domain, protoFactory, socketFactory):
        self.ipaddress = ipaddress
        self.port = port
        self.domain = domain
        self.socketFactory = socketFactory
        self.protoFactory =  protoFactory
        self.socket = False
        self.bufferin = ''

    def _openConnection(self):
        """Open a TCP connection to the server, and reset any existing one."""

        self.close()
        self.socket = self.socketFactory.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        self.socket.connect((self.ipaddress, self.port))

    def _readsocket(self, length):
        """Read exactly @length bytes from the socket"""
        if not self.socket:
            raise NTLM_Proxy_Exception("Read operation on closed socket.")
        data = self.bufferin
        while len(data)<length:
            data += self.socket.recv(1024)
        data, self.bufferin = data[:length], data[length:]
        return data

    def _transaction(self, msg):
        if not self.socket:
            raise NTLM_Proxy_Exception("Transaction on closed socket.")
        self.socket.send(msg)
        data = self._readsocket(self.proto.minimumData)
        data += self._readsocket(self.proto.getTransportLength(data))
        return data

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = False
        self.bufferin = ''

    def negotiate(self, ntlm_negotiate):
        """Accept a Negotiate NTLM message (Type 1), and return a Challenge message (Type 2)."""
       
        self._openConnection()
        self.proto = self.protoFactory()

        # First transaction: negotiation (optional)
        msg = self.proto.make_negotiate_protocol_req()
        if msg:
            msg = self._transaction(msg)
            self.proto.parse_negotiate_protocol_resp(msg)

        # Second transaction: get the challenge
        msg = self.proto.make_session_setup_req(ntlm_negotiate, True)
        msg = self._transaction(msg)
        result, challenge = self.proto.parse_session_setup_resp(msg)
        if not result:
            return False
        return challenge

    def authenticate(self, ntlm_authenticate):
        """Accept an Authenticate NTLM message (Type 3), and return True if the user and credentials are correct."""

        msg = self.proto.make_session_setup_req(ntlm_authenticate, False)
        msg = self._transaction(msg)
        return self.proto.parse_session_setup_resp(msg)[0]

