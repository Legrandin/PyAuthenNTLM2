#!/usr/bin/env python
#
# PyAuthenNTLM2: A mod-python module for Apache that carries out NTLM authentication
#
# ntlm_ad_proxy.py
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

import socket
from ntlm_proxy import NTLM_Proxy

class LDAP_Context:
    pass

class NTLM_AD_Proxy(NTLM_Proxy):
    """This is a class that handles one single NTLM authentication request like it was
    a domain controller. However, it is just a proxy for the real, remote DC.
    """
    _portad = 339

    def __init__(self, ipdc, domain, socketFactory=socket, ldapFactory=None):
        NTLM_Proxy.__init__(self, ipdc, self._portad, domain, lambda: LDAP_Context(), socketFactory)
        #self.smbFactory =  smbFactory or (lambda: SMB_Context())
